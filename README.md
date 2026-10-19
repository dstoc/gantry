# gantry

`gantry` is a policy-enforced command runner for constrained environments.

It exposes three HTTP endpoints on one server:

- `/mcp`: MCP Streamable HTTP endpoint with tool `run_command`
- `/raw`: NDJSON streaming endpoint for direct command execution
- `/check`: JSON policy-check endpoint that returns a decision object

Policy decisions are made by [Rego](https://www.openpolicyagent.org/docs/policy-reference) modules loaded from `GANTRY_POLICY_DIR`. Administrator-controlled filesystem profiles load from the sibling `filesystems/` directory.

## Security Model

- Commands are executed without shell wrappers (`tokio::process::Command`), so no shell interpolation is used.
- Policy is always checked before process spawn.
- Rego input includes:
  - `input.command`: executable token requested by client
  - `input.path`: resolved absolute executable path
  - `input.hash`: SHA-256 hash of the resolved executable file (lowercase hex)
  - `input.args`: argument list
  - `input.env`: forwarded environment map
  - `input.cwd`: trusted resolved cwd policy label, produced by `gantry` rather than copied from request input
- Runtime is fail-closed:
  - if policy load fails at startup, server still starts but denies all requests
  - if policy reload fails, engine switches to deny-all until a valid policy set is loaded
- CWD authorization uses the fd-resolved cwd label for Rego. Direct uses the opened directory for execution. Bubblewrap passes the authorized absolute path to the supervisor, which resolves it inside the sandbox and fails if it is unavailable. See [CWD Policy Guarantees](docs/cwd-policy-guarantees.md) for exact guarantees and limits.

Policy checks are advisory and point-in-time:

- `/check` and `check_command` evaluate the same pre-spawn authorization path as execution
- they return a decision object instead of starting a process
- a later execution can still differ if policy or the executable file changes after the check
- callers that need enforcement must still execute through `gantry`; `/check` is not a capability token

## Configuration

Server options and their environment variables:

- `--bind-addr HOST:PORT` or `GANTRY_BIND_ADDR`: TCP listener, default `127.0.0.1:8000`
- `--bind-uds ABSOLUTE_PATH` or `GANTRY_BIND_UDS`: Unix socket listener
- `--policy-dir PATH` or `GANTRY_POLICY_DIR`: directory containing `.rego` policy files
- `--backend bubblewrap|direct`: select the server's execution backend

Command-line values take precedence over environment values. A listener flag selects that listener and ignores both listener environment variables. Without a listener flag, set at most one listener environment variable. If neither is set, Gantry uses TCP on `127.0.0.1:8000`. `--bind-addr` and `--bind-uds` cannot both be supplied.

The old server variables `MCP_BIND_ADDR`, `MCP_BIND_UDS`, and `POLICY_DIR` are ignored. The `run-remote` client variables `RUN_REMOTE_SERVER` and `RUN_REMOTE_SOCKET` are unchanged.

Bubblewrap is the default backend. It requires Linux, Bubblewrap with descriptor-based bind support, and the `gantry-supervisor` binary installed beside `gantry`. Each command receives a separate user, mount, PID, and network namespace. A restricted runtime view exposes the authorized executable, its interpreter and shared libraries, private `/proc`, `/tmp`, and `/run`, and only the selected profile mounts. Bubblewrap setup errors fail closed. Use `--backend direct` to explicitly select unsandboxed execution; Direct policies must return `filesystem: null` and `baffle_session: null`.

For a Bubblewrap decision with a non-null `baffle_session`, Gantry calls Baffle's file-only `create_ephemeral_from_file` API and holds the lease until the supervisor and bridge stop. Baffle 2.0.0 or later is required. Configure the control socket with this trusted server environment variable when it differs from Baffle's platform default:

- `GANTRY_BAFFLE_CONTROL_SOCKET`: Baffle control socket; defaults to Baffle's platform path.

The control response supplies the absolute session socket path and public CA certificate. Gantry validates and pins that socket, rejects profiles that expose its containing directory or the control socket, and mounts only the assigned socket. It writes the returned certificate to private trust material for that execution and mounts it at `/run/gantry/baffle-ca.pem`. It removes caller-supplied proxy and CA override variables, then sets the local proxy and certificate paths. Gantry does not read Baffle credentials, session configuration contents, or CA files. Direct rejects Baffle selections and keeps its ambient network behavior.

When migrating from an earlier Gantry release, remove the manually configured Baffle CA path and session socket directory settings. Keep the control socket setting only when the daemon uses a non-default path.

Examples:

```bash
GANTRY_BIND_ADDR=0.0.0.0:3000 GANTRY_POLICY_DIR=/opt/config/policies gantry
gantry --bind-addr 127.0.0.1:8000 --policy-dir /opt/config/policies
gantry --bind-uds /run/gantry/gantry.sock --policy-dir /opt/config/policies
gantry --backend bubblewrap --policy-dir /opt/config/policies
gantry --backend direct --policy-dir /opt/config/direct-policies
```

When `GANTRY_POLICY_DIR=/etc/gantry/policies`, place filesystem profiles in `/etc/gantry/filesystems`:

```text
/etc/gantry/
  policies/
    main.rego
  filesystems/
    workspace-readonly.toml
```

## Build and Run

From this folder:

```bash
cargo build --bins
./target/debug/gantry
```

Or build binaries:

```bash
cargo build --release --bins
# server
./target/release/gantry
# execution supervisor, installed beside gantry
./target/release/gantry-supervisor
# helper client
./target/release/run-remote
```

## Policy Directory Layout

Minimal layout:

```text
nw_sandbox/
  main.rego
  curl.rego
```

Larger layout (examples below):

```text
nw_sandbox/
  main.rego
  curl.rego
  python.rego
  date.rego
  build.rego
  echo.rego
  toolx.rego
  toolx_flexible.rego
  toolx_segments.rego
```

## Structured Decision Contract

`gantry` evaluates `data.sandbox.main.decision`. Every allowed decision must set all three fields. Use explicit `null` values when the policy does not select a filesystem profile or Baffle session. Missing fields do not mean `null`.

The default Bubblewrap backend requires a named profile. For an explicitly selected Direct backend, both selection fields must be `null`.

```rego
package sandbox.main

default decision := {
    "allow": false,
    "filesystem": null,
    "baffle_session": null,
}

decision := {
    "allow": true,
    "filesystem": "workspace-readonly",
    "baffle_session": null,
} if {
    data.sandbox[input.command].allow
    count(object.keys(input.env)) == 0
}
```

For a Direct deployment, use the same structured contract with both policy selections set to `null`, then start the server with `--backend direct`:

```rego
decision := {
    "allow": true,
    "filesystem": null,
    "baffle_session": null,
} if {
    data.sandbox[input.command].allow
}
```

The same input and authorization path are used by `check_command`, `POST /check`, and `run-remote --check`.

The startup-selected backend is not a Rego field. Direct requires both selection fields to be `null`. Bubblewrap requires a configured filesystem profile and accepts either a `null` Baffle selection or a Baffle configuration filename. Undefined, conflicting, malformed, and backend-incompatible decisions deny execution.

Checks include the selected `filesystem`, `baffle_session`, and configured `backend`. A check validates policy and profile selection; it does not spawn a command, mount a filesystem, or create a Baffle session.

### Filesystem Profiles

Profiles are TOML files named `<profile>.toml` in the sibling `filesystems/` directory. A profile has `version = 1` and direct source and destination paths. Profile names use lowercase letters, digits, hyphens, and underscores. Bind sources must be absolute paths to regular files or directories. Destinations must be absolute and cannot contain traversal components, overlap another mount, or shadow protected system paths.

```toml
version = 1

[[mounts]]
source = "/srv/workspace"
target = "/workspace"
access = "read-only"

[[mounts]]
type = "tmpfs"
target = "/tmp"
size = "256MiB"
```

Bind access must be `read-only` or `read-write`. Tmpfs sizes must be positive and use `B`, `KiB`, `MiB`, or `GiB`. Profiles are administrator-controlled; Rego selects a profile name and cannot choose mount paths or access.

### Migrating from the Boolean Contract

Replace `data.sandbox.main.allow` with `data.sandbox.main.decision`. A Direct deployment returns explicit `filesystem: null` and `baffle_session: null` fields, and uses `--backend direct` when selecting the backend explicitly. Bubblewrap policies select a named profile from the administrator-managed `filesystems/` directory.

Command-specific `data.sandbox[...].allow` rules can remain as rules inside the router policy. The router must return the structured decision object above.

## Rego Examples

### `curl.rego`

```rego
package sandbox.curl

default allow = false
default allow_env = false

# Allow: curl -I https://example.com
allow if {
    input.args == ["-I", "https://example.com"]
    startswith(input.path, "/usr/bin/")
}

# This command intentionally allows no forwarded env vars.
```

### `curl_pinned.rego` (pin executable hash)

```rego
package sandbox.curl

default allow = false
default allow_env = false

# Allow only the expected curl binary and invocation.
allow if {
    input.args == ["-I", "https://example.com"]
    input.path == "/usr/bin/curl"
    input.hash == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

### `python.rego`

```rego
package sandbox.python

default allow = false
default allow_env = false

# Allow: python -m http.server
allow if {
    input.args == ["-m", "http.server"]
}

# Optional override example:
# allow_env if {
#     input.env.PYTHONUNBUFFERED == "1"
# }
```

### `date.rego` (no args)

```rego
package sandbox.date

default allow = false
default allow_env = false

allow if {
    count(input.args) == 0
}
```

### `build.rego` (must contain `--target x86`)

```rego
package sandbox.build

default allow = false
default allow_env = false

allow if {
    some i
    i + 1 < count(input.args)
    input.args[i] == "--target"
    input.args[i + 1] == "x86"
}
```

### `echo.rego` (ban a specific arg)

```rego
package sandbox.echo

default allow = false
default allow_env = false

allow if {
    not banned_arg_present
}

banned_arg_present if {
    some i
    input.args[i] == "--unsafe"
}
```

### `toolx.rego` (exactly 3 args from allowlist)

```rego
package sandbox.toolx

default allow = false
default allow_env = false

allowed_args := {"--fast", "--verbose", "--dry-run"}

allow if {
    count(input.args) == 3
    every a in input.args {
        allowed_args[a]
    }
}
```

### `toolx_flexible.rego` (up to 3 args from allowlist)

```rego
package sandbox.toolx_flexible

default allow = false
default allow_env = false

allowed_args := {"--fast", "--verbose", "--dry-run"}

allow if {
    count(input.args) <= 3
    every a in input.args {
        allowed_args[a]
    }
}
```

### `toolx_segments.rego` (mix singles and pair segments)

```rego
package sandbox.toolx_segments

default allow = false
default allow_env = false

single_args := {"--fast", "--verbose", "--dry-run"}

allow if {
    valid_from(0)
}

valid_from(i) if {
    i == count(input.args)
}

valid_from(i) if {
    i < count(input.args)
    single_args[input.args[i]]
    valid_from(i + 1)
}

valid_from(i) if {
    i + 1 < count(input.args)
    input.args[i] == "--target"
    input.args[i + 1] == "x86"
    valid_from(i + 2)
}
```

## Raw Endpoint (`/raw`) Usage

Request:

```bash
curl -sS -N -X POST http://127.0.0.1:8000/raw \
  -H 'content-type: application/json' \
  -d '{
    "executable": "curl",
    "args": ["-I", "https://example.com"],
    "cwd": "/tmp",
    "env": {}
  }'
```

Response is NDJSON events:

- `{ "event": "start" }`
- `{ "event": "stdout", "data_b64": "..." }`
- `{ "event": "stderr", "data_b64": "..." }`
- `{ "event": "exit", "exitCode": 0 }`
- or `{ "event": "error", "message": "..." }`

## MCP Tool Contract (`/mcp`)

Tool name: `run_command`

Input schema:

- `executable: string`
- `args: string[]` (optional)
- `cwd: string | null` (optional)
- `env: object<string,string> | null` (optional)

Output schema:

- `stdout: string`
- `stderr: string`
- `exitCode: number | null`

Output from MCP tool calls is capped at 1 MiB per stream; truncated output appends `...truncated...`.

## `run-remote` Client

`run-remote` is a low-level client for `/raw` that streams stdout/stderr locally. Cladding installs wrapper scripts such as `run-in-nw-sandbox` and `run-in-fs-sandbox` that set `RUN_REMOTE_SERVER` from the component-specific endpoint before calling `run-remote`.

- Requires `RUN_REMOTE_SERVER` (full URL, usually `http://127.0.0.1:8000/raw`)
- Or `RUN_REMOTE_SOCKET` (absolute Unix socket path); the client sends HTTP over that socket and targets `/raw` or `/check` as needed
- `RUN_REMOTE_SERVER` and `RUN_REMOTE_SOCKET` are mutually exclusive
- Requires `--` delimiter before executable
- Supports env forwarding with `--keep-env`
- `--check` switches from `/raw` streaming to `/check` JSON output
- default `run-remote -- ...` behavior remains unchanged

Examples:

```bash
export RUN_REMOTE_SERVER=http://127.0.0.1:8000/raw

# simplest
run-remote -- curl -I https://example.com

# forward selected env vars
run-remote --keep-env=API_TOKEN,CI -- curl -I https://example.com

# equivalent two-arg keep-env form
run-remote --keep-env API_TOKEN -- curl -I https://example.com

# policy-only preflight
run-remote --check -- curl -I https://example.com
```

Unix socket example:

```bash
export RUN_REMOTE_SOCKET=/tmp/gantry.sock

run-remote -- curl -I https://example.com

run-remote --check -- curl -I https://example.com
```

`run-remote --check` builds the same payload as execution, including `cwd` and forwarded env, but sends it to `/check` instead of `/raw`. If `RUN_REMOTE_SERVER` ends in `/raw`, the client derives the check endpoint by replacing the final path segment with `/check`.

Exit codes for `run-remote --check`:

- `0` when the check succeeds and `allowed` is `true`
- `1` when the check succeeds and `allowed` is `false`
- `125` for local/client/server failures such as parse errors, missing env, connection failures, malformed responses, or HTTP errors

The JSON decision object is written to stdout.

## Live Reload Behavior

When `GANTRY_POLICY_DIR` is set, `gantry` checks Rego files and the sibling `filesystems/*.toml` profiles for changes.

- valid policy/profile changes -> a new combined generation becomes active
- invalid policy or profile change -> deny-all becomes active
- subsequent valid changes -> service recovers automatically

Each authorized plan retains the generation used for its decision and profile selection.

## Troubleshooting

- `Command not allowed: <cmd>`
  - `data.sandbox.main.decision` returned `allow: false`
  - verify router and command package names match `input.command`
- `Policy deny-all is active: ...`
  - policy set failed to compile/load
  - fix Rego syntax or policy directory contents
- `Policy evaluation failed for '<cmd>': ...`
  - query returned an evaluation error
  - inspect rule logic and data shape assumptions
- `Failed to resolve executable path for '<cmd>': ...`
  - executable not found on `PATH` or not executable

## Test

From the repository root, run the build and test suite:

```bash
cargo build
cargo test
```

Entrypoints:

- server: `src/main.rs`
- MCP/HTTP wiring: `src/mcp.rs`
- raw endpoint: `src/raw.rs`
- policy engine: `src/policy.rs`
- helper client: `src/bin/run-remote.rs`, `src/remote.rs`
