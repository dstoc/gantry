# Gantry

Gantry is a policy-enforced command execution server. It lets clients run commands subject to [Rego](https://www.openpolicyagent.org/docs/policy-reference) rules, with Linux [Bubblewrap](https://github.com/containers/bubblewrap) isolation by default. Optional [Baffle](https://github.com/dstoc/baffle) integration provides tightly scoped outbound HTTP/HTTPS access through per-command proxy sessions.

Use Gantry when an agent or other client needs to execute selected commands without unrestricted access to the host filesystem or network.

## How it works

1. A client submits an executable, arguments, working directory, and optional environment values.
2. Gantry resolves the executable and working directory, then evaluates the configured Rego policy.
3. If allowed, Gantry runs the command inside a fresh Bubblewrap sandbox, applying the selected filesystem profile and optional Baffle network session.
4. Gantry returns the command's output and exit status. Denied commands never start.

Gantry offers three interfaces on the same server:

| Interface | Purpose |
| --- | --- |
| `/mcp` | Streamable HTTP MCP server exposing `run_command` |
| `/raw` | Streaming NDJSON execution API |
| `/check` | Preflight policy decision without execution |

`/check` is advisory: a subsequent run evaluates policy again.

## Requirements

- Linux with Bubblewrap supporting descriptor-based binds (default backend).
- The `gantry` and `gantry-supervisor` executables installed alongside each other.
- Rego policy files and, for Bubblewrap execution, an administrator-managed filesystem profile.
- Optional: Baffle 2.0.0 or later, already running, for policy-selected proxy sessions.

The `direct` backend is available for explicitly chosen, **unsandboxed** execution. It is not a fallback when Bubblewrap fails.

## Build

From the repository root:

```sh
cargo build --release --bins
```

The binaries are in `target/release/`:

- `gantry`: server
- `gantry-supervisor`: command supervisor used by Bubblewrap
- `run-remote`: command-line client

Install `gantry` and `gantry-supervisor` in the same directory.

## Downloaded releases

GitHub Releases provide archives for Linux x86_64, Linux aarch64, and Apple
Silicon macOS. Each archive contains `gantry`, `gantry-supervisor`,
`run-remote`, this README, the reference documentation, and the license. The
Linux archives use the GNU libc target and require glibc 2.35 or later. They
also require Bubblewrap with descriptor-based bind support and a host that
permits the namespaces Bubblewrap needs. Install `gantry-supervisor` beside
`gantry` for the Bubblewrap backend. Bubblewrap is Linux-only. Apple Silicon
macOS supports the explicitly selected Direct backend.

Archive names include the release version, operating system, and architecture.
`SHA256SUMS` covers all three archives. For example, download the Linux x86_64
archive and checksum file for the same release:

```sh
VERSION=0.4.8
ARCHIVE="gantry-${VERSION}-linux-x86_64-gnu.tar.gz"
RELEASE="https://github.com/dstoc/gantry/releases/download/v${VERSION}"
curl -fLO "${RELEASE}/${ARCHIVE}"
curl -fLO "${RELEASE}/SHA256SUMS"
grep "  ${ARCHIVE}$" SHA256SUMS | sha256sum --check --strict -
tar -xzf "$ARCHIVE"
sudo install -m 0755 "gantry-${VERSION}-linux-x86_64-gnu"/gantry \
  "gantry-${VERSION}-linux-x86_64-gnu"/gantry-supervisor \
  "gantry-${VERSION}-linux-x86_64-gnu"/run-remote /usr/local/bin/
```

On macOS, verify the selected archive with
`grep "  ${ARCHIVE}$" SHA256SUMS | shasum -a 256 -c -` instead of
`sha256sum --check --strict -`.

## Release operation

Release Please reads conventional commits on `main` and opens or updates a
version and changelog pull request. Merging that pull request creates the
version tag and a draft GitHub release. Release Please creates the tag at the
release commit even while the release is a draft.

The manifest starts at version `0.4.7`, which matches `Cargo.toml`. Its
bootstrap commit keeps older repository history out of the first generated
changelog. Release tags use the form `vX.Y.Z`.

To request a specific version when conventional commits do not select one, add
`Release-As: X.Y.Z` to the body of a commit on `main`. For a squash-merged pull
request, include this footer in the pull request body and preserve it in the
squash commit body. Release Please then opens a version and changelog pull
request for that version.

Release Please uses the workflow token, so its tag does not start a second
workflow run. The release workflow passes the tag and commit SHA to its build
and publish jobs in the same run. Its workflow token also does not start the
normal pull request checks, so it dispatches the existing CI workflow on the
release branch to produce the required `test` check.

The release workflow builds all three targets from that tag's commit. It checks
the target architecture, runs binary smoke checks, packages the binaries and
documentation, and creates `SHA256SUMS`. It uploads the three archives and
checksum file to the draft, downloads them again, and verifies the uploaded
bytes before publishing the release. A failed build, upload, or verification
leaves the release as a draft.

To recover a failed release, open the **Release** workflow in GitHub Actions,
select `main`, then run it with the exact draft tag, such as `v0.4.8`. The
workflow checks that the tag points to the same version and still has a draft
release. It rebuilds the archives, removes stale assets from that draft,
uploads the expected set, and repeats the checksum checks before publication.
It rejects tags whose release is already published.

## Quick start

Create a policy directory and an adjacent filesystem-profile directory:

```text
/etc/gantry/
  policies/
    main.rego
  filesystems/
    workspace-readonly.toml
```

For example, allow running `date` without arguments:

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
    input.command == "date"
    count(input.args) == 0
    count(object.keys(input.env)) == 0
}
```

Save as `/etc/gantry/policies/main.rego`. Create `/etc/gantry/filesystems/workspace-readonly.toml`:

```toml
version = 1
mounts = []
```

Start the server (using paths accessible to the server process):

```sh
gantry --policy-dir /etc/gantry/policies
```

In another terminal, run:

```sh
RUN_REMOTE_SERVER=http://127.0.0.1:8000/raw run-remote -- date
```

To inspect the authorization decision without running the command:

```sh
RUN_REMOTE_SERVER=http://127.0.0.1:8000/raw run-remote --check -- date
```

The command's working directory must also exist inside the selected sandbox. Use an explicitly authorized working directory and mount if your workflow needs one.

## Server configuration

```text
gantry [--bind-addr HOST:PORT | --bind-uds ABSOLUTE_PATH]
       [--policy-dir PATH] [--backend bubblewrap|direct]
```

| Option | Environment variable | Default |
| --- | --- | --- |
| `--bind-addr` | `GANTRY_BIND_ADDR` | `127.0.0.1:8000` |
| `--bind-uds` | `GANTRY_BIND_UDS` | Not set |
| `--policy-dir` | `GANTRY_POLICY_DIR` | See [reference](docs/reference.md) |
| `--backend` | — | `bubblewrap` |
| — | `GANTRY_BUBBLEWRAP_STARTUP_TIMEOUT_SECS` | `30` |

CLI listener flags take precedence over listener environment variables; without a listener flag, set at most one listener variable. `--bind-addr` and `--bind-uds` are mutually exclusive.

Examples:

```sh
gantry --bind-uds /run/gantry/gantry.sock --policy-dir /etc/gantry/policies
gantry --backend direct --policy-dir /etc/gantry/direct-policies
```

Only use `--backend direct` when host filesystem and network access are intended.

## Policies and filesystem access

Gantry evaluates `data.sandbox.main.decision`, whose result must contain all three fields:

```rego
{
    "allow": true,
    "filesystem": "workspace-readonly",
    "baffle_session": null,
}
```

- `allow`: whether execution is permitted.
- `filesystem`: name of a trusted TOML profile in the sibling `filesystems/` directory. Required for Bubblewrap; must be `null` for Direct.
- `baffle_session`: optional daemon-managed Baffle session configuration filename; `null` means no Baffle session. Must be `null` for Direct.

Policy input includes the requested command, resolved executable path and SHA-256 hash, arguments, forwarded environment and a trusted working-directory label. Profiles control available mounts; command callers cannot choose arbitrary host mount sources.

A profile can expose specific host paths:

```toml
version = 1

[[mounts]]
source = "/srv/workspace"
target = "/workspace"
access = "read-only"
```

Filesystem profiles can also define `tmpfs` mounts and `runtime_paths` for interpreters, helper executables, libraries, and toolchains not discovered automatically. See [full policy and runtime reference](docs/reference.md).

Policies and filesystem profiles reload automatically. Invalid configurations activate deny-all, not the previous permissive policy.

## Optional Baffle networking

By default a Bubblewrap command has an isolated network namespace. To grant controlled outbound HTTPS access, configure and run a separate [Baffle](https://github.com/dstoc/baffle) daemon (version 2.0.0+) in file-only mode, then have Rego select a Baffle session configuration:

```rego
"baffle_session": "github.toml"
```

For an authorized command, Gantry uses Baffle's control API to create an **ephemeral** session, exposes only that session's proxy socket inside the sandbox, and configures common proxy and CA trust environment variables. The lease is released when execution finishes.

Baffle supplies the session socket path and public CA certificate in its control response. Gantry does not start the Baffle daemon or read its credentials, configuration files, or CA files.

If Baffle's control socket is at a non-default location, set:

```sh
GANTRY_BAFFLE_CONTROL_SOCKET=/run/baffle/control.sock
```

TLS trust varies by application: programs using bundled certificate stores or certificate pinning may need additional configuration. See [reference](docs/reference.md) for details.

## Clients

### Command-line client

`run-remote` sends requests to `/raw`, streams output, and preserves command exit status:

```sh
export RUN_REMOTE_SERVER=http://127.0.0.1:8000/raw
run-remote -- date
run-remote --check -- date
run-remote --keep-env=CI -- date
```

For a Unix socket, use `RUN_REMOTE_SOCKET=/run/gantry/gantry.sock` instead of `RUN_REMOTE_SERVER`. These settings are mutually exclusive.

### HTTP API

The raw endpoint accepts JSON:

```sh
curl -sS -N http://127.0.0.1:8000/raw \
  -H 'content-type: application/json' \
  -d '{"executable":"date","args":[],"env":{}}'
```

Responses stream `start`, `stdout`, `stderr`, and `exit` events (or `error`). Output events encode bytes as base64.

The `/mcp` endpoint exposes an MCP `run_command` tool with `executable`, optional `args`, `cwd`, and `env`. See [API reference](docs/reference.md) for schemas and output limits.

## Security considerations

- Command execution is **not** wrapped in a shell; shell syntax is not interpreted automatically.
- Access is denied unless a valid policy explicitly allows it.
- Bubblewrap uses isolated user, mount, PID, and network namespaces. Configuration or startup failures never silently fall back to Direct.
- A filesystem profile and any additional runtime paths determine what a command can read or write. Review them as carefully as the Rego policy.
- The `/check` endpoint is not an authorization token; each execution is rechecked.
- Do not expose the server to untrusted clients without appropriate access controls at the deployment boundary.

## Further documentation

- [Detailed configuration, API, policy examples, and runtime reference](docs/reference.md)
- [CWD policy guarantees and limitations](docs/cwd-policy-guarantees.md)
- [Policy-driven sandbox implementation proposal](docs/proposals/policy-driven-sandboxed-execution.md)

## Development

```sh
cargo build --bins
cargo test
```
