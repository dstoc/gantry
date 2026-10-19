# Proposal: Policy-Driven Sandboxed Execution

**Project:** Gantry  
**Status:** Draft  
**Scope:** Gantry only  
**Prerequisite:** The `mcp-run` → `gantry` rename and repository extraction are complete and not part of this proposal.

## Summary

Evolve Gantry from a policy-enforced command runner into a **policy-driven execution system offering both sandboxed and direct command execution**. Rego authorizes the requested command and selects:

- A named **filesystem profile** containing administrator-defined mounts, or `null` to select Direct execution.
- An optional **Baffle session configuration filename**, which controls network access.

Gantry selects the execution backend from `filesystem`: **a named profile selects Bubblewrap (`bwrap`)** and **`null` selects Direct** (subject to a trusted configuration gate). Bubblewrap enforces per-command filesystem and network isolation, and optionally uses a fresh Baffle session through a Rust `gantry-supervisor` TCP-to-UDS bridge. Direct retains Gantry's current `tokio::process::Command` execution path, without Bubblewrap or the supervisor. Both run the authorized absolute executable path without another policy check.

Every Bubblewrap execution receives an isolated filesystem and network namespace. Direct deliberately retains Gantry's existing process/filesystem/network access; it must be explicitly enabled and is **never** an automatic fallback after Bubblewrap failure. Authorization remains mandatory for both backends. Existing MCP, raw streaming and check interfaces remain the entry points.

## Motivation and existing behaviour

Gantry currently evaluates a boolean Rego query, `data.sandbox.main.allow`, then executes the resolved command directly using `tokio::process::Command`. Rego can inspect the requested command, resolved path, executable SHA-256, arguments, forwarded environment, and a trusted working-directory label. The `POST /check` and MCP `check_command` paths share pre-spawn authorization with actual execution. The new design must preserve that logical authorization path while moving spawning into a supervisor.

A boolean approval alone cannot distinguish a command allowed to read a checkout, one allowed to change it, or one permitted to contact a narrowly specified API with injected credentials. Nor can a shared parent-container proxy provide independent network authority to two simultaneous commands when either can connect to the same socket or listener.

Sandboxed invocations receive their own filesystem view and network namespace, while Baffle retains responsibility for HTTPS policy, destination/path restrictions and credential injection. Direct invocations intentionally preserve Gantry's existing unsandboxed execution semantics.

## Goals

1. Extend Rego to return a single structured decision containing `allow`, `filesystem`, and `baffle_session`.
2. Select either a **named, administrator-controlled filesystem profile** or `null` for Direct; select an optional Baffle configuration filename only for Bubblewrap.
3. Implement **Bubblewrap and Direct** execution backends with a common execution lifecycle; Baffle is the only managed network integration.
4. Create an isolated filesystem, process environment and network namespace for every Bubblewrap command, while retaining the existing execution model for Direct.
5. Give each network-authorized command a unique ephemeral Baffle session and only that session's data socket.
6. Implement a local HTTP-proxy-compatible TCP-to-UDS bridge in Rust, without `socat` or another long-running external bridge service.
7. Preserve current no-shell command semantics, trusted CWD input to Rego, authorized command forwarding, streamed output, exit reporting, and cancellation.
8. Fail closed when authorization or selected-backend preparation fails, and never fall back from a failed Bubblewrap execution to Direct.
9. Keep future OCI/microVM backends possible without changing Rego policy names or semantics.

## Non-goals

- Changes to Cladding, its container topology, or its mount configuration.
- Changes to the Baffle daemon, v2 control protocol, or session policy syntax.
- Implementing other execution backends beyond Bubblewrap and Direct.
- Arbitrary mounts, backend selection, or Baffle session creation requested by an untrusted command caller.
- Network providers other than Baffle, general network-provider APIs, and separate network-profile mappings.
- Adding unrestricted direct network access to **Bubblewrap**, shell interpolation, or a generic network-forwarding service. Direct intentionally inherits the ambient networking of the Gantry process.
- A complete resource quota framework; memory, CPU, and PID limits can be designed separately.

## Proposed architecture

```text
MCP /raw /check request
         |
         v
Trusted resolution + Rego authorization
  -> { allow, filesystem, baffle_session }
         |
         v
Execution planner
  - Route based on filesystem decision
  - Validate backend compatibility
  - Carry forward authorized path, args, env and CWD
         |
         +-- filesystem: null ----------> Direct (if enabled)
         |                                - Existing Command::new(path)
         |                                - Gantry's ambient filesystem/network
         |                                - No bwrap, supervisor, or Baffle lease
         |
         +-- filesystem: "profile" -----> Bubblewrap
                                          - Apply selected profile mounts
                                          - Isolate PID/mount/network namespaces
                                          - Optional leased Baffle session
                                          - Supervisor and TCP-to-UDS bridge

Command exit -> output/status and backend-specific cleanup


```

**Boundary:** Rego explicitly selects `filesystem: null` for Direct or a named profile for Bubblewrap. Gantry validates the backend combination, including Baffle selection. Bubblewrap enforces the chosen filesystem/network isolation; Direct receives Gantry's existing ambient authority by design. The caller cannot choose or override a backend, and Bubblewrap failures must not downgrade to Direct.

## 1. Rego decision contract

### Single structured decision

Replace the boolean query with a single object evaluated from a consistent compiled policy snapshot. Initially preserve the existing `sandbox` package namespace, using:

`data.sandbox.main.decision`

Example:

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
    "baffle_session": "github-readonly.toml",
} if {
    input.command == "gh"
    count(input.args) >= 2
    input.args[0] == "pr"
    input.args[1] == "view"
    # Additional executable/hash/cwd/env constraints as needed.
}

decision := {
    "allow": true,
    "filesystem": "workspace-write",
    "baffle_session": null,
} if {
    input.command == "cargo"
    input.args == ["test"]
}

# Retain Gantry's existing direct execution for a specifically allowed command.
decision := {
    "allow": true,
    "filesystem": null,
    "baffle_session": null,
} if {
    input.command == "date"
    count(input.args) == 0
}
```

| Field | Type | Contract |
| --- | --- | --- |
| `allow` | boolean | Required; only `true` permits execution. |
| `filesystem` | string or null | Required; a named profile selects Bubblewrap, `null` selects Direct (only if explicitly enabled in trusted configuration). |
| `baffle_session` | string or null | Required; with Bubblewrap, `null` means no external network; a filename selects a Baffle session relative to `session_config_dir`. Direct requires `null`, but still inherits ambient network access. |

For a denied decision, only `allow: false` has effect. For an allowed decision, an invalid named filesystem profile, malformed Baffle filename, undefined result, malformed type or conflicting decisions must deny execution. **`filesystem: null` explicitly requests Direct, and requires both the trusted Direct-enable setting and `baffle_session: null`.** A named profile requests Bubblewrap; if Bubblewrap cannot enforce it, fail rather than execute directly. `baffle_session: null` provides network isolation **only with Bubblewrap**.

Evaluate authorization and profile selection together, not as unrelated queries against potentially different policy generations. Preserve command-specific `data.sandbox[...].allow` modules where useful by adapting the router policy. Retaining `sandbox` avoids coupling this change to an unrelated Rego package rename; changing the package name can be a separate migration.

Rego must not return raw filesystem paths, mount flags, Baffle credentials, or runtime-created session IDs. It selects only a trusted Baffle **configuration filename**. The caller's request shape stays unchanged.

### Checks

`POST /check`, MCP `check_command`, and `run-remote --check` report the selected names and the configured backend while retaining existing executable, hash, cwd, policy-mode and denial diagnostics:

```json
{
  "allowed": true,
  "reason": null,
  "filesystem": "workspace-readonly",
  "baffle_session": "github-readonly.toml",
  "backend": "bubblewrap"
}
```

A check validates the selected backend, including whether Direct is enabled and the `filesystem`/`baffle_session` combination is permitted. It may validate filesystem-profile existence/schema and Baffle filename syntax, but **must not** create a Baffle session, mount filesystems or spawn either backend. It remains advisory and point-in-time: the real execution reauthorizes and may fail during provisioning. Explicitly document migration from the current boolean `allow` contract. A compatibility mode, if offered, must not imply an unrestricted filesystem by default.

## 2. Filesystem policies with direct source paths

### Named declarative profiles

Rego selects a named filesystem profile. Each administrator-controlled profile specifies **source paths directly**; there is no additional named-resource registry or resource-to-path mapping.

Proposed layout:

```text
config/
  policies/
    main.rego
    gh.rego
    cargo.rego
  filesystems/
    workspace-readonly.toml
    workspace-write.toml
    minimal.toml
```

Example `filesystems/workspace-readonly.toml`:

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

A writable profile can specify `access = "read-write"`. Paths are absolute **within the trusted Gantry runtime**, not necessarily on the physical host. No untrusted caller or Rego expression may supply or override source paths, destinations, or access modes; Rego selects only the profile name.

### Path validation and mount safety

- Parse profiles only from administrator-controlled files.
- Resolve source paths in trusted code; reject traversal, symlink races, unsafe file types, conflicting targets and protected-target shadowing.
- Pin opened source objects before applying mounts, preferably with Bubblewrap's descriptor-based `--bind-fd`/`--ro-bind-fd` (where available) or another race-resistant equivalent. Validate backend version and required capabilities; fail closed if unavailable.
- Read-only mounts constrain writes *from the command* but do not freeze changes by other processes. Consider nested mounts and unintended writable submounts.
- Filesystem profiles are **allowlists**; they are not mounted on top of an inherited unrestricted root filesystem.

### Minimal trusted runtime root

The backend must construct a limited runtime view containing the authorized executable, required interpreter/libraries, essential system files, a suitable `/proc`, and private temporary state. This baseline is not the entire parent filesystem and must not expose credentials, control sockets, or unrelated application data.

A selected profile adds only its declared direct-path mounts to that baseline. If the authorized executable or cwd cannot be represented without expanding access, reject execution.

### Filesystem invariants

- Ensure authorized mount sources correspond to the objects actually mounted, avoiding re-resolution through mutable paths.
- Gantry retains trusted CWD resolution for the Rego input, then passes the authorized CWD path to the supervisor. The supervisor uses that path as its working directory inside the sandbox. If unavailable or inaccessible, command spawning fails. No descriptor handoff or directory identity verification is required.
- Preserve the executable path selected by authorization in the sandbox filesystem and pass it unchanged to the supervisor; the executable's contents need not be pinned against intervening writes (see §5).
- Scrub inherited file descriptors and environment variables.
- Writable mounts are genuinely writable and need not be disposable.

## 3. Direct Baffle session selection

### Rego selects a configuration filename

**Baffle is the only network integration in scope.** There is no general network-provider abstraction and no Gantry network-profile mapping layer.

The Rego decision's `baffle_session` is either `null` (no network) or a filename relative to Baffle's administrator-controlled `session_config_dir`:

```json
{
  "allow": true,
  "filesystem": "workspace-readonly",
  "baffle_session": "github-readonly.toml"
}
```

This is a Baffle **session configuration filename**, not the runtime-generated Baffle session ID or socket path. Gantry validates the name and Baffle performs its file-only ownership, symlink and contents checks when creating the session. The filename comes from Rego, never the untrusted command request.

Example Baffle configuration:

```toml
version = 2
persistent = false
unmatched = "deny"

[rules."api.github.com"]
paths = ["/repos/dstoc/**"]
```

Omit `socket_name` so concurrently provisioned sessions receive unique data socket paths. Require ephemeral sessions; failed provisioning prevents command startup.

### Trusted Baffle integration

Gantry uses Baffle's existing `baffle-client` and `create_from_file` operation directly. If deployment requires a privileged broker, it exposes a constrained create/lease interface but **does not** introduce another network provider or policy mapping.

Trusted Gantry execution state holds the ephemeral session lease for the complete command/process-tree lifetime, releasing it on success, cancellation, spawn failure and unexpected termination. Only the assigned Baffle **data** socket is exposed inside the sandbox; never the control socket or credentials.

### No Baffle session in Bubblewrap

With `filesystem` set to a named profile and `baffle_session: null`, the command runs in an isolated network namespace, without an external route, any Baffle socket, or injected proxy configuration. Private loopback may be used within the invocation. Caller-supplied proxy and bypass environment variables cannot override this restriction.

## 4. Pluggable execution backends

Introduce a backend-neutral validated plan, plus a lifecycle-bearing handle:

```rust
trait ExecutionBackend {
    async fn start(&self, plan: ExecutionPlan)
        -> Result<RunningExecution>;
}
```

`ExecutionPlan` contains the authorized absolute executable path (and the hash used in the policy decision for diagnostics), exact argument vector, authorized CWD path, sanitized environment, validated filesystem source descriptors and access modes, optional leased Baffle data endpoint, stdio configuration, and isolation/lifecycle constraints. The backend forwards the authorized invocation instead of re-resolving the requested command.

`RunningExecution` supports streamed output, exit status, cancellation and cleanup. Exact Rust type and ownership details are implementation decisions; the important property is **no orphaned process tree or leaked Baffle lease** when the caller disconnects or execution fails.

The filesystem decision selects the backend: a named filesystem profile selects Bubblewrap, while `filesystem: null` selects Direct when enabled by trusted Gantry configuration. Direct keeps the current `tokio::process::Command` behavior. Future backends may implement named profiles, but failed Bubblewrap execution never falls back to Direct.

### Backend selection matrix

| Filesystem decision | Baffle session | Backend | Result |
| --- | --- | --- | --- |
| Named profile | null | Bubblewrap | Isolated; no external network |
| Named profile | filename | Bubblewrap | Isolated; per-command Baffle proxy |
| null | null | Direct | Current Gantry command execution, if enabled |
| null | filename | Denied | Direct does not support per-command Baffle sessions |

Direct is a deliberate policy selection; no backend failure changes a named filesystem decision into Direct.

Use capability validation before provisioning. Concurrent runs must each retain their own immutable policy/profile snapshot and execution ownership.

### Direct backend

Direct preserves the current Gantry execution path: after authorization, spawn the resolved executable using `tokio::process::Command` with its authorized arguments, environment and CWD. Keep existing stdio, streaming, exit and cancellation behavior.

Direct does not use Bubblewrap, a per-command filesystem policy, a supervisor, a Baffle lease or a command-local bridge. It inherits Gantry's filesystem and network environment, including any existing proxy configuration. Only an explicit `filesystem: null`, `baffle_session: null` decision may select it, and only if Direct is enabled in trusted configuration.

A missing/invalid filesystem field must not select Direct. A failed Bubblewrap execution must not retry through Direct.

## 5. Bubblewrap backend

### Per-invocation isolation

Spawn a new Bubblewrap sandbox for **every** command with a named filesystem profile, including those without a Baffle session. Configure a private mount namespace, PID namespace, and network namespace (using `--unshare-net`) with appropriate user namespace, session, capability and inherited-descriptor restrictions. Do not rely on the parent container's default filesystem/proxy access as the child's security policy.

Construct the filesystem view explicitly from the trusted runtime baseline plus the selected profile's mounts. Create private `/proc` and temporary filesystem views appropriate to the PID and mount namespace. Use `--die-with-parent`, `--new-session`, and process-group/cgroup cleanup as applicable, but verify that descendant processes cannot outlive a completed or cancelled execution.

Nested user/network namespaces may be blocked by kernel settings, seccomp, or rootless container configuration. Detect unsupported environments clearly. **Never fall back to unsandboxed command execution.**

### Per-command localhost bridge

Inside the sandbox run a small Rust binary, **`gantry-supervisor`**, whose responsibilities are:

1. Receive the **authorized invocation** from trusted Gantry code: the resolved absolute executable path, exact argument vector, effective working directory and sanitized environment. Do not accept a separate, caller-supplied executable or resolve the original command name through `PATH`.
2. Receive the assigned Baffle data UDS path, if networking was authorized.
3. Verify the private loopback interface is available, then bind `127.0.0.1:3128`.
4. For each TCP client, connect to the assigned Unix socket and forward bytes bidirectionally with Tokio.
5. Confirm bridge readiness, then spawn the authorized absolute path directly with the same arguments, cwd and environment (subject only to Gantry's trusted sandbox/proxy environment setup).
6. Supervise the command process tree, relay stdout/stderr and exit status, and terminate listeners and descendants on completion/cancellation.

Each invocation has its own network namespace and can reuse the same port:

```text
Command A: 127.0.0.1:3128 -> Baffle session A UDS
Command B: 127.0.0.1:3128 -> Baffle session B UDS
```

Expose **only the assigned Baffle data UDS** in the sandbox, at a fixed location such as `/run/gantry/proxy.sock`. Never mount the parent Baffle session directory, provider control socket, or another command's socket. Validate live pathname UDS bind mounts across user/mount/network namespaces; fail closed if isolation is unavailable.

Set trusted `http_proxy`, `https_proxy`, `HTTP_PROXY` and `HTTPS_PROXY` to `http://127.0.0.1:3128` only when Baffle is authorized. Caller-provided `ALL_PROXY`, `NO_PROXY` and other proxy/bypass variables cannot redirect traffic. Provide only the public Baffle CA when needed; never its private key or credential files. Baffle retains HTTPS CONNECT, host/path, and credential-injection enforcement.

The supervisor is **inside** the isolation boundary and has no Baffle control authority.

### Authorized command handoff

Gantry currently resolves the executable path and hashes its contents before evaluating Rego, then passes that resolved path into `Command::new(resolved_executable)` when launching the command. Retain this model even though actual process creation moves to `gantry-supervisor`.

**Required sequence:**

1. Gantry resolves the requested executable to an **absolute path**, calculates its SHA-256 for the existing Rego check, and authorizes the command, arguments, environment and trusted cwd label.
2. Gantry builds a typed internal **`AuthorizedInvocation`** carrying the *same resolved executable path*, exact authorized arguments, effective environment and CWD path. These are trusted execution-plan values, not a second command request or an opportunity for untrusted policy/profile overrides.
3. The Bubblewrap backend makes that executable path available at the **same absolute location** inside the sandbox, using the trusted runtime baseline and/or authorized mounts. If that path cannot be executed within the filesystem policy, fail rather than running some alternative executable.
4. Gantry passes the authorized invocation to the supervisor through a trusted launch channel (for example, process arguments or a private pipe). The supervisor must not search `PATH`, re-resolve the original command token, or evaluate Rego again. It calls `Command::new(authorized_absolute_path)` directly, sets the supplied arguments, cwd and sanitized environment, and spawns the child without a shell.
5. The supervisor sets the authorized CWD path as the command's working directory inside the sandbox. A missing or inaccessible CWD causes a spawn error. No CWD descriptor handoff or identity verification is required.

**Explicit non-goal: executable TOCTOU protection.** The hash remains a point-in-time Rego input. Gantry does not need to preserve the executable inode or bytes against renames, replacements or in-place writes after authorization. Such changes are permitted by this design, as with Gantry's existing path-based spawn. No sealed snapshots, executable memfds, `execveat` handoffs, sealed manifests, or executable-byte equivalence tests are required.

The resolved path and sandbox filesystem mapping must remain consistent as an execution *interface*: passing `/usr/bin/gh` must not accidentally start an unrelated binary at that path because of a different mount layout selected by the backend. This is a configuration correctness requirement, not a promise to defeat concurrent executable modifications. Verify ordinary ELF and shebang execution work through the new supervisor path.

### Lifetime and cancellation

```text
Authorize request and resolve profiles
  -> Validate backend capabilities
  -> Provision Baffle lease if needed
  -> Prepare namespace and mount plan
  -> Start bwrap + supervisor
  -> Confirm bridge readiness
  -> Spawn and supervise authorized command
  -> Stream and report output/status
  -> Terminate descendants and supervisor
  -> Release network lease
```

Ensure cleanup on all intermediate errors (bad mounts, missing executable, bridge bind/connect failures, client disconnects, cancelled futures, server shutdown). Do not report a successful `start` event until the sandbox is ready and the authorized command has actually started. Explicitly separate sandbox setup errors from the command's nonzero exit status.

## 6. Public API and compatibility

Keep command request fields (`executable`, `args`, `cwd`, `env`) unchanged for MCP, `/raw`, and `/check` callers. Gantry selects profiles itself; a caller cannot override them.

- Extend check responses to include selected profile names and configured backend while retaining current fields and exit conventions.
- Preserve existing MCP command output and `/raw` stdout/stderr streaming, output limits, exit codes and disconnect semantics.
- Refactor synchronous `spawn_command_process` and the shared authorization path as needed because Baffle provisioning and backend startup are asynchronous. Keep authorization shared between all execution paths.
- Introduce structured decision migration documentation from `data.sandbox.main.allow`; explicit migration is preferable to retaining insecure default execution semantics.
- Retain deny-all behaviour on policy startup/reload errors. Load Rego and direct-path filesystem profiles into coherent immutable generations; validate Baffle filenames against the configured session directory before provisioning; do not combine values from incompatible reload generations.

## 7. Security acceptance requirements

**Authorization:** one Rego decision, from verified input, selects no caller-controlled mount paths or Baffle sessions. Reject malformed/unknown values. Pass the authorized absolute executable path and exact invocation to the supervisor without further command-name resolution; retain the point-in-time Rego hash check and trusted CWD input. Do not claim executable TOCTOU protection.

**Filesystem:** only direct paths declared in trusted filesystem profiles and a minimal runtime baseline are accessible. Deny path/symlink races, protected mount shadowing, leaked control sockets and inherited privileged FDs. Honor read-only vs read-write semantics.

**Network:** no direct external route, reachable parent proxy, or cross-command proxy connection. The selected Baffle UDS is the sole external-egress capability. No control socket or credential secret is visible inside the sandbox. Proxy failures never trigger direct fallback.

**Lifecycle:** per-invocation namespaces and leases; all descendants, listeners and session resources cleaned up after completion and cancellation. Concurrency does not share authority accidentally.

**Backend:** an unsupported or failed sandbox requirement cannot be ignored or downgraded. Rootless deployment restrictions fail clearly, without implicit unsandboxed execution.

## 8. Testing and validation

| Area | Essential tests |
| --- | --- |
| Rego | Allow/deny, differing filesystem/Baffle-file selections, invalid names/types, conflicting decisions, snapshot reload consistency. |
| `/check` | Reports intended profiles; performs no Baffle creation or process spawn; real execution reauthorizes. |
| Filesystem | RO blocks writes, RW allows writes, tmpfs ephemeral, unmounted files hidden, protected paths inaccessible, symlink/path/mount race tests. |
| Executable/CWD | Supervisor receives the resolved absolute executable path and authorized arguments/environment, performs no `PATH` lookup or policy recheck, and executes at the expected sandbox path; test ELF/shebang commands, authorized CWD selection, and spawn failures for missing or inaccessible CWD paths. No TOCTOU/identity-pinning tests. |
| Network | Bubblewrap with `baffle_session: null` has no external network; Baffle session rules remain enforced; Direct inherits Gantry networking and requires a null Baffle selection. |
| Concurrency | Simultaneous commands each bind `127.0.0.1:3128` with different Baffle sessions; neither can reach the other's endpoint. |
| Lifecycle | Success, nonzero exit, provisioning failure, mount failure, bridge failure, child cancellation, client disconnect, server termination, descendant cleanup, lease release. |
| Compatibility | Bubblewrap in supported Linux environments and rootless containers; namespace capability and live pathname UDS mount spike before dependent work. |

Include negative tests that deliberately attempt to connect to the parent proxy listener, open other Baffle session sockets, access protected filesystem paths, and use direct TCP egress.

## 9. Phased implementation plan

### Phase 0 — Feasibility spikes

- Demonstrate Bubblewrap nested mount/user/PID/network namespace creation in the intended runtime environment.
- Validate private loopback availability and a local TCP listener.
- Bind only a live Baffle pathname UDS into the child namespace and successfully proxy HTTPS CONNECT through it.
- Prove unwanted parent socket/network access is blocked.
- Test process-tree cleanup and lease loss when the parent dies.
- Demonstrate that the supervisor receives and runs the already-resolved absolute executable path with the authorized invocation, and that a missing or inaccessible authorized CWD causes a spawn error.

**Deliverable:** documented compatibility findings and any required kernel/container prerequisites. If critical assumptions fail, adjust the enforcement design before implementing the full backend.

### Phase 1 — Structured policy and profiles

- Implement the structured Rego result and migration from boolean `allow`.
- Define direct-path filesystem profile schema, Baffle configuration filename validation, and policy reload consistency.
- Build a validated `ExecutionPlan` with the already-authorized executable path, arguments, effective environment and CWD path.
- Extend `/check` and tests without side effects.

**Deliverable:** a policy-only dry run showing selected source paths and Baffle configuration file.

### Phase 2 — Backend abstraction and Bubblewrap filesystem isolation

- Introduce `ExecutionBackend` and `RunningExecution` lifecycle types.
- Implement isolated per-command Bubblewrap execution without external networking.
- Implement simple authorized-invocation handoff to the supervisor without a new executable lookup; use the authorized CWD path and preserve output and cancellation semantics.
- Add filesystem and namespace escape tests.

**Deliverable:** authorized commands run in isolated, no-network filesystem environments.

### Phase 3 — Per-command Baffle integration

- Integrate Baffle's existing client directly and implement ephemeral lease ownership.
- Implement `gantry-supervisor` with integrated Tokio TCP-to-UDS forwarding.
- Expose only the selected data UDS to the command sandbox.
- Set controlled proxy environment and public CA trust as required.
- Enforce readiness and cleanup on all success/failure paths.

**Deliverable:** independent commands can use different Baffle policies concurrently, without `socat`.

### Phase 4 — Hardening and documentation

- Complete real-Baffle end-to-end tests and negative isolation tests.
- Add useful diagnostics for policy selection, backend startup, Baffle session provisioning and cleanup, without leaking secrets or raw sensitive arguments unnecessarily.
- Document profile authoring, runtime prerequisites and unsupported environments.
- Confirm no implicit direct-execution fallback.

**Deliverable:** documented security guarantees and a production-ready initial backend.

## 10. Open decisions

1. **Trusted runtime root:** How should Gantry define and provision the minimum executable, dynamic libraries and system files while avoiding wholesale exposure of the parent root filesystem?
2. **Filesystem source integrity:** Which descriptor-based Linux APIs and mount strategy will preserve mount-source identity across Bubblewrap setup? Executable byte/inode identity across the authorization-to-spawn interval is explicitly not required.
3. **Baffle transport:** Should Gantry speak the Baffle control UDS directly when trusted, or use a separate broker? No general network-provider API is needed.
4. **Socket handoff:** What exactly is needed to safely mount and access a newly created Baffle Unix socket across nested namespaces and UID mappings?
5. **Process-tree termination:** Are PID namespaces plus supervisor signalling sufficient for all supported environments, or does Gantry additionally require cgroups or another reaper mechanism?
6. **Profile configuration and reload:** Finalize direct-path TOML schema, Baffle filename rules, reload consistency, and explicit migration from the legacy boolean policy.
7. **Quotas and execution limits:** Decide whether timeouts, memory, CPU, process limits and maximum tmpfs sizes belong in this proposal or a subsequent policy extension.

## Final acceptance criteria

This feature is complete when:

- Rego returns exactly one validated object with `allow`, `filesystem` and `baffle_session`.
- A named filesystem profile selects Bubblewrap; `filesystem: null` selects Direct only when enabled. Every allowed command still requires Rego authorization.
- Bubblewrap has no direct external networking without Baffle; Direct retains Gantry's existing network access and requires `baffle_session: null`.
- Filesystem profiles specify direct administrator-managed mount source paths; Rego selects Baffle session configuration filenames directly.
- Bubblewrap enforces the selected filesystem, process and network requirements per invocation.
- Optional Baffle access provisions a unique ephemeral session per command and keeps its lease until execution cleanup.
- The Rust supervisor supplies the local HTTP proxy via an in-process TCP-to-UDS bridge on `127.0.0.1:3128`, without `socat`.
- Concurrent commands have independent proxy and filesystem authority.
- The supervisor launches the same resolved absolute executable path and invocation authorized by Gantry, without another command-name lookup or policy evaluation. Executable changes after authorization are outside the guarantees. Existing command and check transports preserve their observable output/exit/cancellation contracts, with selected filesystem/Baffle names added to check diagnostics.
- All setup, isolation, provisioning and cleanup failures fail closed.
- The decision and profile contracts do not mention Bubblewrap and can be implemented by another enforcing backend.

## References

- [Gantry](https://github.com/dstoc/gantry)
- [Current Gantry command policy and API](https://github.com/dstoc/gantry/blob/main/README.md)
- [Gantry CWD authorization guarantees](https://github.com/dstoc/gantry/blob/main/docs/cwd-policy-guarantees.md)
- [Bubblewrap](https://github.com/containers/bubblewrap)
- [Baffle](https://github.com/dstoc/baffle)
- [Baffle control protocol](https://github.com/dstoc/baffle/blob/main/docs/control-protocol.md)
- [Baffle Rust client](https://github.com/dstoc/baffle/blob/main/docs/client.md)