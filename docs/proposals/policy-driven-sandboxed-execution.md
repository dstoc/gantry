# Proposal: Policy-Driven Sandboxed Execution

**Project:** Gantry  
**Status:** Draft  
**Scope:** Gantry only  
**Prerequisite:** The `mcp-run` → `gantry` rename and repository extraction are complete and not part of this proposal.

## Summary

Evolve Gantry from a policy-enforced command runner into a **policy-driven, per-invocation sandboxed execution system**. Rego authorizes the requested command and selects two independently named resources:

- A **filesystem profile**, specifying which trusted resources the command may see and modify.
- A **network profile**, specifying which (if any) controlled network access the command receives.

Gantry resolves that decision into a backend-neutral execution plan. An execution backend enforces the plan; **Bubblewrap (`bwrap`) is the initial backend**, but is not exposed in the Rego contract. For a selected Baffle network policy, Gantry creates a fresh, leased proxy session per command. A small Rust **`gantry-supervisor`** inside the command's private network namespace provides a localhost TCP-to-Unix-socket bridge without `socat`.

Every command runs with a new isolation boundary, including commands for which Rego selects no network access. Authorization and sandbox establishment are fail-closed. Existing MCP, raw streaming, and check interfaces remain the command-facing entry points.

## Motivation and existing behaviour

Gantry currently evaluates a boolean Rego query, `data.sandbox.main.allow`, then executes the resolved command directly using `tokio::process::Command`. Rego can inspect the requested command, resolved path, executable SHA-256, arguments, forwarded environment, and a trusted working-directory label. The `POST /check` and MCP `check_command` paths share pre-spawn authorization with actual execution.

A boolean approval alone cannot distinguish a command allowed to read a checkout, one allowed to change it, or one permitted to contact a narrowly specified API with injected credentials. Nor can a shared parent-container proxy provide independent network authority to two simultaneous commands when either can connect to the same socket or listener.

This design gives each invocation its own filesystem view and network namespace, while keeping Baffle responsible for HTTPS policy, destination/path restrictions, and credential injection.

## Goals

1. Extend Rego to return a single, structured authorization decision containing `allow`, `filesystem`, and `network`.
2. Select **named, administrator-controlled** profiles, not caller-provided mount arguments, paths, or Baffle session IDs.
3. Provide backend-neutral filesystem and network requirements, enforced first by Bubblewrap.
4. Create an isolated filesystem, process environment, and network namespace for every command.
5. Give each network-authorized command a unique ephemeral Baffle session and only that session's data socket.
6. Implement a local HTTP-proxy-compatible TCP-to-UDS bridge in Rust, without `socat` or another long-running external bridge service.
7. Preserve current no-shell command semantics, executable/CWD authorization invariants, streamed output, exit reporting, and cancellation.
8. Fail closed when policy evaluation, profile resolution, resource provisioning, namespace creation, mount setup, bridge initialization, or execution fails.
9. Keep future OCI/microVM backends possible without changing Rego policy names or semantics.

## Non-goals

- Changes to Cladding, its container topology, or its mount configuration.
- Changes to the Baffle daemon, v2 control protocol, or session policy syntax.
- Implementing other execution backends in this work.
- Arbitrary mounts, backend selection, or Baffle session creation requested by an untrusted command caller.
- Unrestricted direct network access, shell interpolation, or a generic network-forwarding service.
- A complete resource quota framework; memory, CPU, and PID limits can be designed separately.

## Proposed architecture

```text
MCP /raw /check request
         |
         v
Trusted resolution + Rego authorization
  -> { allow, filesystem, network }
         |
         v
Execution planner
  - Resolve named profiles and trusted resources
  - Validate backend capabilities
  - Preserve authorized executable + cwd identity
  - Create optional leased network session
         |
         v
ExecutionBackend (Bubblewrap initially)
  - Mount-only authorized filesystem view
  - Isolated user, PID, mount and network namespaces
  - No inherited proxy/control sockets or network routes
         |
         v
 gantry-supervisor (inside sandbox)
  - Optional 127.0.0.1:3128 -> selected Baffle data UDS
  - Spawn command directly; supervise/stream/terminate
         |
         v
Command exit -> process cleanup -> Baffle lease released
```

**Boundary:** Rego decides permitted access. Named profile files describe that access. The execution planner resolves it to trusted, concrete resources. A backend implements isolation. Baffle owns network policy and injected secrets. Neither the backend nor the command may elevate the Rego-selected authority.

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
    "network": null,
}

decision := {
    "allow": true,
    "filesystem": "workspace-readonly",
    "network": "github-readonly",
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
    "network": null,
} if {
    input.command == "cargo"
    input.args == ["test"]
}
```

| Field | Type | Contract |
| --- | --- | --- |
| `allow` | boolean | Required; only `true` permits execution. |
| `filesystem` | string or null | Required string for authorized invocations; names a trusted filesystem profile. |
| `network` | string or null | Required; `null` means no external network, otherwise names a trusted network profile. |

For a denied decision, only `allow: false` has effect. For an allowed decision, an unknown/empty/invalid filesystem name, unknown network name, undefined result, malformed type, or multiple conflicting decisions must deny the invocation. **There is no implicit unrestricted filesystem or network policy.**

Evaluate authorization and profile selection together, not as unrelated queries against potentially different policy generations. Preserve command-specific `data.sandbox[...].allow` modules where useful by adapting the router policy. Retaining `sandbox` avoids coupling this change to an unrelated Rego package rename; changing the package name can be a separate migration.

Rego must not return raw filesystem paths, mount flags, Baffle credentials, or already-created Baffle session identifiers. The caller's request shape stays unchanged.

### Checks

`POST /check`, MCP `check_command`, and `run-remote --check` report the selected names and the configured backend while retaining existing executable, hash, cwd, policy-mode and denial diagnostics:

```json
{
  "allowed": true,
  "reason": null,
  "filesystem": "workspace-readonly",
  "network": "github-readonly",
  "backend": "bubblewrap"
}
```

A check may validate static profile existence/schema and backend compatibility, but **must not** create a Baffle session, mount filesystems, or launch Bubblewrap. It remains advisory and point-in-time: the real execution reauthorizes and may fail during provisioning. Explicitly document migration from the current boolean `allow` contract. A compatibility mode, if offered, must not imply an unrestricted filesystem by default.

## 2. Filesystem policies and trusted resources

### Named declarative profiles

Suggested configuration layout (paths and exact schema to be finalized):

```text
config/
  gantry.toml
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
kind = "resource"
resource = "workspace"
target = "/workspace"
access = "read-only"

[[mounts]]
kind = "tmpfs"
target = "/tmp"
size = "256MiB"
```

A writable profile may use `access = "read-write"` for an explicitly writable resource. Other initial mount kinds may include empty directories; do not introduce arbitrary filesystem overlays or copy-on-write implicitly.

### Resource ceiling

Resources are declared separately by the trusted Gantry operator, for example:

```toml
[resources.workspace]
path = "/srv/workspace"
max_access = "read-write"
```

The filesystem profile selects a subset of previously configured resources and may request **no more access** than their maximum declared permissions. It cannot reference arbitrary host paths supplied by the command or dynamically computed by Rego. Multiple profiles can share resource names without duplicating the underlying path configuration.

The term "host path" here is relative to Gantry's own trusted runtime filesystem, not necessarily the physical machine's filesystem. Gantry cannot expose resources beyond those available to its process.

### Minimal trusted runtime root

The execution backend must construct a limited runtime view for program execution: selected executable and libraries, essential runtime files, a suitable `/proc` view, and private temporary state. This trusted baseline is *not* the entirety of the parent container's root filesystem and must not expose credentials, control sockets, or unrelated application data.

A selected filesystem profile adds explicit resources to that baseline. Runtime dependencies and environment-specific filesystem setup should be documented as a separate, administrator-controlled part of Gantry configuration. If the authorized executable or cwd cannot be made available without expanding access, fail.

### Filesystem invariants

- Resolve resource names and filesystem policy definitions in trusted code.
- Reject unsafe sources, symlinks, traversal, overlapping mounts, and protected-target shadowing unless a precisely defined, safe ordering exists.
- Preserve source identity across validation and mount setup; prefer fd-based resolution where available.
- Preserve the existing **fd-resolved cwd guarantee** documented in `docs/cwd-policy-guarantees.md`: execution must use the directory that policy evaluated, accounting for namespace translation.
- Execute the same authorized executable object or prove equivalence across the sandbox boundary; do not authorize one host path and execute an attacker-substituted path inside the sandbox.
- Scrub inherited descriptors and environment variables which could grant access outside selected resources.
- Writable mounts are genuinely writable; edits to those resources are not assumed to be disposable.

## 3. Network policies and Baffle sessions

### Named network profiles

A network profile is a trusted mapping from a Rego-selected name to a provider and its administrator-managed configuration:

```toml
[networks.github-readonly]
provider = "baffle"
session = "github-readonly.toml"
```

The session path is a **Baffle file-only configuration name** (relative to Baffle's configured `session_config_dir`), not a session ID, secret, or free-form user-supplied policy. Baffle resolves, validates, and snapshots the actual v2 TOML file.

Example Baffle session file:

```toml
version = 2
persistent = false
unmatched = "deny"

[rules."api.github.com"]
paths = ["/repos/dstoc/**"]
```

Omit `socket_name` for per-command profiles so concurrently provisioned sessions receive generated, unique paths. A non-null network selection requires successful session creation before command start. A null network selection creates no Baffle session and provides no external network.

### Trusted Baffle provider

Introduce a provider abstraction (illustrative Rust):

```rust
trait NetworkSessionProvider {
    async fn create(&self, profile: &NetworkProfile)
        -> Result<NetworkSession>;
}
```

The initial provider uses Baffle's existing `baffle-client` and `create_from_file` operation, either over a trusted direct control UDS or via a trusted broker. These deployment options remain interchangeable behind the interface. Gantry must **never expose the Baffle control socket or injected secret material to the command**.

An ephemeral Baffle session is leased over the create control connection; keep the returned handle alive for the whole workload. Require `persistent = false`, verify the created session is ephemeral, and fail (and clean up) if it is not. Close the lease after normal completion, cancellation, spawn failure, or unexpected termination. Baffle handles its own session socket removal on lease release.

The provider returns a typed leased endpoint and does not make any command network connections. The execution backend receives only the selected data endpoint, not provider control authority.

### No network means no network

With `network: null`, use a private network namespace with no external routes or inherited reachable external interfaces. Do not provide any proxy socket or proxy environment. A private loopback interface may be used for processes within that invocation. Caller-provided proxy variables and bypass controls must not override these restrictions.

## 4. Pluggable execution backends

Introduce a backend-neutral validated plan, plus a lifecycle-bearing handle:

```rust
trait ExecutionBackend {
    async fn start(&self, plan: ExecutionPlan)
        -> Result<RunningExecution>;
}
```

`ExecutionPlan` includes the authorized executable identity, argument vector, effective working directory, sanitized environment, resolved filesystem resources and access modes, optional leased network attachment, stdio configuration, and required isolation/lifecycle constraints.

`RunningExecution` supports streamed output, exit status, cancellation and cleanup. Exact Rust type and ownership details are implementation decisions; the important property is **no orphaned process tree or leaked Baffle lease** when the caller disconnects or execution fails.

The backend is selected through trusted Gantry configuration, **not Rego**. Initially `bubblewrap` is the only isolating backend. Future OCI/container or microVM backends can translate the same requirements into their mechanisms, but they must reject unsupported requirements rather than silently degrade isolation. Any temporary direct-execution backend used solely for tests must never be an implicit production fallback.

Use capability validation before provisioning. Concurrent runs must each retain their own immutable policy/profile snapshot and execution ownership.

## 5. Bubblewrap backend

### Per-invocation isolation

Spawn a new Bubblewrap sandbox for **every** authorized command, including commands without network access. Configure a private mount namespace, PID namespace, and network namespace (using `--unshare-net`) with appropriate user namespace, session, capability and inherited-descriptor restrictions. Do not rely on the parent container's default filesystem/proxy access as the child's security policy.

Construct the filesystem view explicitly from the trusted runtime baseline plus selected resource mounts. Create private `/proc` and temporary filesystem views appropriate to the PID and mount namespace. Use `--die-with-parent`, `--new-session`, and process-group/cgroup cleanup as applicable, but verify that descendant processes cannot outlive a completed or cancelled execution.

Nested user/network namespaces may be blocked by kernel settings, seccomp, or rootless container configuration. Detect unsupported environments clearly. **Never fall back to unsandboxed command execution.**

### Per-command localhost bridge

Inside the sandbox run a small Rust binary, **`gantry-supervisor`**, whose responsibilities are:

1. Accept one assigned Baffle data UDS path (if networking was authorized).
2. Make sure private loopback is usable (verify and arrange startup; don't assume it works in every namespace configuration).
3. Start a TCP listener on `127.0.0.1:3128` in this invocation's network namespace.
4. For each TCP client, connect to the assigned Unix socket and forward bytes bidirectionally using Tokio.
5. Signal bridge readiness before spawning the authorized command.
6. Spawn the authorized executable directly, without invoking a shell, and supervise its process tree.
7. Relay stdout/stderr and exit status through the existing Gantry protocol; terminate the bridge and descendants on completion/cancellation.

Commands in different network namespaces can each use the same port without colliding:

```text
Command A: 127.0.0.1:3128 -> session A UDS
Command B: 127.0.0.1:3128 -> session B UDS
```

Expose **only the selected Baffle data UDS** in the child filesystem view, at a fixed sandbox-private location such as `/run/gantry/proxy.sock`. Do not mount the parent Baffle session directory, provider control UDS, or other sessions' data sockets. Validate Linux pathname Unix socket bind-mount semantics across user/mount/network namespaces with a real Baffle integration test before settling on the exact mount mechanics. If safely exposing a live socket is impossible on a target backend, reject execution or design an equally isolated transport—not a shared proxy listener.

Set trusted proxy variables in the command environment only when networking is selected:

```text
http_proxy=http://127.0.0.1:3128
https_proxy=http://127.0.0.1:3128
HTTP_PROXY=http://127.0.0.1:3128
HTTPS_PROXY=http://127.0.0.1:3128
```

Do not permit forwarded `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, lowercase counterparts, or tool-specific proxy settings to redirect traffic around the selected endpoint. Provide the **public** Baffle CA certificate when TLS interception is needed; do not expose its private key or credential files. Baffle remains responsible for CONNECT-only HTTPS behaviour, host/path policy and injection.

The command supervisor is a process *within the isolation boundary*, not a privileged session broker. It must not receive Baffle control authority.

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
- Retain deny-all behaviour on policy startup/reload errors. Load Rego, filesystem profiles, resource mappings and network mappings into coherent immutable generations; do not combine values from incompatible reload generations.

## 7. Security acceptance requirements

**Authorization:** one Rego decision, from verified input, selects no caller-controlled resource paths or proxy sessions. Reject malformed/unknown values. Retain executable hash and fd-resolved cwd guarantees through the namespace boundary.

**Filesystem:** only declared trusted resources and a minimal runtime baseline are accessible. Deny path/symlink races, protected mount shadowing, leaked control sockets and inherited privileged FDs. Honor read-only vs read-write semantics.

**Network:** no direct external route, reachable parent proxy, or cross-command proxy connection. The selected Baffle UDS is the sole external-egress capability. No control socket or credential secret is visible inside the sandbox. Proxy failures never trigger direct fallback.

**Lifecycle:** per-invocation namespaces and leases; all descendants, listeners and session resources cleaned up after completion and cancellation. Concurrency does not share authority accidentally.

**Backend:** an unsupported or failed sandbox requirement cannot be ignored or downgraded. Rootless deployment restrictions fail clearly, without implicit unsandboxed execution.

## 8. Testing and validation

| Area | Essential tests |
| --- | --- |
| Rego | Allow/deny, differing filesystem/network selections, invalid names/types, conflicting decisions, snapshot reload consistency. |
| `/check` | Reports intended profiles; performs no Baffle creation or process spawn; real execution reauthorizes. |
| Filesystem | RO blocks writes, RW allows writes, tmpfs ephemeral, unmounted files hidden, protected paths inaccessible, symlink/path/mount race tests. |
| Executable/CWD | Same object and opened cwd are used after authorization; no substitution across mounts or namespace transitions. |
| Network | `network: null` blocks direct egress; selected HTTPS CONNECT succeeds; Baffle host/path/credential rules respected; no alternate proxy or control socket access. |
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

**Deliverable:** documented compatibility findings and any required kernel/container prerequisites. If critical assumptions fail, adjust the enforcement design before implementing the full backend.

### Phase 1 — Structured policy and profiles

- Implement the structured Rego result and migration from boolean `allow`.
- Define trusted resource and filesystem profile schemas, network mappings and validation.
- Build an immutable validated `ExecutionPlan` for each invocation.
- Extend `/check` and tests without side effects.

**Deliverable:** a policy-only dry run showing authorized resources and selected isolation requirements.

### Phase 2 — Backend abstraction and Bubblewrap filesystem isolation

- Introduce `ExecutionBackend` and `RunningExecution` lifecycle types.
- Implement isolated per-command Bubblewrap execution without external networking.
- Preserve executable/CWD identity, output and cancellation semantics.
- Add filesystem and namespace escape tests.

**Deliverable:** authorized commands run in isolated, no-network filesystem environments.

### Phase 3 — Per-command Baffle integration

- Implement the trusted Baffle provider and ephemeral lease ownership.
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
2. **Filesystem source integrity:** Which descriptor-based Linux APIs and mount strategy will preserve the authorized executable, cwd and resource identity across Bubblewrap setup?
3. **Baffle transport:** Should Gantry speak the Baffle control UDS directly when trusted, or use a separate broker? Keep the provider API independent of that deployment choice.
4. **Socket handoff:** What exactly is needed to safely mount and access a newly created Baffle Unix socket across nested namespaces and UID mappings?
5. **Process-tree termination:** Are PID namespaces plus supervisor signalling sufficient for all supported environments, or does Gantry additionally require cgroups or another reaper mechanism?
6. **Profile configuration and reload:** Finalize TOML schema, profile filename rules, snapshot changes and explicit migration from the legacy boolean policy.
7. **Quotas and execution limits:** Decide whether timeouts, memory, CPU, process limits and maximum tmpfs sizes belong in this proposal or a subsequent policy extension.

## Final acceptance criteria

This feature is complete when:

- Rego returns exactly one validated object with `allow`, `filesystem` and `network`.
- Every authorized command requires a named filesystem profile and always runs in an isolated sandbox.
- Network access is absent by default and never falls back to direct egress.
- Profiles refer only to administrator-managed trusted resources and Baffle session configurations.
- Bubblewrap enforces the selected filesystem, process and network requirements per invocation.
- Optional Baffle access provisions a unique ephemeral session per command and keeps its lease until execution cleanup.
- The Rust supervisor supplies the local HTTP proxy via an in-process TCP-to-UDS bridge on `127.0.0.1:3128`, without `socat`.
- Concurrent commands have independent proxy and filesystem authority.
- Existing command and check transports preserve their observable output/exit/cancellation contracts, with selected profiles added to check diagnostics.
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