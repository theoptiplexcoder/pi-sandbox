# Phased Implementation Plan: Modular, Sequential Engineering Roadmap for `claudelike-pisandbox`

**Target**: `claudelike-pisandbox` Pi Coding Agent Security Extension  
**Engineering Paradigm**: Verification-First, Mutually Exclusive Sequential Phases, Modular Architecture, Zero Leaky Abstractions  
**Author / Security Engineer**: Lead Security Engineer  

---

## Architecture Decomposition & Module Map

To ensure strict modularity and zero coupling across unrelated subsystems, the extension is structured into five distinct, loosely coupled layers:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Phase 5: Extension Lifecycle & UX                     │
│               (index.ts, src/ui.ts, slash commands, status bar)             │
└──────────────────────┬───────────────────────────────┬──────────────────────┘
                       │                               │
        ┌──────────────┴───────────────┐ ┌─────────────┴──────────────┐
        │   Phase 2: In-Process Guard  │ │ Phase 3: OS Containment    │
        │      (src/tool-guard.ts)     │ │ (src/bwrap.ts, bash-ops)   │
        └──────────────┬───────────────┘ └─────────────┬──────────────┘
                       │                               │
                       │                 ┌─────────────┴──────────────┐
                       │                 │  Phase 4: Network Proxy    │
                       │                 │ (src/proxy/http, socks5)   │
                       │                 └─────────────┬──────────────┘
                       │                               │
┌──────────────────────┴───────────────────────────────┴──────────────────────┐
│                    Phase 1: Configuration & Policy Engine                   │
│                    (src/config.ts, src/policy.ts, tests)                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

Each phase below is **mutually exclusive**, **self-contained**, and has an **explicit Definition of Done (DoD)** with automated verification tests before proceeding to subsequent phases.

---

## Phase 1: Policy & Configuration Core (Foundation Layer)

### Objective
Establish the immutable security policies, hierarchical configuration parsing, symlink canonicalization, secret matchers, and path glob engines. This phase has **zero dependencies on Pi runtime or external processes** and can be validated 100% deterministically.

### Modules to Build & Refine
1. **`src/config.ts`**:
   - `SandboxConfig`, `NetworkConfig`, `FilesystemConfig` TypeScript interfaces with complete JSDoc annotations.
   - Dual-tier configuration loader:
     - Global: `~/.pi/agent/sandbox.json`
     - Project-local: `<cwd>/.pi/sandbox.json`
   - Union-merge semantics for whitelist arrays (`allowWrite`, `allowedDomains`) and override semantics for flags (`enabled`).
   - Tilde expansion (`~` $\rightarrow$ `os.homedir()`).

2. **`src/policy.ts`**:
   - `canonicalizePath(path: string, baseCwd?: string): string`:
     - Resolves symlinks using native `realpathSync.native`.
     - Handles non-existent target files by traversing upward to the nearest existing ancestor and re-attaching trailing non-existent segments, defeating directory traversal exploits (`../../../../`).
   - `matchesPattern(path: string, patterns: string[], baseCwd?: string): boolean`:
     - Matches filename globs (`.env*`, `*.pem`, `*.key`, `id_rsa*`).
     - Matches path-based globs (`/var/log/*.log`).
     - Matches directory prefix paths (`~/.ssh` matches any file under `~/.ssh/`).
   - `isSecretPath(path: string, extraPatterns?: string[], baseCwd?: string): boolean`:
     - Built-in detection for sensitive credentials (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.netrc`, `/etc/shadow`, `/etc/sudoers`).
   - `decideReadPolicy(...)` and `decideWritePolicy(...)`:
     - Deterministic decision states: `"allow" | "deny" | "prompt"`.

### Developer Documentation Standards
- Every function must include explicit JSDoc explaining threat scenarios mitigated (e.g. symlink race conditions, traversal attacks).
- Clear inline comments detailing why native realpath is used over string normalization.

### Verification & Definition of Done (DoD)
- Unit test suite: `test/policy.test.ts`
- Tests must pass for:
  - Traversal attacks (`../../../../etc/passwd`).
  - Symlinked files pointing outside workspace boundaries.
  - Tilde expansion for user home directories.
  - Secret glob pattern matching (`.env.production`, `id_ed25519`, `server.key`).
  - Read/Write policy decision matrices for both relative and absolute paths.
- Command: `bun test test/policy.test.ts` (100% passing).

---

## Phase 2: In-Process Node Tool Guard (Tool Call Interception Layer)

### Objective
Secure Pi's direct Node.js built-in tools (`read`, `write`, `edit`) from prompt injections and unauthorized data access. These tools execute inside the Node process, so OS-level process sandboxes cannot constrain them; they must be guarded at the event level.

### Security Perimeter & Tool Boundaries (Directive D)
- **Phase 2 Perimeter**: Strictly protects Pi's direct Node.js built-in filesystem tools (`read`, `write`, `edit`).
- **Pi Built-in Context**: Pi only exposes `read`, `write`, `edit`, and `bash` as built-in coding agent tools. `grep`, `find`, and `ls` are not registered as standalone Node tools in Pi core; they run via the `bash` subprocess tool.
- **Subprocess & External Perimeter**: Shell executions (`bash` tool and interactive `!` commands), subprocesses, network calls, and package managers are explicitly isolated at the operating system kernel level in **Phase 3 (bwrap)** and **Phase 4 (network proxy)**.

### Modules to Build & Refine
1. **`src/tool-guard.ts`**:
   - `registerToolGuard(pi: ExtensionAPI, getOptions: () => ToolGuardOptions)`:
     - Subscribes to `pi.on("tool_call")`.
     - Validates and sanitizes parameters (rejects undefined, non-strings, empty paths, and null bytes `\0`).
     - Uses a shared `resolvePrompt()` helper to enforce fail-closed behavior across all operations.
     - Top-level `try/catch` wrapping: any unexpected exception in policy evaluation or prompter execution immediately returns `{ block: true, reason }`.
   - **Read Guard**:
     - Evaluates target path against `decideReadPolicy`.
     - If denied: returns `{ block: true, reason: "[Security Sandbox Violation] Reading '<path>' is denied by security policy." }`.
     - If prompt: delegates to `resolvePrompt()`. If `askPermission` is undefined (headless/non-interactive), **fails closed to block**.
   - **Write / Edit Guard**:
     - Evaluates target path against `decideWritePolicy`.
     - Prevents unauthorized modification of host files outside `allowWrite` (e.g. `~/.bashrc`, `/etc/crontab`).
     - Prevents tampering with sensitive files inside the workspace (e.g. `.env`, `.pi/sandbox.json`).
     - If prompt: delegates to `resolvePrompt()`. If headless/unapproved, **fails closed to block**.

### Developer Documentation Standards
- Document how Pi's `event.input` mutability works vs blocking with `{ block: true, reason }`.
- Document why `tool_call` errors block the tool fail-safe per Pi's security guidelines.

### Verification & Definition of Done (DoD)
- Unit & adversarial test suite: `test/tool-guard.test.ts`
- Tests must verify:
  - Reading `~/.ssh/id_rsa`, `/etc/shadow`, and `.env` returns `block: true`.
  - Writing or editing `.env`, `.pi/sandbox.json`, or files outside workspace is blocked or prompted.
  - Writing valid files inside workspace (`src/main.ts`, `/tmp/temp.log`) is allowed.
  - Directive A: Prompt decision with NO prompter blocks for both read and write (fail-closed).
  - Directive B: Malformed input (undefined, 42, null, array, empty, null byte `\0`) all block safely without throwing.
  - Directive C: Prompter throwing an exception fails closed and blocks.
  - Directive E: Dynamic config reactivity (mid-session toggle updates guard decisions instantly).
- Command: `bun test test/tool-guard.test.ts` (100% passing).

---

## Phase 3: OS-Level Subprocess Containment (`bwrap` Engine)

### Objective
Enforce kernel-level filesystem isolation, process hierarchy controls, and command containment for all shell executions (`bash` tool calls and interactive `!` commands).

### Modules to Build & Refine
1. **`src/bwrap.ts`**:
   - `isBwrapAvailable(): boolean`:
     - Checks host for `/usr/bin/bwrap` or `/bin/bwrap`.
   - `buildBwrapArgs(options: BwrapOptions): string[]`:
     - Generates deterministic CLI arguments for `bwrap`:
       - `--ro-bind / /`: Entire host root filesystem is mounted read-only.
       - `--dev /dev` & `--proc /proc`: Standard kernel pseudo-filesystems.
       - `--tmpfs /tmp`: Isolated ephemeral `/tmp` namespace.
       - `--bind $CWD $CWD`: Read-write bind mount strictly limited to current project root.
       - `--bind $PATH $PATH`: Binds any extra authorized absolute write paths from `config.filesystem.allowWrite`.
       - Secret Masking: Mounts empty `--tmpfs` over sensitive directories (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.netrc`, and any path in `denyRead`).
       - DenyWrite Protection: Mounts `--ro-bind` over files in `denyWrite` (e.g. `$CWD/.env`) so even within `$CWD`, scripts cannot modify them.
       - `--unshare-net`: Isolates network namespace (wired to proxy in Phase 4).
       - `--die-with-parent`: Eliminates orphaned processes if the parent crashes.
       - `--chdir $CWD`: Sets isolated process working directory.

2. **`src/bash-operations.ts`**:
   - `createSandboxedBashOps(getOptions: () => SandboxedBashOptions): BashOperations`:
     - Implements Pi's `BashOperations` interface (`exec(command, cwd, { onData, signal, timeout })`).
     - Spawns subprocess with `detached: true` into its own process group.
     - Process group lifecycle cleanup: on timeout or `signal.abort`, terminates the entire process tree via `process.kill(-child.pid, "SIGKILL")`.

### Developer Documentation Standards
- Detailed explanation of each bubblewrap flag, namespace semantics, and why tmpfs masking is used over bind-mounting `/dev/null`.
- Documentation of process group signal propagation (`-child.pid`).

### Verification & Definition of Done (DoD)
- Unit & functional test suite: `test/bwrap.test.ts`
- Tests must verify:
  - Command execution inside `$CWD` works.
  - Writing outside `$CWD` (`touch /etc/test.tmp` or `touch ~/.bashrc`) triggers a read-only filesystem error.
  - Secret directories (`~/.ssh`) appear completely empty inside the container.
  - Timeouts and abort signals clean up all spawned child processes.
- Command: `bun test test/bwrap.test.ts` (100% passing).

---

## Phase 4: Network Egress Containment & Domain-Filtering Proxy

### Objective
Prevent data exfiltration, phone-home malware, and unauthorized remote access by confining outbound network connections to an approved domain whitelist with interactive TUI prompting.

### Modules to Build & Refine
1. **`src/proxy/domain-matcher.ts`**:
   - `domainMatchesPattern(domain: string, pattern: string): boolean`:
     - Matches exact hosts (`github.com`).
     - Matches wildcard subdomains (`*.github.com`, `*.npmjs.org`).
     - Case-insensitive normalization.
   - `isDomainAllowed(domain: string, allowedDomains: string[], deniedDomains: string[]): boolean`:
     - Denied domains always override allowed entries.

2. **`src/proxy/http-proxy.ts`**:
   - `createHttpProxy(options: HttpProxyOptions): http.Server`:
     - HTTP/1.1 forward proxy handler.
     - HTTPS `CONNECT` tunnel handler (`CONNECT host:port`).
     - Inspects requested target hostname.
     - If allowed: tunnels connection via `net.connect()`.
     - If unknown: triggers `onUnknownDomain(hostname, port)` hook. If approved, tunnels traffic; otherwise terminates with `HTTP 403 Forbidden`.

3. **`src/proxy/proxy-server.ts`**:
   - `startProxyServer(...)`:
     - Starts the in-memory proxy server listening on local loopback interface or Unix domain socket.
     - Creates secure temporary directory (`mode: 0o700`) for IPC sockets.
     - Provides clean `stop()` method to close all open client/server sockets and unlink temporary files.

### Developer Documentation Standards
- Document HTTP `CONNECT` tunneling protocol flow.
- Document how the proxy integrates with `bwrap --unshare-net` via environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) and Unix sockets.

### Verification & Definition of Done (DoD)
- Unit & integration test suite: `test/domain-matcher.test.ts` and `test/proxy.test.ts`
- Tests must verify:
  - Allowed domains connect successfully.
  - Denied domains are immediately rejected with HTTP 403.
  - Wildcard domain rules work across multi-level subdomains.
  - Proxy shuts down cleanly without socket leaks.
- Command: `bun test test/domain-matcher.test.ts` (100% passing).

---

## Phase 5: Extension Lifecycle, TUI & Developer Ergonomics

### Objective
Integrate all four underlying layers into the native Pi extension ecosystem, providing seamless operator controls, interactive permission dialogs, visual status indicators, and slash commands.

### Modules to Build & Refine
1. **`src/ui.ts`**:
   - `promptPermission(ctx: ExtensionContext, title: string, target: string)`:
     - Uses `ctx.ui.select` to present clean, structured approval options:
       - `[1] Allow for this session`
       - `[2] Allow and save to project (.pi/sandbox.json)`
       - `[3] Deny (Abort)`
     - In headless / non-interactive mode (`ctx.hasUI === false`), automatically defaults to fail-closed (`abort`).

2. **`index.ts` (Extension Entry Point)**:
   - Registers custom sandboxed bash tool via `createBashTool(cwd, { operations: sandboxedBashOps })`.
   - Replaces bash tool with `pi.registerTool({ ...sandboxedBashTool, label: "bash (sandboxed)" })`.
   - Intercepts interactive user commands via `pi.on("user_bash")`.
   - Registers tool call guard via `registerToolGuard(pi, ...)`.
   - Connects `pi.on("session_start")`: loads configs, verifies `bwrap`, initializes proxy, sets status indicator (`🔒 Sandbox Active (bwrap + proxy)`).
   - Connects `pi.on("session_shutdown")`: cleanly tears down proxy server and removes temporary directories.
   - Registers slash commands:
     - `/sandbox`: Formats and displays active rules, allowed domains, and session grants.
     - `/sandbox-toggle`: Allows operator to enable or disable sandboxing dynamically.

3. **Developer Documentation (`README.md` & JSDoc)**:
   - Complete architectural overview, configuration guides, example `.pi/sandbox.json` recipes, and security boundary explanations.

### Verification & Definition of Done (DoD)
- Full end-to-end typecheck: `bun run typecheck` (0 errors).
- Full end-to-end test suite: `bun test` (all tests passing across all suites).
- Interactive verification in Pi:
  - `/sandbox` displays active configuration.
  - Status bar shows `🔒 Sandbox Active`.
  - Manual test of blocked command (`touch /etc/evil`) and blocked secret read (`cat ~/.ssh/id_rsa`).

---

## Phase Dependencies & Sequencing Summary

| Phase | Core Deliverable | Dependencies | Verification Command |
|---|---|---|---|
| **Phase 1** | Policy & Config Engine (`config.ts`, `policy.ts`) | *None (Pure TS)* | `bun test test/policy.test.ts` |
| **Phase 2** | In-Process Tool Guard (`tool-guard.ts`) | Phase 1 | `bun test test/tool-guard.test.ts` |
| **Phase 3** | OS Subprocess Containment (`bwrap.ts`, `bash-operations.ts`) | Phase 1 | `bun test test/bwrap.test.ts` |
| **Phase 4** | Domain Filtering Proxy (`proxy/`) | Phase 1 | `bun test test/domain-matcher.test.ts` |
| **Phase 5** | Extension Lifecycle & TUI (`index.ts`, `ui.ts`, README) | Phases 1–4 | `bun test && bun run typecheck` |
