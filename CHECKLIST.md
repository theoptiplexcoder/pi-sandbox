# Key Task Checklist: `claudelike-pisandbox` Implementation

Tracking progress of security engineering tasks for the dual-layer sandboxing extension.

---

## Phase 1: Security Policy & Configuration Engine
- [x] **Task 1.1**: Create `config.default.json` with baseline filesystem deny/allow rules and network domain allowlists.
- [x] **Task 1.2**: Implement `src/config.ts` to load and merge global (`~/.pi/agent/sandbox.json`) and project-local (`<cwd>/.pi/sandbox.json`) configs.
- [x] **Task 1.3**: Implement `src/policy.ts`:
  - [x] Path canonicalization with symlink resolution (`realpathSync.native`).
  - [x] Pattern and glob matcher (`matchesPattern`).
  - [x] Secret detection engine (covering `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `.env*`, `*.pem`, `*.key`).
- [x] **Task 1.4**: Implement `test/policy.test.ts` to test path traversal attacks (`../../`), symlink escapes, and secret matching. Run with `bun test`.

---

## Phase 2: In-Process Tool Guard (Node.js Direct Tools)
- [x] **Task 2.1**: Implement `src/tool-guard.ts` to intercept `pi.on("tool_call")` for `read`, `write`, and `edit`.
- [x] **Task 2.2**: Block unauthorized reads/writes to secret files with explicit security feedback.
- [x] **Task 2.3**: Gate writes outside working directory (`cwd`) and `/tmp`.
- [x] **Task 2.4**: Add automated test cases for tool interception and blocking behavior (`test/tool-guard.test.ts`).

---

## Phase 3: Bubblewrap Subprocess Containment
- [x] **Task 3.1**: Verify environment support for `bwrap` (check availability and permissions).
- [x] **Task 3.2**: Implement `src/bwrap.ts`:
  - [x] Generate strict `bwrap` command-line flags (`--ro-bind / /`, `--bind $CWD $CWD`, `--tmpfs /tmp`, masking `~/.ssh` etc.).
  - [x] Detached process group execution (`detached: true`).
  - [x] Signal handling and timeout cleanup via `process.kill(-child.pid, "SIGKILL")`.
- [x] **Task 3.3**: Implement `src/bash-operations.ts` implementing `BashOperations` (`exec`).
- [x] **Task 3.4**: Integrate with Pi:
  - [x] Replace `bash` tool using `createBashTool(cwd, { operations })`.
  - [x] Intercept interactive shell commands via `pi.on("user_bash")`.
- [x] **Task 3.5**: Verify host protection against command attacks via unit tests (`test/bwrap.test.ts`).

---

## Phase 4: Network Isolation & Domain-Filtering Proxy
- [x] **Task 4.1**: Implement `src/proxy/domain-matcher.ts` supporting exact domains, wildcards (`*.github.com`), and IP checks.
- [x] **Task 4.2**: Implement `src/proxy/http-proxy.ts`:
  - [x] In-memory HTTP server handling `CONNECT` tunnels and plain HTTP forward requests.
- [x] **Task 4.4**: Implement `src/proxy/proxy-server.ts`:
  - [x] In-memory proxy manager with clean lifecycle stop/cleanup.
  - [x] Domain whitelist check and prompt delegate.
- [x] **Task 4.5**: Wire proxy into `bwrap` execution (`--unshare-net`, socket binding).
- [x] **Task 4.6**: Implement interactive TUI permission prompt (`src/ui.ts`) when unlisted domains are requested.

---

## Phase 5: Extension Lifecycle, UX & Hardening
- [x] **Task 5.1**: Implement `index.ts` connecting lifecycle hooks (`session_start`, `session_shutdown`).
- [x] **Task 5.2**: Register `/sandbox` and `/sandbox-toggle` slash commands.
- [x] **Task 5.3**: Add visual status indicators (`ctx.ui.setStatus`).
- [x] **Task 5.4**: Run end-to-end security test suite (`bun test`).
- [x] **Task 5.5**: Document setup and verification in `README.md`.
