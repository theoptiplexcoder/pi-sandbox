# Key Task Checklist: `claudelike-pisandbox` Implementation

Tracking progress of security engineering tasks for the dual-layer sandboxing extension.

---

## Phase 1: Security Policy & Configuration Engine
- [ ] **Task 1.1**: Create `config.default.json` with baseline filesystem deny/allow rules and network domain allowlists.
- [ ] **Task 1.2**: Implement `src/config.ts` to load and merge global (`~/.pi/agent/sandbox.json`) and project-local (`<cwd>/.pi/sandbox.json`) configs.
- [ ] **Task 1.3**: Implement `src/policy.ts`:
  - [ ] Path canonicalization with symlink resolution (`realpathSync.native`).
  - [ ] Pattern and glob matcher (`matchesPattern`).
  - [ ] Secret detection engine (covering `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `.env*`, `*.pem`, `*.key`).
- [ ] **Task 1.4**: Implement `test/policy.test.ts` to test path traversal attacks (`../../`), symlink escapes, and secret matching. Run with `bun test`.

---

## Phase 2: In-Process Tool Guard (Node.js Direct Tools)
- [ ] **Task 2.1**: Implement `src/tool-guard.ts` to intercept `pi.on("tool_call")` for `read`, `write`, and `edit`.
- [ ] **Task 2.2**: Block unauthorized reads/writes to secret files with explicit security feedback.
- [ ] **Task 2.3**: Gate writes outside working directory (`cwd`) and `/tmp`.
- [ ] **Task 2.4**: Add automated test cases for tool interception and blocking behavior.

---

## Phase 3: Bubblewrap Subprocess Containment
- [ ] **Task 3.1**: Verify environment support for `bwrap` (check availability and permissions).
- [ ] **Task 3.2**: Implement `src/bwrap.ts`:
  - [ ] Generate strict `bwrap` command-line flags (`--ro-bind / /`, `--bind $CWD $CWD`, `--tmpfs /tmp`, masking `~/.ssh` etc.).
  - [ ] Detached process group execution (`detached: true`).
  - [ ] Signal handling and timeout cleanup via `process.kill(-child.pid, "SIGKILL")`.
- [ ] **Task 3.3**: Implement `src/bash-operations.ts` implementing `BashOperations` (`exec`).
- [ ] **Task 3.4**: Integrate with Pi:
  - [ ] Replace `bash` tool using `createBashTool(cwd, { operations })`.
  - [ ] Intercept interactive shell commands via `pi.on("user_bash")`.
- [ ] **Task 3.5**: Verify host protection against command attacks (e.g. `touch /etc/hacked`, `rm -rf /`, `cat ~/.ssh/id_rsa`).

---

## Phase 4: Network Isolation & Domain-Filtering Proxy
- [ ] **Task 4.1**: Implement `src/proxy/domain-matcher.ts` supporting exact domains, wildcards (`*.github.com`), and IP checks.
- [ ] **Task 4.2**: Implement `src/proxy/http-proxy.ts`:
  - [ ] In-memory HTTP server handling `CONNECT` tunnels and plain HTTP forward requests.
- [ ] **Task 4.3**: Implement `src/proxy/socks5-proxy.ts`:
  - [ ] SOCKS5 server for raw TCP/git/ssh/curl traffic.
- [ ] **Task 4.4**: Implement `src/proxy/proxy-server.ts`:
  - [ ] Unix domain socket listener in secure directory (`0700`).
  - [ ] Domain whitelist check and prompt delegate.
- [ ] **Task 4.5**: Wire proxy into `bwrap` execution (`--unshare-net`, socket binding, proxy environment variables).
- [ ] **Task 4.6**: Implement interactive TUI permission prompt (`src/ui.ts`) when unlisted domains are requested.
- [ ] **Task 4.7**: Verify network exfiltration prevention (e.g. `curl http://attacker.com` is blocked or prompted).

---

## Phase 5: Extension Lifecycle, UX & Hardening
- [ ] **Task 5.1**: Implement `index.ts` connecting lifecycle hooks (`session_start`, `session_shutdown`).
- [ ] **Task 5.2**: Register `/sandbox` and `/sandbox-toggle` slash commands.
- [ ] **Task 5.3**: Add visual status indicators (`ctx.ui.setStatus`).
- [ ] **Task 5.4**: Run end-to-end security test suite (`bun test`).
- [ ] **Task 5.5**: Document setup and verification in `README.md`.
