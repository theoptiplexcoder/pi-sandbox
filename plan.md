# Implementation Plan: Claude-Like Dual-Layer Sandboxing Extension for Pi (`claudelike-pisandbox`)

**Author / Role:** Principal Security Engineer  
**Target:** `pi-coding-agent` Extension Ecosystem (`/home/ybl/git/pi-setup/extensions/claudelike-pisandbox`)  
**References:**
- Anthropic Research: *Claude Code Sandboxing* ([Blog & Architecture Diagrams](https://www.anthropic.com/research/claude-code-sandboxing))
- Pi Official Documentation: `security.md`, `containerization.md`, `extensions.md`, `tui.md`
- Local System: Linux x86_64, `bubblewrap` (`bwrap`) 0.11.0, Node v26, Bun v1.3

---

## 1. Threat Model & Security Objectives

Pi is a coding agent with broad capabilities. By default:
- Direct tool calls (`read`, `write`, `edit`) execute inside the Node process with the privileges of the local user.
- Subprocesses (`bash` tool and interactive `!` commands) run directly in the host shell without process or filesystem restrictions.
- In-flight prompt injections (e.g. from untrusted PRs, cloned repositories, malicious dependencies, or third-party web content) can:
  1. **Exfiltrate host secrets**: Read `~/.ssh/id_*`, `~/.aws/credentials`, `~/.gnupg`, `~/.config/gh/hosts.yml`, `.env`, and send them via `curl`/`wget` to attacker C2 servers.
  2. **Compromise host integrity**: Overwrite `~/.bashrc`, `~/.profile`, `/etc/`, host crontabs, or system binaries.
  3. **Establish persistence / botnets**: Spawn background daemon listeners, reverse shells, or mining processes.

### Core Security Mandates:
1. **Zero Unrestricted Host Writes**: Outside the project working directory (`cwd`) and ephemeral `/tmp`, all writes must be strictly denied at the OS kernel level and blocked at the tool hook layer.
2. **Invisible Secrets**: Host secret directories (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`) must be hidden via empty read-only mounts in subprocesses and blocked from direct `read`/`edit` calls.
3. **Network Egress Containment**: Subprocesses run in an unshared network namespace (`--unshare-net`). Outbound traffic is proxied through a local Unix domain socket connecting to an external filtering proxy that enforces an `allowedDomains` whitelist with interactive TUI prompting for unknown domains.
4. **Subprocess Group Teardown**: Prevent runaway or orphaned background processes by running commands in dedicated process groups (`kill(-pid, SIGKILL)` on abort/timeout).
5. **Mitigation of Approval Fatigue**: Routine development actions inside the workspace and to approved registries (`github.com`, `npmjs.org`, `pypi.org`) run autonomously without constant prompts, reserving user interruptions only for boundary violations.

---

## 2. Architecture & Design

```
                                  ┌───────────────────────────────┐
                                  │      Pi Coding Agent          │
                                  │   (LLM Turns, Tools & TUI)    │
                                  └──────────────┬────────────────┘
                                                 │
                   ┌─────────────────────────────┴─────────────────────────────┐
                   ▼                                                           ▼
     ┌───────────────────────────┐                               ┌───────────────────────────┐
     │  In-Process Policy Guard  │                               │    Sandboxed Bash Tool    │
     │     (pi.on("tool_call")   │                               │ & user_bash (! commands)  │
     └─────────────┬─────────────┘                               └─────────────┬─────────────┘
                   │                                                           │
        ┌──────────┴──────────┐                                                ▼
        │ Path Canonicalizer  │                                  ┌───────────────────────────┐
        │ & Secret Matcher    │                                  │     Bubblewrap Engine     │
        └──────────┬──────────┘                                  │          (bwrap)          │
                   │                                             └─────────────┬─────────────┘
        [Block / Allow / Prompt]                                               │
                   │                                             ┌─────────────┴─────────────┐
                   ▼                                             │ --ro-bind / /             │
             [Host Filesystem]                                   │ --bind $CWD $CWD          │
                                                                 │ --tmpfs /tmp              │
                                                                 │ --tmpfs ~/.ssh (mask)     │
                                                                 │ --unshare-net             │
                                                                 └─────────────┬─────────────┘
                                                                               │
                                                                               ▼ (Unix Domain Socket)
                                                                 ┌───────────────────────────┐
                                                                 │  Domain-Filtering Proxy   │
                                                                 │  (HTTP CONNECT & SOCKS5)  │
                                                                 └─────────────┬─────────────┘
                                                                               │
                                                                 ┌─────────────┴─────────────┐
                                                                 │ Match against             │
                                                                 │ allowedDomains list       │
                                                                 └─────────────┬─────────────┘
                                                                               │
                                                        ┌──────────────────────┴──────────────────────┐
                                                        ▼                                             ▼
                                                [Allowed Domain]                               [Unknown Domain]
                                                        │                                             │
                                                        ▼                                             ▼
                                                [Direct Connection]                          [Interactive UI Prompt]
                                                                                             (Session / Project / Deny)
```

### Key Differences & Improvements over Existing Implementations:
- **Zero Third-Party Binary Wrappers**: Directly drives native Linux `bwrap` with predictable argument construction.
- **Dual-Layer Coverage**: Protects both Node.js in-process file tools (`read`, `write`, `edit`) and subprocess tools (`bash`, `user_bash`).
- **In-Memory Unix Socket Proxy**: Implements pure Node.js HTTP CONNECT and SOCKS5 proxy listeners bound to a secure Unix socket in `/run/user/<uid>` or a secure `/tmp` directory with `0700` permissions.
- **Fail-Safe Defaults**: If `bwrap` or the proxy fails to initialize, dangerous execution is blocked rather than silently falling back to unrestricted host execution.

---

## 3. Directory Layout & Module Responsibilities

```
extensions/claudelike-pisandbox/
├── package.json
├── tsconfig.json
├── README.md
├── plan.md                       # This architectural implementation plan
├── CHECKLIST.md                  # Granular task checklist for milestone tracking
├── index.ts                      # Extension entry point, lifecycle events & commands
├── config.default.json           # Default configuration template
├── src/
│   ├── config.ts                 # Configuration loader (global + project-local merge)
│   ├── policy.ts                 # Canonicalization, path globbing & secret detection
│   ├── bwrap.ts                  # Bubblewrap argument builder & process runner
│   ├── proxy/
│   │   ├── domain-matcher.ts     # Domain matching (*.github.com, glob rules)
│   │   ├── http-proxy.ts         # HTTP / HTTPS CONNECT proxy over Unix socket
│   │   ├── socks5-proxy.ts       # SOCKS5 proxy over Unix socket (for git, curl, ssh)
│   │   └── proxy-server.ts       # Unified proxy lifecycle manager
│   ├── bash-operations.ts        # Custom BashOperations implementation for pi
│   ├── tool-guard.ts             # pi.on("tool_call") guard for read/write/edit
│   └── ui.ts                     # TUI confirmation dialogs & status reporting
└── test/
    ├── policy.test.ts            # Unit tests for path canonicalization & secrets
    ├── domain-matcher.test.ts    # Unit tests for domain whitelisting
    ├── bwrap.test.ts             # Functional tests verifying bwrap isolation
    └── proxy.test.ts             # Functional tests for Unix socket proxying
```

---

## 4. Granular Component Specifications

### 4.1 Configuration Management (`src/config.ts`)
- Config locations:
  - Global: `~/.pi/agent/sandbox.json`
  - Project-local: `<cwd>/.pi/sandbox.json`
- Merging Strategy:
  - Project-local takes precedence over Global; Global takes precedence over Default.
  - Whitelist arrays (`allowedDomains`, `allowWrite`, `allowRead`) are unioned for seamless ergonomics while maintaining strictness.
- Schema:
  ```json
  {
    "enabled": true,
    "network": {
      "enabled": true,
      "allowedDomains": [
        "github.com",
        "*.github.com",
        "*.npmjs.org",
        "registry.npmjs.org",
        "pypi.org",
        "*.pypi.org"
      ],
      "deniedDomains": []
    },
    "filesystem": {
      "denyRead": [
        "~/.ssh",
        "~/.aws",
        "~/.gnupg",
        "~/.config/gh",
        "~/.netrc"
      ],
      "allowWrite": [
        ".",
        "/tmp"
      ],
      "denyWrite": [
        ".env",
        ".env.*",
        "*.pem",
        "*.key",
        "id_rsa*",
        "id_ed25519*"
      ]
    }
  }
  ```

### 4.2 In-Process Policy Guard (`src/tool-guard.ts` & `src/policy.ts`)
- Hooks `pi.on("tool_call")`:
  - When `event.toolName` is `read`, `write`, or `edit`:
    - Canonicalize target paths using `realpathSync.native` (traversal-safe, resolves symlinks).
    - Check against `denyRead` / `denyWrite` patterns.
    - If targeting a secret file, immediately return `{ block: true, reason: "Access denied by security sandbox policy: sensitive secret path." }`.
    - If writing outside `allowWrite` (`cwd` or `/tmp`), trigger UI prompt or block immediately if unattended.
- Fast fail-safe: All unknown or unresolved symlink paths outside the tree are rejected.

### 4.3 Bubblewrap Subprocess Engine (`src/bwrap.ts`)
- Invocation parameters:
  ```bash
  bwrap \
    --ro-bind / / \
    --dev /dev \
    --proc /proc \
    --tmpfs /tmp \
    --bind "$CWD" "$CWD" \
    --tmpfs "$HOME/.ssh" \
    --tmpfs "$HOME/.aws" \
    --tmpfs "$HOME/.gnupg" \
    --tmpfs "$HOME/.config/gh" \
    --unshare-net \
    --bind "$SOCKET_DIR" "/run/pi-sandbox" \
    --setenv HTTP_PROXY "http://localhost:8080" \
    --setenv HTTPS_PROXY "http://localhost:8080" \
    --setenv ALL_PROXY "socks5://localhost:1080" \
    -- "$SHELL" -c "$COMMAND"
  ```
- **Socket Bridging inside Sandbox**:
  - Connects inside the network namespace to `/run/pi-sandbox/proxy.sock` via a small background forwarder or transparent wrapper.
- **Process Group Isolation**:
  - Spawns with `detached: true`.
  - On timeout or `signal.abort`, executes `process.kill(-child.pid, "SIGKILL")`.

### 4.4 Local Domain-Filtering Proxy (`src/proxy/*`)
- Listens on a local Unix socket or loopback port.
- **HTTP/HTTPS CONNECT Handler**:
  - Parses the `CONNECT host:port` or HTTP request headers.
  - Checks `host` against `allowedDomains`.
  - If allowed: tunnels traffic directly to the destination.
  - If unlisted: suspends socket, asks user via Pi TUI, and either connects or terminates the client socket with HTTP 403 Forbidden.
- **SOCKS5 Handler**:
  - Intercepts SOCKS5 handshakes (command `0x01` CONNECT).
  - Evaluates domain or IPv4/IPv6 destination.
  - Rejects unauthorized destinations gracefully with `0x02` (connection not allowed by ruleset).

### 4.5 Interactive TUI & UX Integration (`src/ui.ts` & `index.ts`)
- Uses `ctx.ui.select` or `ctx.ui.custom` to display clean, non-intrusive permission prompts:
  ```
  🔒 Sandbox Security Alert
  Subprocess requested connection to: api.stripe.com:443
  
  [1] Allow for this session
  [2] Allow and save to project .pi/sandbox.json
  [3] Allow and save globally (~/.pi/agent/sandbox.json)
  [4] Deny connection (Abort)
  ```
- Status bar display:
  - `ctx.ui.setStatus("sandbox", "🔒 Sandbox Active [cwd protected]")`
- Slash commands:
  - `/sandbox` — displays active policies, whitelisted domains, and session allowances.
  - `/sandbox-toggle` — allows authorized operator toggle.

---

## 5. Phased Execution Roadmap

1. **Phase 1: Project Foundation & Security Policy Engine**
   - Implement configuration loader (`src/config.ts`).
   - Implement canonical path resolution, secret matchers, and pattern matchers (`src/policy.ts`).
   - Write comprehensive unit tests for traversal evasion (`../../`), symlink escapes, and secret regexes (`test/policy.test.ts`).

2. **Phase 2: In-Process Tool Interception**
   - Implement `tool-guard.ts` hooked to `pi.on("tool_call")`.
   - Protect built-in `read`, `write`, `edit` against secret and path leakage.
   - Verify that model file operations outside `cwd` are blocked or prompted.

3. **Phase 3: Bubblewrap OS Containment Engine**
   - Implement `bwrap.ts` argument generator and process spawner.
   - Implement `bash-operations.ts` conforming to Pi's `BashOperations` interface.
   - Replace built-in `bash` tool via `createBashTool` and handle `user_bash` hook for `!` shell commands.
   - Add process group killing on abort and timeout.

4. **Phase 4: Network Isolation & Domain-Filtering Proxy**
   - Implement domain matching logic (`domain-matcher.ts`).
   - Implement Unix socket HTTP CONNECT and SOCKS5 proxy server.
   - Wire proxy to `bwrap` network namespace via `--unshare-net`.
   - Implement user permission prompts via Pi UI when unlisted domains are encountered.

5. **Phase 5: CLI Commands, Status Indicators & Full End-to-End Verification**
   - Register `/sandbox`, `/sandbox status`, and status bar widget.
   - Run end-to-end security test suite:
     - Test arbitrary command execution blocking outside `cwd`.
     - Test exfiltration attempt via `curl` to unauthorized host.
     - Test reading `.env` and `~/.ssh`.
     - Test write containment (`rm -rf /` or `/etc` write denial).
