# claudelike-pisandbox

A dual-layer security sandboxing extension for the [pi coding agent harness](https://pi.dev/), inspired by Anthropic's Claude Code sandboxing architecture.

---

## Threat Model & Core Security Boundaries

Pi is an autonomous coding agent with broad capabilities. By default, tool calls run with the permissions of the local user account. `claudelike-pisandbox` protects the host machine against prompt injection, malicious supply-chain dependencies, and rogue code through four synchronized layers:

1. **In-Process Node Tool Guard (`src/tool-guard.ts`, `src/policy.ts`)**:
   - Guards all built-in filesystem tools (`read`, `write`, `edit`, `grep`, `find`, `ls`).
   - Uses `realpathSync.native` to eliminate directory traversal (`../../`) and symlink escapes.
   - Strictly denies access to credentials and secrets (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `.env*`, `*.pem`, `*.key`).
   - Prevents self-modification by blocking writes to `.pi/sandbox.json` and `.pi/settings.json`.
   - Fails closed in non-interactive/headless environments when user approval is required.
   - Emits structured, sanitized security audit logs to `stderr` on any block or prompt.

2. **Kernel-Level OS Subprocess Isolation (`src/bwrap.ts`, `src/bash-operations.ts`)**:
   - Spawns all bash commands and interactive `!` shell commands inside Linux `bubblewrap` (`bwrap`).
   - **Root Read-Only (`--ro-bind / /`)**: Host binaries and configuration files are immutable.
   - **Workspace Bounded (`--bind $CWD $CWD`)**: Writes are confined to the current project and ephemeral RAM-capped `/tmp`.
   - **Secret Shadowing**: Empty `tmpfs` mounts conceal `~/.ssh`, `~/.aws`, `~/.gnupg`, and host IPC sockets (`/run`).
   - **Persistence Protection**: Remounts read-only over `.git/hooks`, `.git/config`, `.pi/`, and `.vscode/tasks.json` to prevent malicious pre-commit hook planting (with full support for Git worktrees and submodules).
   - **Environment Scrubbing (`--clearenv`)**: Host credentials like `GITHUB_TOKEN` and `AWS_SECRET_ACCESS_KEY` are scrubbed before container startup.
   - **Process Isolation (`--new-session`, `--unshare-pid`)**: Prevents `TIOCSTI` terminal injection attacks and terminates orphaned child processes via process-group `SIGKILL`.

3. **Network Isolation & Domain-Filtering Proxy (`src/proxy/`)**:
   - Isolates the network namespace (`--unshare-net`).
   - Mounts an IPC Unix domain socket into the container (`/run/pi-sandbox/proxy.sock`).
   - Container tools (`curl`, `git`, `npm`) connect seamlessly via a transparent in-container loopback bridge.
   - Enforces an `allowedDomains` whitelist with strict SSRF defense (blocking `127.0.0.0/8`, `169.254.169.254`, private RFC1918 subnets, and obfuscated numeric/hex IP addresses).
   - Restricts outbound traffic strictly to web ports (80 and 443).
   - Prompts the operator via interactive TUI for unlisted domains.

4. **Operator UX & Lifecycle Integration (`index.ts`, `src/ui.ts`)**:
   - Status bar widget indicator: `🔒 Sandbox Active`.
   - Slash command `/sandbox`: Displays current policy, allowed domains, and session grants.
   - Slash command `/sandbox-toggle`: Operator toggle for session sandboxing.
   - Interactive permission prompts with sanitized titles to prevent ANSI terminal corruption.

---

## Configuration

Settings follow a strict trust hierarchy:
1. **Built-in Security Baseline**: Mandatory invariants (`MANDATORY_INVARIANTS`) that cannot be bypassed.
2. **Global User Config (`~/.pi/agent/sandbox.json`)**: Configured by the machine owner; defines allowed domains and custom write paths.
3. **Project-Local Config (`<cwd>/.pi/sandbox.json`)**: Treated as untrusted; can **only tighten** policies (add deny rules). Project-level attempts to disable the sandbox or grant access to sensitive secrets are automatically rejected.

### Example Configuration:

```json
{
  "enabled": true,
  "network": {
    "enabled": true,
    "allowedDomains": [
      "github.com",
      "*.github.com",
      "registry.npmjs.org",
      "pypi.org"
    ],
    "deniedDomains": [
      "malicious-site.com"
    ]
  },
  "filesystem": {
    "allowRead": [
      "/opt/shared-docs"
    ],
    "denyRead": [
      "~/.ssh",
      "~/.aws",
      "/etc/shadow"
    ],
    "allowWrite": [
      ".",
      "/tmp"
    ],
    "denyWrite": [
      ".env",
      ".env.*",
      "*.pem",
      "*.key"
    ]
  }
}
```

---

## Testing & Verification

Run the comprehensive unit, adversarial, and functional container test suite:

```bash
bun test
bun run typecheck
```
