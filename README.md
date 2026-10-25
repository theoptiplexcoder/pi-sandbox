# claudelike-pisandbox

A dual-layer security sandboxing extension for the [pi coding agent harness](https://pi.dev/), inspired by Anthropic's Claude Code sandboxing architecture.

## Overview

`claudelike-pisandbox` isolates commands and file operations executed by `pi`:

1. **In-Process Tool Guard (`src/tool-guard.ts`, `src/policy.ts`)**:
   - Intercepts Pi's direct Node.js tools (`read`, `write`, `edit`) using `pi.on("tool_call")`.
   - Prevents path traversal evasions (`../../`) using native symlink resolution (`realpathSync.native`).
   - Automatically denies access to host secrets (`.env`, `.env.*`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `*.pem`, `*.key`).
   - Prompts the user before writing outside project working boundaries.

2. **OS-Level Filesystem Containment (`src/bwrap.ts`, `src/bash-operations.ts`)**:
   - Isolates subprocess execution (`bash` tool calls and interactive `!` commands) using Linux `bubblewrap` (`bwrap`).
   - Mounts the host root filesystem read-only (`--ro-bind / /`).
   - Writable paths are strictly confined to the workspace root (`$CWD`) and ephemeral `/tmp`.
   - Sensitive directories (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`) are shadowed with empty tmpfs mounts.
   - Child processes run in isolated process groups and are immediately terminated on timeout or abort signal.

3. **Network Isolation & Domain Filtering Proxy (`src/proxy/`)**:
   - Enforces network namespace isolation (`--unshare-net`).
   - Routes outbound traffic through a local proxy server.
   - Enforces an `allowedDomains` whitelist (`github.com`, `registry.npmjs.org`, `pypi.org`, etc.).
   - Halts unlisted network requests and prompts the operator via Pi's interactive TUI (`src/ui.ts`).

4. **Slash Commands & TUI Status**:
   - Status indicator in Pi status bar (`🔒 Sandbox Active`).
   - `/sandbox`: Inspect current policies, allowed domains, and session allowances.
   - `/sandbox-toggle`: Temporarily enable or disable sandboxing during an active session.

---

## Configuration

The extension supports hierarchical configuration. Project-local settings override and extend global settings:

- **Global Config**: `~/.pi/agent/sandbox.json`
- **Project-Local Config**: `<cwd>/.pi/sandbox.json`

Example `<cwd>/.pi/sandbox.json`:

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
      "/opt/shared-tools"
    ],
    "denyRead": [
      "~/.ssh",
      "~/.aws",
      "/etc/shadow"
    ],
    "allowWrite": [
      ".",
      "/tmp",
      "/var/log/my-app"
    ],
    "denyWrite": [
      ".env",
      ".env.*",
      "*.key",
      "*.pem"
    ]
  }
}
```

---

## Testing & Verification

Run the test suite via Bun:

```bash
bun test
bun run typecheck
```
