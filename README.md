# claudelike-pisandbox

A dual-layer security sandboxing extension for [pi](https://pi.dev/), inspired by Anthropic's Claude Code sandboxing architecture.

## Overview

`claudelike-pisandbox` isolates commands and file operations executed by `pi`:

1. **OS-Level Filesystem Containment (`bwrap`)**:
   - Isolates subprocess execution (`bash` tool calls and interactive `!` commands) using Linux `bubblewrap`.
   - Restricts writable paths strictly to the working directory (`cwd`) and ephemeral `/tmp`.
   - Protects host secrets (`~/.ssh`, `~/.gnupg`, `~/.aws`, `.env*`) by mounting empty read-only tmpfs or denying access.

2. **Network Egress Containment**:
   - Runs bash commands in an unshared network namespace (`--unshare-net`).
   - Routes outbound connections through a local proxy over Unix domain socket.
   - Enforces domain allowlists (`allowedDomains`) and blocks unauthorized exfiltration.

3. **In-Process Policy Guard**:
   - Hooks into `pi.on("tool_call")` to safeguard direct Node.js tool calls (`read`, `write`, `edit`).
   - Blocks unauthorized access to sensitive credential files or directories outside workspace boundaries.

4. **Interactive TUI Approvals**:
   - Integrates with `pi-tui` to prompt the operator for any unlisted domain or directory access.

## Architecture

```
                       ┌─────────────────────────┐
                       │       Pi Agent          │
                       │ (read, write, edit, !)  │
                       └────────────┬────────────┘
                                    │
                  ┌─────────────────┴─────────────────┐
                  ▼                                   ▼
      [In-Process Policy Guard]           [Sandboxed Bash Tool]
      - Canonicalizes paths                - bubblewrap namespace
      - Blocks ~/.ssh, .env*               - RO root, bind CWD
                                           - --unshare-net
                                                      │
                                                      ▼
                                           [Unix Domain Socket]
                                                      │
                                                      ▼
                                           [Domain Filter Proxy]
                                           - Matches allowedDomains
                                           - Interactive UI Prompt
```

## Requirements

- Linux with `bubblewrap` (`bwrap`) installed.
- `bun` or `node` (v20+).
- `pi` coding agent harness.

## Development

```bash
bun install
bun test
```
