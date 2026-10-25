import { existsSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { expandTilde, MANDATORY_INVARIANTS, type SandboxConfig } from "./config.ts";
import { isSecretPath } from "./policy.ts";

export interface BwrapOptions {
  cwd: string;
  config: SandboxConfig;
  unshareNet?: boolean;
  socketDir?: string;
  proxyPort?: number;
  socksPort?: number;
}

/**
 * Checks whether bubblewrap ('bwrap') is installed and accessible on the host system.
 */
export function isBwrapAvailable(): boolean {
  return existsSync("/usr/bin/bwrap") || existsSync("/bin/bwrap");
}

/**
 * Recursively scans the project workspace up to maxDepth (default 8) to locate
 * all nested secret files matching denyWrite patterns (e.g. backend/.env, certs/*.key).
 * Skips node_modules to avoid performance penalties, but inspects standard project trees.
 */
export function findNestedSecretsInWorkspace(
  dir: string,
  extraDenyPatterns: readonly string[] = [],
  maxDepth: number = 8,
  currentDepth: number = 0,
): string[] {
  const matches: string[] = [];
  if (!existsSync(dir) || currentDepth > maxDepth) return matches;

  try {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);

      if (entry.isDirectory()) {
        // Skip node_modules, .git (handled separately for security), .pnpm-store
        if (entry.name === "node_modules" || entry.name === ".pnpm-store" || entry.name === ".git") {
          continue;
        }
        matches.push(
          ...findNestedSecretsInWorkspace(fullPath, extraDenyPatterns, maxDepth, currentDepth + 1),
        );
      } else if (entry.isFile()) {
        // Check using single source of truth: isSecretPath
        if (isSecretPath(fullPath, extraDenyPatterns as string[], dir)) {
          matches.push(fullPath);
        }
      }
    }
  } catch (err) {
    // If a directory is unreadable or inaccessible, warn loud
    console.error(`[claudelike-pisandbox] Warning: Unreadable directory in workspace: ${dir}:`, err);
  }

  return matches;
}

/**
 * Whitelist of safe environment variables forwarded to the container.
 * Everything else (including AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, OPENAI_API_KEY, SSH_AUTH_SOCK)
 * is stripped via --clearenv to prevent environment leakage.
 */
export const SAFE_ENV_VARS = [
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "SHELL",
  "TERM",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TZ",
  "NODE_ENV",
];

/**
 * Builds the bubblewrap CLI arguments implementing OS-level kernel isolation.
 *
 * Hardened Security Features:
 * 1. Root Read-Only (--ro-bind / /): System binaries/libs are readable, but cannot be modified.
 * 2. Pseudo Filesystems: Fresh /dev and /proc mounts.
 * 3. Ephemeral /tmp (--tmpfs /tmp): Isolated temporary storage that vanishes on exit.
 * 4. Mask Sockets & Daemons (--tmpfs /run): Hides /run/user, /var/run/docker.sock, and SSH agent sockets.
 * 5. Environment Cleared (--clearenv): Only explicitly whitelisted environment variables are forwarded.
 * 6. Process Isolation (--new-session, --unshare-pid): Defeats TIOCSTI terminal injection and cleans setsid children.
 * 7. Host Secrets Shadowed (--tmpfs ~/.ssh, ~/.aws, etc.): Empty tmpfs over sensitive credential stores.
 * 8. Writable Workspace strictly bounded (--bind $CWD $CWD).
 * 9. Execution Hooks & Persistence Protected: Remounts read-only over .git/hooks, .git/config, .pi, and .vscode.
 * 10. Nested Secret Masking: Recursively finds all .env, *.key, and secret files inside $CWD (e.g. backend/.env)
 *     and remounts them read-only (--ro-bind).
 * 11. Network Namespace Isolation (--unshare-net): Blocks raw network egress.
 */
export function buildBwrapArgs(options: BwrapOptions): string[] {
  const { cwd, config, unshareNet, socketDir } = options;
  const args: string[] = [];

  // 1. Process & Terminal Isolation (Defeats TIOCSTI keystroke injection & orphans)
  args.push("--new-session");
  args.push("--unshare-pid");
  args.push("--die-with-parent");

  // 2. Root filesystem read-only
  args.push("--ro-bind", "/", "/");

  // 3. Kernel pseudo filesystems
  args.push("--dev", "/dev");
  args.push("--proc", "/proc");

  // 4. Ephemeral /tmp
  args.push("--tmpfs", "/tmp");

  // 5. Mask host IPC sockets, Docker daemon, and user runtimes
  args.push("--tmpfs", "/run");

  // 6. Bind writable workspace directory
  const resolvedCwd = resolve(cwd);
  args.push("--bind", resolvedCwd, resolvedCwd);

  // 7. Additional allowed write paths (from trusted config only)
  const allowWrite = config.filesystem?.allowWrite ?? [];
  for (const p of allowWrite) {
    if (p === "." || p === "./") continue;
    const absPath = resolve(cwd, expandTilde(p));
    if (absPath !== resolvedCwd && absPath !== "/tmp" && existsSync(absPath)) {
      args.push("--bind", absPath, absPath);
    }
  }

  // 8. Mask host secrets with empty tmpfs mounts
  const secretsToMask = new Set<string>();

  const allDenyPatterns = [
    ...MANDATORY_INVARIANTS.denyRead,
    ...(config.filesystem?.denyRead ?? []),
  ];

  for (const pattern of allDenyPatterns) {
    if (!pattern.includes("*")) {
      const absPath = resolve(cwd, expandTilde(pattern));
      if (existsSync(absPath)) {
        secretsToMask.add(absPath);
      }
    } else if (pattern.endsWith("/**")) {
      const baseDir = resolve(cwd, expandTilde(pattern.slice(0, -3)));
      if (existsSync(baseDir)) {
        secretsToMask.add(baseDir);
      }
    }
  }

  for (const secretPath of secretsToMask) {
    try {
      const stat = statSync(secretPath);
      if (stat.isDirectory()) {
        args.push("--tmpfs", secretPath);
      } else if (stat.isFile()) {
        args.push("--ro-bind", "/dev/null", secretPath);
      }
    } catch {
      // Ignore unresolvable paths
    }
  }

  // 9. Protect git persistence hooks, configs, and IDE execution settings inside $CWD
  const sensitiveCwdPaths = [
    join(resolvedCwd, ".git", "hooks"),
    join(resolvedCwd, ".git", "config"),
    join(resolvedCwd, ".pi"),
    join(resolvedCwd, ".vscode", "tasks.json"),
    join(resolvedCwd, ".envrc"),
  ];

  for (const p of sensitiveCwdPaths) {
    if (existsSync(p)) {
      args.push("--ro-bind", p, p);
    }
  }

  // 10. Nested workspace secret protection (e.g. backend/.env, api/certs/server.key)
  const nestedSecrets = findNestedSecretsInWorkspace(
    resolvedCwd,
    config.filesystem?.denyWrite ?? [],
  );
  for (const sec of nestedSecrets) {
    args.push("--ro-bind", sec, sec);
  }

  // 11. Environment Isolation: Clean environment and only forward safe vars
  args.push("--clearenv");
  for (const envKey of SAFE_ENV_VARS) {
    const val = process.env[envKey];
    if (val !== undefined) {
      args.push("--setenv", envKey, val);
    }
  }
  // Ensure HOME and CWD are properly initialized
  args.push("--setenv", "HOME", homedir());

  // 12. Network namespace containment
  const networkSandboxed = unshareNet ?? config.network?.enabled !== false;
  if (networkSandboxed) {
    args.push("--unshare-net");

    // Bind local socket directory if specified
    // In Phase 4, a local socat bridge forwards inside the sandbox to /run/pi-sandbox/proxy.sock
    if (socketDir && existsSync(socketDir)) {
      args.push("--bind", socketDir, "/run/pi-sandbox");
    }
  }

  // 13. Process execution directory
  args.push("--chdir", resolvedCwd);

  return args;
}
