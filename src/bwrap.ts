import { existsSync, mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
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
  tmpfsBytes?: number; // Cap tmpfs in RAM (default: 512MB)
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
    console.error(`[claudelike-pisandbox] Warning: Unreadable directory in workspace: ${dir}:`, err);
  }

  return matches;
}

/**
 * Resolves the real git directory for standard repositories, worktrees, and submodules.
 * - If .git is a directory: returns resolved .git path.
 * - If .git is a file (worktree/submodule): reads "gitdir: <path>" and resolves it.
 */
export function resolveGitDirectory(workspaceDir: string): string | null {
  const gitPath = join(workspaceDir, ".git");
  if (!existsSync(gitPath)) return null;

  try {
    const stat = statSync(gitPath);
    if (stat.isDirectory()) {
      return gitPath;
    } else if (stat.isFile()) {
      // Worktree / submodule pointer file: gitdir: ../../.git/worktrees/my-worktree
      const content = readFileSync(gitPath, "utf-8").trim();
      const match = /^gitdir:\s*(.+)$/m.exec(content);
      if (match && match[1]) {
        return resolve(workspaceDir, match[1]);
      }
    }
  } catch {
    // Ignore read errors
  }
  return null;
}

/**
 * Generates git protection mounts.
 * Ensures `.git/hooks` is pre-created on the host so an attacker cannot later `mkdir .git/hooks`
 * inside the sandbox to plant delayed execution hooks. Also mounts `.git/config` as read-only.
 */
export function buildGitProtectionMounts(workspaceDir: string): string[] {
  const mounts: string[] = [];
  const gitDir = resolveGitDirectory(workspaceDir);
  if (!gitDir) return mounts;

  try {
    // 1. Pre-create hooks dir on host so it can be mounted read-only without holes
    const hooksDir = join(gitDir, "hooks");
    if (!existsSync(hooksDir)) {
      mkdirSync(hooksDir, { recursive: true });
    }
    mounts.push("--ro-bind", hooksDir, hooksDir);

    // 2. Protect git config if it exists
    const configPath = join(gitDir, "config");
    if (existsSync(configPath)) {
      mounts.push("--ro-bind", configPath, configPath);
    }
  } catch {
    // Ignore git creation errors
  }

  return mounts;
}

/**
 * Strict allowlist of safe environment variables forwarded to the container.
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
  "GIT_AUTHOR_NAME",
  "GIT_AUTHOR_EMAIL",
  "GIT_COMMITTER_NAME",
  "GIT_COMMITTER_EMAIL",
];

/**
 * Builds the bubblewrap CLI arguments implementing OS-level kernel isolation.
 */
export function buildBwrapArgs(options: BwrapOptions): string[] {
  const { cwd, config, unshareNet, socketDir, tmpfsBytes = 536870912 } = options; // Default 512MB RAM cap
  const args: string[] = [];

  // 1. Process & Terminal Isolation (Defeats TIOCSTI keystroke injection & setsid orphans)
  args.push("--new-session");
  args.push("--unshare-pid");
  args.push("--die-with-parent");

  // 2. Root filesystem read-only
  args.push("--ro-bind", "/", "/");

  // 3. Kernel pseudo filesystems
  args.push("--dev", "/dev");
  args.push("--proc", "/proc");

  // 4. Ephemeral /tmp with RAM size limit
  args.push("--size", String(tmpfsBytes));
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

  // 9. Git Persistence & Execution Hook Protection (including worktree support)
  const gitMounts = buildGitProtectionMounts(resolvedCwd);
  args.push(...gitMounts);

  // Remount read-only over other project hook directories if present
  const sensitiveCwdPaths = [
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
  args.push("--setenv", "HOME", homedir());

  // 12. Network namespace containment
  const networkSandboxed = unshareNet ?? config.network?.enabled !== false;
  if (networkSandboxed) {
    args.push("--unshare-net");

    // Bind local socket directory if specified
    if (socketDir && existsSync(socketDir)) {
      args.push("--bind", socketDir, "/run/pi-sandbox");
    }
  }

  // 13. Process execution directory
  args.push("--chdir", resolvedCwd);

  return args;
}
