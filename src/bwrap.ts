import { existsSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { expandTilde, MANDATORY_INVARIANTS, type SandboxConfig } from "./config.ts";
import { globToRegex } from "./policy.ts";

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
 * Scans a directory and finds any files matching denyWrite glob patterns (e.g. .env, *.pem, *.key).
 */
function findMatchingFilesInDir(dir: string, patterns: string[]): string[] {
  const matches: string[] = [];
  if (!existsSync(dir)) return matches;

  try {
    const entries = readdirSync(dir);
    for (const entry of entries) {
      for (const pat of patterns) {
        if (!pat.includes("/") && !pat.includes("\\")) {
          const regex = globToRegex(pat);
          if (regex.test(entry)) {
            matches.push(join(dir, entry));
            break;
          }
        }
      }
    }
  } catch {
    // Ignore unreadable directories
  }

  return matches;
}

/**
 * Builds the bubblewrap CLI arguments implementing OS-level kernel isolation.
 *
 * Security Model:
 * 1. Root Read-Only (--ro-bind / /): System binaries/libs are readable, but cannot be modified.
 * 2. Pseudo Filesystems: Mounts fresh /dev and /proc.
 * 3. Ephemeral /tmp (--tmpfs /tmp): Isolated temporary storage that vanishes on exit.
 * 4. Workspace Bound Read-Write (--bind $CWD $CWD): Confined to the target project directory.
 * 5. Secret Masking (--tmpfs ~/.ssh, etc.): Shadowing credential stores with empty tmpfs mounts.
 * 6. In-Workspace Secret Protection (--ro-bind): Existing .env / key files inside $CWD are remounted
 *    read-only so commands cannot overwrite or exfiltrate modified keys.
 * 7. Network Namespace Isolation (--unshare-net): Closes raw network egress.
 * 8. Process Lifetime (--die-with-parent): Kernel terminates container processes if the parent exits.
 */
export function buildBwrapArgs(options: BwrapOptions): string[] {
  const { cwd, config, unshareNet, socketDir, proxyPort, socksPort } = options;
  const args: string[] = [];

  // 1. Root filesystem read-only
  args.push("--ro-bind", "/", "/");

  // 2. Kernel pseudo filesystems
  args.push("--dev", "/dev");
  args.push("--proc", "/proc");

  // 3. Ephemeral /tmp
  args.push("--tmpfs", "/tmp");

  // 4. Bind writable workspace directory
  const resolvedCwd = resolve(cwd);
  args.push("--bind", resolvedCwd, resolvedCwd);

  // 5. Additional allowed write paths (from trusted config only)
  const allowWrite = config.filesystem?.allowWrite ?? [];
  for (const p of allowWrite) {
    if (p === "." || p === "./") continue;
    const absPath = resolve(cwd, expandTilde(p));
    if (absPath !== resolvedCwd && absPath !== "/tmp" && existsSync(absPath)) {
      args.push("--bind", absPath, absPath);
    }
  }

  // 6. Mask host secrets with empty tmpfs mounts
  // Includes mandatory invariants and any extra configured denyRead paths
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

  // 7. Protect sensitive files inside cwd by remounting them read-only
  const allDenyWritePatterns = [
    ...MANDATORY_INVARIANTS.denyWrite,
    ...(config.filesystem?.denyWrite ?? []),
  ];

  // A. Protect explicit non-wildcard files
  for (const p of allDenyWritePatterns) {
    if (!p.includes("*")) {
      const absPath = resolve(cwd, expandTilde(p));
      if (existsSync(absPath)) {
        args.push("--ro-bind", absPath, absPath);
      }
    }
  }

  // B. Scan workspace root for matching wildcard files (.env, *.pem, *.key)
  const wildcardPatterns = allDenyWritePatterns.filter((p) => p.includes("*"));
  const matchedWorkspaceSecrets = findMatchingFilesInDir(resolvedCwd, wildcardPatterns);
  for (const sec of matchedWorkspaceSecrets) {
    args.push("--ro-bind", sec, sec);
  }

  // 8. Network namespace containment
  const networkSandboxed = unshareNet ?? config.network?.enabled !== false;
  if (networkSandboxed) {
    args.push("--unshare-net");

    // Bind local socket directory if specified
    if (socketDir && existsSync(socketDir)) {
      args.push("--bind", socketDir, "/run/pi-sandbox");
    }

    // Set proxy environment variables if ports/sockets are specified
    if (proxyPort) {
      args.push("--setenv", "http_proxy", `http://127.0.0.1:${proxyPort}`);
      args.push("--setenv", "https_proxy", `http://127.0.0.1:${proxyPort}`);
      args.push("--setenv", "HTTP_PROXY", `http://127.0.0.1:${proxyPort}`);
      args.push("--setenv", "HTTPS_PROXY", `http://127.0.0.1:${proxyPort}`);
    }
    if (socksPort) {
      args.push("--setenv", "all_proxy", `socks5h://127.0.0.1:${socksPort}`);
      args.push("--setenv", "ALL_PROXY", `socks5h://127.0.0.1:${socksPort}`);
    }
  }

  // 9. Standard environment configuration
  args.push("--chdir", resolvedCwd);
  args.push("--die-with-parent");

  return args;
}
