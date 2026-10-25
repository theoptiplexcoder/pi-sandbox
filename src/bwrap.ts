import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { expandTilde, type SandboxConfig } from "./config.ts";

export interface BwrapOptions {
  cwd: string;
  config: SandboxConfig;
  unshareNet?: boolean;
  socketDir?: string;
  proxyPort?: number;
  socksPort?: number;
}

export function isBwrapAvailable(): boolean {
  return existsSync("/usr/bin/bwrap") || existsSync("/bin/bwrap");
}

/**
 * Builds the bubblewrap CLI arguments.
 */
export function buildBwrapArgs(options: BwrapOptions): string[] {
  const { cwd, config, unshareNet, socketDir } = options;
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

  // 5. Additional allowed write paths
  const allowWrite = config.filesystem?.allowWrite ?? [];
  for (const p of allowWrite) {
    if (p === "." || p === "./") continue;
    const absPath = resolve(cwd, expandTilde(p));
    if (absPath !== resolvedCwd && absPath !== "/tmp" && existsSync(absPath)) {
      args.push("--bind", absPath, absPath);
    }
  }

  // 6. Mask host secrets with empty tmpfs mounts
  const defaultSecretsToMask = [
    resolve(homedir(), ".ssh"),
    resolve(homedir(), ".aws"),
    resolve(homedir(), ".gnupg"),
    resolve(homedir(), ".config", "gh"),
    resolve(homedir(), ".netrc"),
  ];

  for (const secretPath of defaultSecretsToMask) {
    if (existsSync(secretPath)) {
      args.push("--tmpfs", secretPath);
    }
  }

  // Also mask any extra paths configured in denyRead
  const denyRead = config.filesystem?.denyRead ?? [];
  for (const p of denyRead) {
    const absPath = resolve(cwd, expandTilde(p));
    if (existsSync(absPath) && !defaultSecretsToMask.includes(absPath)) {
      args.push("--tmpfs", absPath);
    }
  }

  // 7. Protect denyWrite files inside cwd by remounting read-only if they exist
  const denyWrite = config.filesystem?.denyWrite ?? [];
  for (const p of denyWrite) {
    if (!p.includes("*")) {
      const absPath = resolve(cwd, expandTilde(p));
      if (existsSync(absPath)) {
        args.push("--ro-bind", absPath, absPath);
      }
    }
  }

  // 8. Network namespace containment
  if (unshareNet || config.network?.enabled !== false) {
    args.push("--unshare-net");

    // Bind local socket directory if specified
    if (socketDir && existsSync(socketDir)) {
      args.push("--bind", socketDir, "/run/pi-sandbox");
    }
  }

  // 9. Standard environment configuration
  args.push("--chdir", resolvedCwd);
  args.push("--die-with-parent");

  return args;
}
