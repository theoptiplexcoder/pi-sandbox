import { existsSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, resolve } from "node:path";
import { expandTilde } from "./config.ts";

/**
 * Resolves symlinks and normalizes paths using native realpath where possible.
 * If the file or parent does not exist yet (e.g. pending write), resolves existing
 * ancestor chain and appends remaining non-existent components to defeat path traversal.
 */
export function canonicalizePath(filePath: string, baseCwd: string = process.cwd()): string {
  const expanded = expandTilde(filePath);
  const absolutePath = isAbsolute(expanded) ? resolve(expanded) : resolve(baseCwd, expanded);

  try {
    return realpathSync.native(absolutePath);
  } catch {
    // If the path does not exist, probe upwards to resolve symlinked parent directories
    const tail: string[] = [];
    let probe = absolutePath;
    while (!existsSync(probe)) {
      const parent = dirname(probe);
      if (parent === probe) {
        return absolutePath;
      }
      tail.unshift(basename(probe));
      probe = parent;
    }

    try {
      return resolve(realpathSync.native(probe), ...tail);
    } catch {
      return absolutePath;
    }
  }
}

/**
 * Checks if a given file path matches any pattern in the list.
 * Supports:
 * - Direct paths / exact matches (e.g. "/etc/shadow", "~/.ssh")
 * - Directory prefixes (e.g. "~/.ssh" matches "~/.ssh/id_rsa")
 * - Glob wildcards (e.g. "*.pem", ".env*", "id_rsa*")
 */
export function matchesPattern(
  filePath: string,
  patterns: string[],
  baseCwd: string = process.cwd(),
): boolean {
  if (!patterns || patterns.length === 0) return false;

  const targetCanonical = canonicalizePath(filePath, baseCwd);
  const targetBaseName = basename(targetCanonical);

  for (const rawPattern of patterns) {
    if (!rawPattern) continue;

    // 1. Filename glob check (e.g., "*.pem", ".env*", "id_rsa*")
    if (rawPattern.includes("*") && !rawPattern.includes("/") && !rawPattern.includes("\\")) {
      const globRegex = new RegExp(
        "^" + rawPattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$",
      );
      if (globRegex.test(targetBaseName)) {
        return true;
      }
      continue;
    }

    // 2. Path-based glob check (e.g., "/var/log/*.log" or ".env.*")
    if (rawPattern.includes("*")) {
      const expandedPattern = expandTilde(rawPattern);
      const absPattern = isAbsolute(expandedPattern)
        ? resolve(expandedPattern)
        : resolve(baseCwd, expandedPattern);

      const patternRegex = new RegExp(
        "^" + absPattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$",
      );
      if (patternRegex.test(targetCanonical)) {
        return true;
      }
      continue;
    }

    // 3. Exact path or directory prefix check
    const patternCanonical = canonicalizePath(rawPattern, baseCwd);
    if (targetCanonical === patternCanonical) {
      return true;
    }

    const separator = patternCanonical.endsWith("/") ? "" : "/";
    if (targetCanonical.startsWith(patternCanonical + separator)) {
      return true;
    }
  }

  return false;
}

/**
 * High-risk secret patterns that should always be shielded.
 */
export const DEFAULT_SECRET_PATTERNS = [
  "~/.ssh",
  "~/.ssh/*",
  "~/.aws",
  "~/.aws/*",
  "~/.gnupg",
  "~/.gnupg/*",
  "~/.config/gh",
  "~/.config/gh/*",
  "~/.netrc",
  "/etc/shadow",
  "/etc/sudoers",
  ".env",
  ".env.*",
  "*.pem",
  "*.key",
  "id_rsa*",
  "id_ed25519*",
  "id_ecdsa*",
];

/**
 * Checks whether a path points to a sensitive host secret.
 */
export function isSecretPath(
  filePath: string,
  extraPatterns: string[] = [],
  baseCwd: string = process.cwd(),
): boolean {
  const allPatterns = [...DEFAULT_SECRET_PATTERNS, ...extraPatterns];
  return matchesPattern(filePath, allPatterns, baseCwd);
}

export type FilePolicyDecision = "allow" | "deny" | "prompt";

/**
 * Decides whether a read operation should be allowed, denied, or prompted.
 */
export function decideReadPolicy(
  filePath: string,
  allowRead: string[] = [],
  denyRead: string[] = [],
  baseCwd: string = process.cwd(),
): FilePolicyDecision {
  // 1. Explicit deny or secret check
  if (matchesPattern(filePath, denyRead, baseCwd) || isSecretPath(filePath, denyRead, baseCwd)) {
    return "deny";
  }

  // 2. Explicit allowRead overrides
  if (allowRead.length > 0 && matchesPattern(filePath, allowRead, baseCwd)) {
    return "allow";
  }

  // 3. Current working directory is always allowed to read
  const canonicalTarget = canonicalizePath(filePath, baseCwd);
  const canonicalCwd = canonicalizePath(baseCwd, baseCwd);
  if (
    canonicalTarget === canonicalCwd ||
    canonicalTarget.startsWith(canonicalCwd.endsWith("/") ? canonicalCwd : canonicalCwd + "/")
  ) {
    return "allow";
  }

  // 4. Safe public system paths needed for tooling (node_modules, /tmp, etc.)
  const canonicalTmp = canonicalizePath("/tmp", baseCwd);
  if (
    canonicalTarget === canonicalTmp ||
    canonicalTarget.startsWith(canonicalTmp.endsWith("/") ? canonicalTmp : canonicalTmp + "/")
  ) {
    return "allow";
  }

  return "allow"; // Reads to general system utilities are permitted unless in denyRead
}

/**
 * Decides whether a write operation should be allowed, denied, or prompted.
 */
export function decideWritePolicy(
  filePath: string,
  allowWrite: string[] = [".", "/tmp"],
  denyWrite: string[] = [],
  baseCwd: string = process.cwd(),
): FilePolicyDecision {
  // 1. Explicit deny or secret pattern check
  if (matchesPattern(filePath, denyWrite, baseCwd) || isSecretPath(filePath, denyWrite, baseCwd)) {
    return "deny";
  }

  // 2. Must match allowWrite patterns (e.g. "." or "/tmp" or explicit absolute paths)
  if (allowWrite.length > 0 && matchesPattern(filePath, allowWrite, baseCwd)) {
    return "allow";
  }

  // 3. Otherwise requires permission prompt
  return "prompt";
}
