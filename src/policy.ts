import { existsSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { expandTilde, MANDATORY_INVARIANTS } from "./config.ts";

/**
 * Checks if targetPath is strictly inside allowedRoot or is allowedRoot itself.
 * Uses path.relative() rather than fragile string-prefix checks to prevent
 * sibling directory confusion (e.g. /app/project-secret matching /app/project).
 *
 * @param allowedRoot Base directory.
 * @param targetPath Path to test.
 * @returns True if targetPath is contained within or equals allowedRoot.
 */
export function isPathContained(allowedRoot: string, targetPath: string): boolean {
  const normRoot = resolve(allowedRoot);
  const normTarget = resolve(targetPath);

  const rel = relative(normRoot, normTarget);

  return (
    rel === "" ||
    (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))
  );
}

/**
 * Resolves symlinks and normalizes paths using native realpath where possible.
 *
 * Security Considerations:
 * - Direct string manipulation (e.g. `path.normalize`) fails to catch symlink escapes
 *   where a symlink points outside the workspace (e.g. `repo/link -> /etc/shadow`).
 * - For files that do not exist yet (e.g. pending write operations), this function
 *   traverses upward to locate the nearest existing ancestor, resolves its realpath,
 *   and appends remaining non-existent components, defeating directory traversal (`../../`).
 *
 * Note: While canonicalizePath defeats static symlink escapes, Phase 3 (bwrap kernel mounts)
 * provides the ultimate protection against concurrent TOCTOU symlink races.
 *
 * @param filePath Path to resolve and canonicalize.
 * @param baseCwd Working directory to resolve relative paths against.
 * @returns Canonicalized absolute path string.
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
 * Converts a standard file glob pattern into a strict regular expression.
 *
 * Glob Semantics Enforced:
 * - `*` matches any characters EXCEPT directory separator (`/`).
 * - `**` matches any characters INCLUDING directory separator (`/`).
 * - `?` matches a single character except `/`.
 * - All other regex meta-characters are escaped.
 *
 * @param glob Pattern string.
 * @returns RegExp with strict path semantics.
 */
export function globToRegex(glob: string): RegExp {
  let regexStr = "";
  let i = 0;

  while (i < glob.length) {
    const char = glob[i];

    if (char === "*") {
      if (glob[i + 1] === "*") {
        // Recursive wildcard: '**'
        if (glob[i + 2] === "/") {
          regexStr += "(?:.*\\/)?";
          i += 3;
        } else {
          regexStr += ".*";
          i += 2;
        }
      } else {
        // Single component wildcard: '*'
        regexStr += "[^/]*";
        i++;
      }
    } else if (char === "?") {
      regexStr += "[^/]";
      i++;
    } else if (
      char === "." ||
      char === "+" ||
      char === "^" ||
      char === "$" ||
      char === "(" ||
      char === ")" ||
      char === "[" ||
      char === "]" ||
      char === "{" ||
      char === "}" ||
      char === "|" ||
      char === "\\"
    ) {
      regexStr += "\\" + char;
      i++;
    } else {
      regexStr += char;
      i++;
    }
  }

  return new RegExp(`^${regexStr}$`);
}

/**
 * Checks if a given file path matches any pattern in the list.
 *
 * Supports three matching tiers:
 * 1. Filename glob check (e.g. "*.pem", ".env*", "id_rsa*") evaluated against basename.
 * 2. Path-based glob check (e.g. "/var/log/*.log" or "path-glob") evaluated against canonical path.
 * 3. Exact path or directory containment check (e.g. "~/.ssh" contains "~/.ssh/id_rsa").
 *
 * @param filePath Target path to test.
 * @param patterns Array of pattern strings.
 * @param baseCwd Working directory for relative pattern resolution.
 * @returns True if target path matches at least one pattern.
 */
export function matchesPattern(
  filePath: string,
  patterns: readonly string[] | string[],
  baseCwd: string = process.cwd(),
): boolean {
  if (!patterns || patterns.length === 0) return false;

  const targetCanonical = canonicalizePath(filePath, baseCwd);
  const targetBaseName = basename(targetCanonical);

  for (const rawPattern of patterns) {
    if (!rawPattern) continue;

    // 1. Filename-only glob check (no path separators)
    if (rawPattern.includes("*") && !rawPattern.includes("/") && !rawPattern.includes("\\")) {
      const regex = globToRegex(rawPattern);
      if (regex.test(targetBaseName)) {
        return true;
      }
      continue;
    }

    // 2. Path-based glob check (contains '*' and '/')
    if (rawPattern.includes("*")) {
      const expandedPattern = expandTilde(rawPattern);
      const absPattern = isAbsolute(expandedPattern)
        ? resolve(expandedPattern)
        : resolve(baseCwd, expandedPattern);

      const regex = globToRegex(absPattern);
      if (regex.test(targetCanonical)) {
        return true;
      }
      continue;
    }

    // 3. Exact path or directory containment check (using isPathContained)
    const patternCanonical = canonicalizePath(rawPattern, baseCwd);
    if (targetCanonical === patternCanonical) {
      return true;
    }

    if (isPathContained(patternCanonical, targetCanonical)) {
      return true;
    }
  }

  return false;
}

/**
 * Built-in high-risk secret patterns derived from mandatory invariants.
 */
export const DEFAULT_SECRET_PATTERNS: readonly string[] = Object.freeze([
  ...MANDATORY_INVARIANTS.denyRead,
  ...MANDATORY_INVARIANTS.denyWrite,
]);

/**
 * Evaluates whether a path points to a sensitive host secret or credential store.
 *
 * @param filePath Path to evaluate.
 * @param extraPatterns Optional additional secret patterns.
 * @param baseCwd Working directory for relative pattern resolution.
 * @returns True if path matches any secret pattern.
 */
export function isSecretPath(
  filePath: string,
  extraPatterns: readonly string[] | string[] = [],
  baseCwd: string = process.cwd(),
): boolean {
  const allPatterns = [...DEFAULT_SECRET_PATTERNS, ...extraPatterns];
  return matchesPattern(filePath, allPatterns, baseCwd);
}

/**
 * Decision states returned by policy checks.
 * - "allow": Operation permitted without user interruption.
 * - "deny": Operation blocked immediately (security violation).
 * - "prompt": Operation requires explicit user approval via TUI.
 */
export type FilePolicyDecision = "allow" | "deny" | "prompt";

/**
 * Decides whether a file READ operation should be allowed, denied, or prompted.
 *
 * Rules:
 * 1. Deny if in denyRead or matches isSecretPath.
 * 2. Allow if in explicit allowRead.
 * 3. Allow if inside working directory (cwd) or /tmp.
 * 4. General system reads allowed unless matching denyRead.
 *
 * @param filePath Path being read.
 * @param allowRead Custom read allowances.
 * @param denyRead Forbidden read paths.
 * @param baseCwd Workspace directory.
 * @returns FilePolicyDecision
 */
export function decideReadPolicy(
  filePath: string,
  allowRead: readonly string[] | string[] = [],
  denyRead: readonly string[] | string[] = [],
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
  if (isPathContained(canonicalCwd, canonicalTarget)) {
    return "allow";
  }

  // 4. Safe public system paths needed for tooling (node_modules, /tmp, etc.)
  const canonicalTmp = canonicalizePath("/tmp", baseCwd);
  if (isPathContained(canonicalTmp, canonicalTarget)) {
    return "allow";
  }

  return "allow"; // Reads to general system binaries/libs are permitted unless in denyRead
}

/**
 * Decides whether a file WRITE or EDIT operation should be allowed, denied, or prompted.
 *
 * Rules:
 * 1. Deny if in denyWrite or matches isSecretPath (e.g. .env, *.key, .pi/sandbox.json).
 * 2. Allow if within allowWrite boundaries (default: ['.', '/tmp'] or custom paths).
 * 3. Prompt if writing outside allowed boundaries (e.g. /etc/, ~/.bashrc, sibling projects).
 *
 * @param filePath Path being written/edited.
 * @param allowWrite Allowed write boundaries.
 * @param denyWrite Forbidden write targets.
 * @param baseCwd Workspace directory.
 * @returns FilePolicyDecision
 */
export function decideWritePolicy(
  filePath: string,
  allowWrite: readonly string[] | string[] = [".", "/tmp"],
  denyWrite: readonly string[] | string[] = [],
  baseCwd: string = process.cwd(),
): FilePolicyDecision {
  // 1. Explicit deny or secret pattern check (mandatory invariants take precedence)
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
