import { execSync } from "node:child_process";

/**
 * Configuration options for git push policy and branch protections.
 */
export interface GitPushConfig {
  /**
   * Whether git push operations are permitted. Default: false.
   */
  enabled?: boolean;
  /**
   * Protected branches that can NEVER be pushed to (e.g. ["main", "master"]).
   * Default: ["main", "master", "release/*", "prod*"]
   */
  protectedBranches?: string[];
  /**
   * Explicit allowed branch patterns (e.g. ["*"] or ["dev", "feature/*"]).
   * Non-matching branches are blocked.
   */
  allowBranches?: string[];
}

export const DEFAULT_PROTECTED_BRANCHES = [
  "main",
  "master",
  "release/*",
  "prod*",
  "production",
];

/**
 * Checks if a branch name matches any glob-like wildcard pattern (e.g. "release/*").
 */
export function matchesBranchPattern(branch: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    if (pattern === branch) return true;
    if (pattern === "*") return true;
    if (pattern.endsWith("/*")) {
      const prefix = pattern.slice(0, -1); // e.g. "release/"
      if (branch.startsWith(prefix)) return true;
    } else if (pattern.endsWith("*")) {
      const prefix = pattern.slice(0, -1);
      if (branch.startsWith(prefix)) return true;
    }
  }
  return false;
}

/**
 * Determines whether a command looks like a `git push` command.
 */
export function isGitPushCommand(command: string): boolean {
  // Matches "git push", "\git push", "/usr/bin/git push", etc.
  const regex = /(?:^|[;&|]\s*)(?:(?:\S*\/)?git)\s+(?:-[^\s]+\s+)*push(?:\s+|$)/i;
  return regex.test(command);
}

/**
 * Resolves the active branch name in the specified repository directory.
 */
export function getCurrentGitBranch(cwd: string): string | null {
  try {
    const branch = execSync("git symbolic-ref --short HEAD", {
      cwd,
      stdio: ["ignore", "pipe", "ignore"],
      encoding: "utf-8",
    }).trim();
    return branch || null;
  } catch {
    return null;
  }
}

/**
 * Extracts target branch references from git push arguments.
 * E.g.: "git push origin dev" -> ["dev"]
 *       "git push origin feature/login:main" -> ["main"] (remote ref is target)
 *       "git push -u origin dev" -> ["dev"]
 * If no explicit branch is found, falls back to the current active branch.
 */
export function extractPushTargetBranches(command: string, cwd: string): string[] {
  // Tokenize command line around git push
  const match = /(?:^|[;&|]\s*)(?:(?:\S*\/)?git)\s+.*?\bpush\b\s*(.*)$/i.exec(command);
  if (!match) return [];

  const rawArgs = match[1].trim();
  const tokens = rawArgs.split(/\s+/).filter(Boolean);

  const targets: string[] = [];
  let foundRemote = false;

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    // Skip flags (like -u, --set-upstream, --force, --tags, etc.)
    if (token.startsWith("-")) {
      // Flags that take an argument
      if (["-o", "--push-option", "--receive-pack", "--exec"].includes(token) && i + 1 < tokens.length) {
        i++;
      }
      continue;
    }

    // First positional argument is the remote (e.g. origin, upstream, or URL)
    if (!foundRemote) {
      foundRemote = true;
      continue;
    }

    // Subsequent positional arguments are refspecs (e.g. "dev", "HEAD:dev", ":old-branch")
    if (token.includes(":")) {
      const parts = token.split(":");
      const remoteRef = parts[1];
      if (remoteRef) {
        // e.g. "refs/heads/dev" -> "dev"
        targets.push(remoteRef.replace(/^refs\/heads\//, ""));
      } else {
        // Deletion ref e.g. ":dev"
        const localRef = parts[0];
        if (localRef) {
          targets.push(localRef.replace(/^refs\/heads\//, ""));
        }
      }
    } else {
      targets.push(token.replace(/^refs\/heads\//, ""));
    }
  }

  // If no explicit branch was specified in args (e.g. simple `git push`), target is current HEAD branch
  if (targets.length === 0) {
    const current = getCurrentGitBranch(cwd);
    if (current) {
      targets.push(current);
    }
  }

  return targets;
}

/**
 * Validates a git push operation against branch protections.
 * Returns { allowed: true } or { allowed: false, reason: string }.
 */
export function evaluateGitPushPolicy(
  command: string,
  cwd: string,
  gitPushConfig?: GitPushConfig,
): { allowed: boolean; reason?: string } {
  if (!isGitPushCommand(command)) {
    return { allowed: true };
  }

  if (gitPushConfig?.enabled !== true) {
    return {
      allowed: false,
      reason: "[Security Sandbox] 'git push' is disabled in sandbox policy.",
    };
  }

  const protectedBranches = gitPushConfig.protectedBranches ?? DEFAULT_PROTECTED_BRANCHES;
  const allowBranches = gitPushConfig.allowBranches ?? ["*"];
  const targetBranches = extractPushTargetBranches(command, cwd);

  if (targetBranches.length === 0) {
    return {
      allowed: false,
      reason: "[Security Sandbox] Cannot determine target branch for 'git push'. Direct push blocked for safety.",
    };
  }

  for (const branch of targetBranches) {
    // 1. Strict check: Protected branches (main, master, etc.) are ALWAYS blocked
    if (matchesBranchPattern(branch, protectedBranches)) {
      return {
        allowed: false,
        reason: `[Security Sandbox Violation] Pushing to protected branch '${branch}' is forbidden by sandbox policy. Only non-main branches are permitted.`,
      };
    }

    // 2. Must match allowBranches if defined
    if (!matchesBranchPattern(branch, allowBranches)) {
      return {
        allowed: false,
        reason: `[Security Sandbox Violation] Target branch '${branch}' is not in allowedBranches list.`,
      };
    }
  }

  return { allowed: true };
}
