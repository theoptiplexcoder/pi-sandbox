import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import type { GitPushConfig } from "./git-policy.ts";

export type { GitPushConfig } from "./git-policy.ts";

/**
 * Configuration options for network egress isolation and domain filtering.
 */
export interface NetworkConfig {
  /**
   * Whether network sandboxing is enabled.
   * If true, subprocesses run with an unshared network namespace (--unshare-net)
   * and outbound requests are routed via proxy.
   */
  enabled?: boolean;
  /**
   * List of allowed domains (e.g. "github.com", "*.github.com", "registry.npmjs.org").
   */
  allowedDomains?: string[];
  /**
   * List of explicitly denied domains (takes precedence over allowedDomains).
   */
  deniedDomains?: string[];
}

/**
 * Configuration options for filesystem isolation and path access controls.
 */
export interface FilesystemConfig {
  /**
   * Paths explicitly allowed for reading beyond the project root and /tmp.
   * Note: Only configurable at global user level. Project configs cannot grant allowRead.
   */
  allowRead?: string[];
  /**
   * Paths strictly forbidden from reading (e.g. "~/.ssh", "/etc/shadow").
   * Masked via empty tmpfs mounts in subprocesses and blocked from direct tool calls.
   */
  denyRead?: string[];
  /**
   * Paths allowed for writing (default: [".", "/tmp"]).
   * Note: Only configurable at global user level. Project configs cannot grant allowWrite.
   */
  allowWrite?: string[];
  /**
   * Patterns or paths forbidden from writing, even if inside an allowWrite directory
   * (e.g. ".env", ".env.*", "*.pem", "*.key").
   */
  denyWrite?: string[];
}

/**
 * Top-level Sandbox Configuration schema.
 */
export interface SandboxConfig {
  /**
   * Global master switch for sandbox protection.
   */
  enabled?: boolean;
  /**
   * Network egress configuration.
   */
  network?: NetworkConfig;
  /**
   * Filesystem access configuration.
   */
  filesystem?: FilesystemConfig;
  /**
   * Git push and branch protection configuration.
   */
  gitPush?: GitPushConfig;
}

/**
 * Mandatory security invariants that can NEVER be relaxed, cleared, or disabled
 * by untrusted project-local configuration.
 *
 * Hardening Rule:
 * An untrusted cloned repository can only tighten restrictions (add to deny lists).
 * It cannot disable the sandbox, whitelist sensitive credentials, or permit self-tampering.
 */
export const MANDATORY_INVARIANTS: Readonly<{
  denyRead: readonly string[];
  denyWrite: readonly string[];
}> = Object.freeze({
  denyRead: Object.freeze([
    "~/.ssh",
    "~/.ssh/**",
    "~/.aws",
    "~/.aws/**",
    "~/.gnupg",
    "~/.gnupg/**",
    "~/.config/gh",
    "~/.config/gh/**",
    "~/.netrc",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/pi-sandbox/**",
    "/etc/pi-sandbox",
    "**/.pi/sandbox.json",
    "**/.pi/settings.json",
    "~/.pi/agent/sandbox.json",
    "~/.pi/agent/settings.json",
  ]),
  denyWrite: Object.freeze([
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "*.pem",
    "*.key",
    "**/*.pem",
    "**/*.key",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "/etc/pi-sandbox/**",
    "/etc/pi-sandbox",
    "**/.pi/sandbox.json",
    "**/.pi/settings.json",
    "~/.pi/agent/sandbox.json",
    "~/.pi/agent/settings.json",
    "/etc",
    "/etc/**",
    "/usr",
    "/usr/**",
    "/boot",
    "/boot/**",
  ]),
});

/**
 * Default fallback security configuration.
 */
export const DEFAULT_CONFIG: SandboxConfig = {
  enabled: true,
  network: {
    enabled: true,
    allowedDomains: [
      "github.com",
      "*.github.com",
      "api.github.com",
      "raw.githubusercontent.com",
      "npmjs.org",
      "*.npmjs.org",
      "registry.npmjs.org",
      "registry.yarnpkg.com",
      "pypi.org",
      "*.pypi.org",
      "files.pythonhosted.org",
    ],
    deniedDomains: [],
  },
  filesystem: {
    allowRead: [],
    denyRead: [...MANDATORY_INVARIANTS.denyRead],
    allowWrite: [".", "/tmp"],
    denyWrite: [...MANDATORY_INVARIANTS.denyWrite],
  },
  gitPush: {
    enabled: false,
    protectedBranches: ["main", "master", "release/*", "prod*"],
    allowBranches: ["*"],
  },
};

/**
 * Expands leading tilde ('~' or '~/') to the user's home directory.
 */
export function expandTilde(pathStr: string): string {
  if (pathStr === "~" || pathStr.startsWith("~/") || pathStr.startsWith("~\\")) {
    return pathStr.replace(/^~(?=$|\/|\\)/, homedir());
  }
  return pathStr;
}

/**
 * Normalizes a configuration path, resolving tilde expansion and relative paths.
 */
export function normalizeConfigPath(pathStr: string, baseCwd: string = process.cwd()): string {
  const expanded = expandTilde(pathStr);
  if (isAbsolute(expanded)) {
    return resolve(expanded);
  }
  return resolve(baseCwd, expanded);
}

function uniqueArray<T>(items: (readonly T[] | T[] | undefined)[]): T[] {
  const result = new Set<T>();
  for (const arr of items) {
    if (arr) {
      for (const item of arr) {
        result.add(item);
      }
    }
  }
  return Array.from(result);
}

/**
 * Merges global user configuration into base default configuration.
 * Global user config is trusted (configured intentionally by the machine owner).
 */
export function mergeGlobalConfig(
  base: SandboxConfig,
  globalOverrides?: Partial<SandboxConfig>,
): SandboxConfig {
  if (!globalOverrides) return { ...base };

  return {
    enabled: globalOverrides.enabled !== undefined ? globalOverrides.enabled : base.enabled,
    network: {
      enabled:
        globalOverrides.network?.enabled !== undefined
          ? globalOverrides.network.enabled
          : base.network?.enabled ?? true,
      allowedDomains: uniqueArray([
        base.network?.allowedDomains,
        globalOverrides.network?.allowedDomains,
      ]),
      deniedDomains: uniqueArray([
        base.network?.deniedDomains,
        globalOverrides.network?.deniedDomains,
      ]),
    },
    filesystem: {
      allowRead: uniqueArray([
        base.filesystem?.allowRead,
        globalOverrides.filesystem?.allowRead,
      ]),
      // Always enforce mandatory invariant deny rules
      denyRead: uniqueArray([
        MANDATORY_INVARIANTS.denyRead,
        base.filesystem?.denyRead,
        globalOverrides.filesystem?.denyRead,
      ]),
      allowWrite: uniqueArray([
        base.filesystem?.allowWrite,
        globalOverrides.filesystem?.allowWrite,
      ]),
      // Always enforce mandatory invariant deny rules
      denyWrite: uniqueArray([
        MANDATORY_INVARIANTS.denyWrite,
        base.filesystem?.denyWrite,
        globalOverrides.filesystem?.denyWrite,
      ]),
    },
    gitPush: {
      enabled:
        globalOverrides.gitPush?.enabled !== undefined
          ? globalOverrides.gitPush.enabled
          : base.gitPush?.enabled ?? false,
      protectedBranches: uniqueArray([
        base.gitPush?.protectedBranches,
        globalOverrides.gitPush?.protectedBranches,
      ]),
      allowBranches: globalOverrides.gitPush?.allowBranches ?? base.gitPush?.allowBranches ?? ["*"],
    },
  };
}

/**
 * Merges untrusted project-local configuration with strict trust boundaries:
 *
 * Security Invariants Enforced (Linus Rule: Zero Trust on Project Permissions):
 * 1. Project config CANNOT disable the sandbox (`enabled: false` is rejected).
 * 2. Project config CANNOT disable network isolation.
 * 3. Project config CANNOT remove mandatory deny rules (deny lists can only be expanded).
 * 4. Project config CANNOT grant allowRead or allowWrite permissions (project allow* is completely dropped).
 *    Untrusted repositories cannot authorize themselves to read or write host files.
 */
export function mergeProjectConfig(
  trustedBase: SandboxConfig,
  projectOverrides?: Partial<SandboxConfig>,
): SandboxConfig {
  if (!projectOverrides) return { ...trustedBase };

  // Project cannot disable sandbox if trustedBase has it enabled
  const effectiveEnabled = trustedBase.enabled;

  // Project can request additional allowed domains, but deniedDomains take precedence
  const effectiveAllowedDomains = uniqueArray([
    trustedBase.network?.allowedDomains,
    projectOverrides.network?.allowedDomains,
  ]);
  const effectiveDeniedDomains = uniqueArray([
    trustedBase.network?.deniedDomains,
    projectOverrides.network?.deniedDomains,
  ]);

  // Project can request additional deny rules (tightening the policy only)
  const effectiveDenyRead = uniqueArray([
    MANDATORY_INVARIANTS.denyRead,
    trustedBase.filesystem?.denyRead,
    projectOverrides.filesystem?.denyRead,
  ]);

  const effectiveDenyWrite = uniqueArray([
    MANDATORY_INVARIANTS.denyWrite,
    trustedBase.filesystem?.denyWrite,
    projectOverrides.filesystem?.denyWrite,
  ]);

  // Security Hardening: Project-local allowRead and allowWrite are completely ignored.
  // Only trustedBase (system defaults + user's ~/.pi/agent/sandbox.json) defines writable/readable roots.
  return {
    enabled: effectiveEnabled,
    network: {
      enabled: trustedBase.network?.enabled ?? true,
      allowedDomains: effectiveAllowedDomains,
      deniedDomains: effectiveDeniedDomains,
    },
    filesystem: {
      allowRead: trustedBase.filesystem?.allowRead ?? [],
      denyRead: effectiveDenyRead,
      allowWrite: trustedBase.filesystem?.allowWrite ?? [".", "/tmp"],
      denyWrite: effectiveDenyWrite,
    },
    gitPush: {
      // Untrusted project can only disable or tighten gitPush (cannot enable if user disabled it)
      enabled: trustedBase.gitPush?.enabled === true && projectOverrides.gitPush?.enabled !== false,
      protectedBranches: uniqueArray([
        trustedBase.gitPush?.protectedBranches,
        projectOverrides.gitPush?.protectedBranches,
      ]),
      allowBranches: projectOverrides.gitPush?.allowBranches ?? trustedBase.gitPush?.allowBranches ?? ["*"],
    },
  };
}

/**
 * Loads and merges hierarchical sandbox configurations in priority order:
 * 1. Default built-in security config
 * 2. System administrative config (/etc/pi-sandbox/sandbox.json) [Root/Admin owned]
 * 3. Global user config (~/.pi/agent/sandbox.json)
 * 4. Project-local config (<cwd>/.pi/sandbox.json) subjected to trust hierarchy filters.
 */
export function loadConfig(
  cwd: string = process.cwd(),
  customConfigPaths?: { system?: string; global?: string; project?: string },
): SandboxConfig {
  const systemPath = customConfigPaths?.system ?? "/etc/pi-sandbox/sandbox.json";
  const globalPath = customConfigPaths?.global ?? join(homedir(), ".pi", "agent", "sandbox.json");
  const projectPath = customConfigPaths?.project ?? join(cwd, ".pi", "sandbox.json");

  let systemConfig: Partial<SandboxConfig> = {};
  let globalConfig: Partial<SandboxConfig> = {};
  let projectConfig: Partial<SandboxConfig> = {};

  if (existsSync(systemPath)) {
    try {
      systemConfig = JSON.parse(readFileSync(systemPath, "utf-8"));
    } catch (err) {
      console.error(`[claudelike-pisandbox] Warning: Failed to parse system config at ${systemPath}:`, err);
    }
  }

  if (existsSync(globalPath)) {
    try {
      globalConfig = JSON.parse(readFileSync(globalPath, "utf-8"));
    } catch (err) {
      console.error(`[claudelike-pisandbox] Warning: Failed to parse global config at ${globalPath}:`, err);
    }
  }

  if (existsSync(projectPath)) {
    try {
      projectConfig = JSON.parse(readFileSync(projectPath, "utf-8"));
    } catch (err) {
      console.error(`[claudelike-pisandbox] Warning: Failed to parse project config at ${projectPath}:`, err);
    }
  }

  // System config acts as baseline override over defaults, followed by user and project
  const baseWithSystem = mergeGlobalConfig(DEFAULT_CONFIG, systemConfig);
  const trusted = mergeGlobalConfig(baseWithSystem, globalConfig);
  return mergeProjectConfig(trusted, projectConfig);
}
