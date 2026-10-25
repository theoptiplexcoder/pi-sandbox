import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

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
   */
  allowRead?: string[];
  /**
   * Paths strictly forbidden from reading (e.g. "~/.ssh", "/etc/shadow").
   * Masked via empty tmpfs mounts in subprocesses and blocked from direct tool calls.
   */
  denyRead?: string[];
  /**
   * Paths allowed for writing (default: [".", "/tmp"]).
   * Can include absolute paths (e.g. "/var/log/my-app").
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
  };
}

/**
 * Merges untrusted project-local configuration with strict trust boundaries:
 *
 * Security Invariants Enforced:
 * 1. Project config CANNOT disable the sandbox (`enabled: false` is rejected).
 * 2. Project config CANNOT disable network isolation.
 * 3. Project config CANNOT remove mandatory deny rules (deny lists can only be expanded).
 * 4. Project config CANNOT grant allowRead or allowWrite to mandatory protected secrets.
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

  // Project can request additional deny rules (tightening the policy)
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

  // Project allowWrite / allowRead: filter out any attempt to whitelist mandatory secrets
  const filterOutSecrets = (paths: string[] | undefined): string[] => {
    if (!paths) return [];
    return paths.filter((p) => {
      const clean = p.trim();
      return (
        clean !== "~/.ssh" &&
        !clean.startsWith("~/.ssh") &&
        clean !== "~/.aws" &&
        !clean.startsWith("~/.aws") &&
        clean !== "/etc/shadow" &&
        clean !== "/etc" &&
        !clean.startsWith("/etc/") &&
        clean !== ".env" &&
        !clean.includes(".pi/sandbox.json")
      );
    });
  };

  const effectiveAllowRead = uniqueArray([
    trustedBase.filesystem?.allowRead,
    filterOutSecrets(projectOverrides.filesystem?.allowRead),
  ]);

  const effectiveAllowWrite = uniqueArray([
    trustedBase.filesystem?.allowWrite,
    filterOutSecrets(projectOverrides.filesystem?.allowWrite),
  ]);

  return {
    enabled: effectiveEnabled,
    network: {
      enabled: trustedBase.network?.enabled ?? true,
      allowedDomains: effectiveAllowedDomains,
      deniedDomains: effectiveDeniedDomains,
    },
    filesystem: {
      allowRead: effectiveAllowRead,
      denyRead: effectiveDenyRead,
      allowWrite: effectiveAllowWrite,
      denyWrite: effectiveDenyWrite,
    },
  };
}

/**
 * Loads and merges hierarchical sandbox configurations in priority order:
 * 1. Default built-in security config
 * 2. Global user config (~/.pi/agent/sandbox.json)
 * 3. Project-local config (<cwd>/.pi/sandbox.json) subjected to trust hierarchy filters.
 */
export function loadConfig(
  cwd: string = process.cwd(),
  customConfigPaths?: { global?: string; project?: string },
): SandboxConfig {
  const globalPath = customConfigPaths?.global ?? join(homedir(), ".pi", "agent", "sandbox.json");
  const projectPath = customConfigPaths?.project ?? join(cwd, ".pi", "sandbox.json");

  let globalConfig: Partial<SandboxConfig> = {};
  let projectConfig: Partial<SandboxConfig> = {};

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

  const trusted = mergeGlobalConfig(DEFAULT_CONFIG, globalConfig);
  return mergeProjectConfig(trusted, projectConfig);
}
