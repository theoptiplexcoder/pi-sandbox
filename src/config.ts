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
 * Default fallback security configuration.
 * Adheres to the principle of least privilege:
 * - Read: Standard tools permitted, credential directories denied.
 * - Write: Restricted strictly to current working directory ('.') and ephemeral '/tmp'.
 * - Network: Whitelisted to common package registries and GitHub.
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
    denyRead: [
      "~/.ssh",
      "~/.aws",
      "~/.gnupg",
      "~/.config/gh",
      "~/.netrc",
      "/etc/shadow",
      "/etc/sudoers",
    ],
    allowWrite: [".", "/tmp"],
    denyWrite: [".env", ".env.*", "*.pem", "*.key", "id_rsa*", "id_ed25519*"],
  },
};

/**
 * Expands leading tilde ('~' or '~/') to the user's home directory.
 * If the path does not start with '~', returns pathStr unchanged.
 *
 * @param pathStr Path potentially containing a tilde.
 * @returns Path with tilde expanded to os.homedir().
 */
export function expandTilde(pathStr: string): string {
  if (pathStr === "~" || pathStr.startsWith("~/") || pathStr.startsWith("~\\")) {
    return pathStr.replace(/^~(?=$|\/|\\)/, homedir());
  }
  return pathStr;
}

/**
 * Normalizes a configuration path, resolving tilde expansion and relative paths.
 *
 * @param pathStr Path to normalize.
 * @param baseCwd Working directory to resolve relative paths against.
 * @returns Absolute resolved path string.
 */
export function normalizeConfigPath(pathStr: string, baseCwd: string = process.cwd()): string {
  const expanded = expandTilde(pathStr);
  if (isAbsolute(expanded)) {
    return resolve(expanded);
  }
  return resolve(baseCwd, expanded);
}

/**
 * Returns a deduplicated array preserving order.
 */
function uniqueArray<T>(items: T[] | undefined): T[] {
  if (!items) return [];
  return Array.from(new Set(items));
}

/**
 * Merges base configuration with overrides using security-first union semantics:
 * - Arrays (allowedDomains, allowWrite, denyRead, etc.) are combined as unique unions.
 * - Flags (enabled) are overridden only if explicitly defined in overrides.
 *
 * @param base The base configuration.
 * @param overrides Partial configuration overrides.
 * @returns A newly merged SandboxConfig instance.
 */
export function mergeConfigs(
  base: SandboxConfig,
  overrides?: Partial<SandboxConfig>,
): SandboxConfig {
  if (!overrides) return { ...base };

  return {
    enabled: overrides.enabled !== undefined ? overrides.enabled : base.enabled,
    network: {
      enabled:
        overrides.network?.enabled !== undefined
          ? overrides.network.enabled
          : base.network?.enabled ?? true,
      allowedDomains: uniqueArray([
        ...(base.network?.allowedDomains ?? []),
        ...(overrides.network?.allowedDomains ?? []),
      ]),
      deniedDomains: uniqueArray([
        ...(base.network?.deniedDomains ?? []),
        ...(overrides.network?.deniedDomains ?? []),
      ]),
    },
    filesystem: {
      allowRead: uniqueArray([
        ...(base.filesystem?.allowRead ?? []),
        ...(overrides.filesystem?.allowRead ?? []),
      ]),
      denyRead: uniqueArray([
        ...(base.filesystem?.denyRead ?? []),
        ...(overrides.filesystem?.denyRead ?? []),
      ]),
      allowWrite: uniqueArray([
        ...(base.filesystem?.allowWrite ?? []),
        ...(overrides.filesystem?.allowWrite ?? []),
      ]),
      denyWrite: uniqueArray([
        ...(base.filesystem?.denyWrite ?? []),
        ...(overrides.filesystem?.denyWrite ?? []),
      ]),
    },
  };
}

/**
 * Loads and merges hierarchical sandbox configurations in priority order:
 * 1. Default built-in security config
 * 2. Global user config (~/.pi/agent/sandbox.json)
 * 3. Project-local config (<cwd>/.pi/sandbox.json)
 *
 * @param cwd Current project root directory.
 * @param customConfigPaths Optional custom paths for testing or overrides.
 * @returns Fully merged SandboxConfig.
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

  const merged = mergeConfigs(DEFAULT_CONFIG, globalConfig);
  return mergeConfigs(merged, projectConfig);
}
