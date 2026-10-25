import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

export interface NetworkConfig {
  enabled?: boolean;
  allowedDomains?: string[];
  deniedDomains?: string[];
}

export interface FilesystemConfig {
  allowRead?: string[];
  denyRead?: string[];
  allowWrite?: string[];
  denyWrite?: string[];
}

export interface SandboxConfig {
  enabled?: boolean;
  network?: NetworkConfig;
  filesystem?: FilesystemConfig;
}

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

export function expandTilde(pathStr: string): string {
  if (pathStr === "~" || pathStr.startsWith("~/")) {
    return pathStr.replace(/^~(?=$|\/)/, homedir());
  }
  return pathStr;
}

export function normalizeConfigPath(pathStr: string, baseCwd: string = process.cwd()): string {
  const expanded = expandTilde(pathStr);
  if (isAbsolute(expanded)) {
    return resolve(expanded);
  }
  return resolve(baseCwd, expanded);
}

function uniqueArray<T>(items: T[] | undefined): T[] {
  if (!items) return [];
  return Array.from(new Set(items));
}

export function mergeConfigs(
  base: SandboxConfig,
  overrides?: Partial<SandboxConfig>,
): SandboxConfig {
  if (!overrides) return { ...base };

  const merged: SandboxConfig = {
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

  return merged;
}

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
