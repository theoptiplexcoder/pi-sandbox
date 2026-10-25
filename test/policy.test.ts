import { describe, expect, it } from "bun:test";
import { mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  DEFAULT_CONFIG,
  expandTilde,
  loadConfig,
  mergeConfigs,
  normalizeConfigPath,
  type SandboxConfig,
} from "../src/config.ts";
import {
  canonicalizePath,
  decideReadPolicy,
  decideWritePolicy,
  isSecretPath,
  matchesPattern,
} from "../src/policy.ts";

describe("Phase 1: Configuration Management (src/config.ts)", () => {
  const cwd = process.cwd();

  it("expands tilde to home directory", () => {
    expect(expandTilde("~")).toBe(homedir());
    expect(expandTilde("~/test")).toBe(join(homedir(), "test"));
    expect(expandTilde("/var/log")).toBe("/var/log");
    expect(expandTilde("relative/path")).toBe("relative/path");
  });

  it("normalizes relative and absolute config paths", () => {
    expect(normalizeConfigPath("src/main.ts", cwd)).toBe(resolve(cwd, "src/main.ts"));
    expect(normalizeConfigPath("/etc/hosts", cwd)).toBe("/etc/hosts");
    expect(normalizeConfigPath("~/.ssh/id_rsa", cwd)).toBe(join(homedir(), ".ssh", "id_rsa"));
  });

  it("merges configs with union array semantics and overrides flags", () => {
    const base: SandboxConfig = {
      enabled: true,
      network: {
        enabled: true,
        allowedDomains: ["github.com"],
        deniedDomains: [],
      },
      filesystem: {
        allowWrite: ["."],
        denyRead: ["~/.ssh"],
      },
    };

    const override: Partial<SandboxConfig> = {
      enabled: false,
      network: {
        allowedDomains: ["*.npmjs.org"],
        deniedDomains: ["evil.com"],
      },
      filesystem: {
        allowWrite: ["/var/log"],
        denyRead: ["/etc/shadow"],
      },
    };

    const merged = mergeConfigs(base, override);
    expect(merged.enabled).toBe(false);
    expect(merged.network?.allowedDomains).toEqual(["github.com", "*.npmjs.org"]);
    expect(merged.network?.deniedDomains).toEqual(["evil.com"]);
    expect(merged.filesystem?.allowWrite).toEqual([".", "/var/log"]);
    expect(merged.filesystem?.denyRead).toEqual(["~/.ssh", "/etc/shadow"]);
  });

  it("loads and merges project-local config over global config", () => {
    const tempDir = join(tmpdir(), `sandbox-test-conf-${Date.now()}`);
    const globalFile = join(tempDir, "global.json");
    const projectFile = join(tempDir, "project.json");

    mkdirSync(tempDir, { recursive: true });

    writeFileSync(
      globalFile,
      JSON.stringify({
        network: { allowedDomains: ["global.com"] },
      }),
    );

    writeFileSync(
      projectFile,
      JSON.stringify({
        network: { allowedDomains: ["project.com"] },
        filesystem: { allowWrite: ["/opt/data"] },
      }),
    );

    const loaded = loadConfig(tempDir, { global: globalFile, project: projectFile });

    expect(loaded.network?.allowedDomains).toContain("global.com");
    expect(loaded.network?.allowedDomains).toContain("project.com");
    expect(loaded.filesystem?.allowWrite).toContain("/opt/data");

    rmSync(tempDir, { recursive: true, force: true });
  });
});

describe("Phase 1: Policy Engine & Canonicalization (src/policy.ts)", () => {
  const cwd = process.cwd();

  it("canonicalizes directory traversal sequences (../../)", () => {
    const malicious = resolve(cwd, "../../../../../../etc/passwd");
    const canonical = canonicalizePath(malicious, cwd);
    expect(canonical).toBe("/etc/passwd");
  });

  it("resolves non-existent file paths to nearest existing ancestor", () => {
    const futureFile = resolve(cwd, "src", "non-existent-sub", "new-file.ts");
    const canonical = canonicalizePath(futureFile, cwd);
    expect(canonical.endsWith("src/non-existent-sub/new-file.ts")).toBe(true);
  });

  it("resolves symlinks pointing outside workspace to real targets", () => {
    const tempDir = join(tmpdir(), `sandbox-test-symlink-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });

    const linkPath = join(tempDir, "link-to-passwd");
    try {
      symlinkSync("/etc/passwd", linkPath);
      const canonical = canonicalizePath(linkPath, tempDir);
      expect(canonical).toBe("/etc/passwd");
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("matches filename globs and path patterns", () => {
    expect(matchesPattern(".env", [".env*"], cwd)).toBe(true);
    expect(matchesPattern(".env.production", [".env*"], cwd)).toBe(true);
    expect(matchesPattern("server.key", ["*.key"], cwd)).toBe(true);
    expect(matchesPattern("cert.pem", ["*.pem"], cwd)).toBe(true);
    expect(matchesPattern("/var/log/my-app.log", ["/var/log/*.log"], cwd)).toBe(true);
    expect(matchesPattern("~/.ssh/id_rsa", ["~/.ssh"], cwd)).toBe(true);
  });

  it("detects sensitive credentials with isSecretPath", () => {
    expect(isSecretPath("~/.ssh/id_rsa", [], cwd)).toBe(true);
    expect(isSecretPath("~/.aws/credentials", [], cwd)).toBe(true);
    expect(isSecretPath("~/.gnupg/secring.gpg", [], cwd)).toBe(true);
    expect(isSecretPath(".env", [], cwd)).toBe(true);
    expect(isSecretPath(".env.local", [], cwd)).toBe(true);
    expect(isSecretPath("/etc/shadow", [], cwd)).toBe(true);
    expect(isSecretPath("id_ed25519", [], cwd)).toBe(true);

    // Safe files
    expect(isSecretPath("src/main.ts", [], cwd)).toBe(false);
    expect(isSecretPath("package.json", [], cwd)).toBe(false);
  });

  it("evaluates decideReadPolicy with security priority", () => {
    // Secret read is denied
    expect(decideReadPolicy("~/.ssh/id_rsa", [], ["~/.ssh"], cwd)).toBe("deny");
    expect(decideReadPolicy("/etc/shadow", [], ["/etc/shadow"], cwd)).toBe("deny");

    // Project files allowed
    expect(decideReadPolicy("package.json", [], [], cwd)).toBe("allow");

    // Custom allowRead override
    expect(decideReadPolicy("/opt/data/shared.txt", ["/opt/data"], [], cwd)).toBe("allow");
  });

  it("evaluates decideWritePolicy with security priority", () => {
    // Writing secret inside workspace is denied
    expect(decideWritePolicy(".env", [".", "/tmp"], [".env*"], cwd)).toBe("deny");
    expect(decideWritePolicy("server.key", [".", "/tmp"], ["*.key"], cwd)).toBe("deny");

    // Writing inside workspace or /tmp is allowed
    expect(decideWritePolicy("src/app.ts", [".", "/tmp"], [], cwd)).toBe("allow");
    expect(decideWritePolicy("/tmp/debug.log", [".", "/tmp"], [], cwd)).toBe("allow");

    // Writing outside workspace requires prompt
    expect(decideWritePolicy("/etc/hosts", [".", "/tmp"], [], cwd)).toBe("prompt");
    expect(decideWritePolicy("/home/user/.bashrc", [".", "/tmp"], [], cwd)).toBe("prompt");

    // Writing to custom allowed absolute path is allowed
    expect(
      decideWritePolicy("/var/log/my-app/app.log", [".", "/tmp", "/var/log/my-app"], [], cwd),
    ).toBe("allow");
  });
});
