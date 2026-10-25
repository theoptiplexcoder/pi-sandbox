import { describe, expect, it } from "bun:test";
import { mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  DEFAULT_CONFIG,
  expandTilde,
  loadConfig,
  MANDATORY_INVARIANTS,
  mergeGlobalConfig,
  mergeProjectConfig,
  normalizeConfigPath,
  type SandboxConfig,
} from "../src/config.ts";
import {
  canonicalizePath,
  decideReadPolicy,
  decideWritePolicy,
  globToRegex,
  isPathContained,
  isSecretPath,
  matchesPattern,
} from "../src/policy.ts";

describe("Phase 1: Configuration Trust Hierarchy (src/config.ts)", () => {
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

  it("ADVERSARIAL: Untrusted project config cannot disable the sandbox", () => {
    const trustedBase: SandboxConfig = {
      ...DEFAULT_CONFIG,
      enabled: true,
    };

    const maliciousProjectConfig: Partial<SandboxConfig> = {
      enabled: false,
    };

    const merged = mergeProjectConfig(trustedBase, maliciousProjectConfig);
    expect(merged.enabled).toBe(true); // Must remain true!
  });

  it("ADVERSARIAL: Untrusted project config cannot remove mandatory deny rules", () => {
    const trustedBase = DEFAULT_CONFIG;

    const maliciousProjectConfig: Partial<SandboxConfig> = {
      filesystem: {
        denyRead: [], // Attempt to clear denyRead
        denyWrite: [], // Attempt to clear denyWrite
        allowRead: ["~/.ssh", "/etc/shadow"], // Attempt to whitelist credentials
      },
    };

    const merged = mergeProjectConfig(trustedBase, maliciousProjectConfig);

    // Mandatory deny rules must still be present
    expect(merged.filesystem?.denyRead).toContain("~/.ssh");
    expect(merged.filesystem?.denyRead).toContain("/etc/shadow");
    expect(merged.filesystem?.denyWrite).toContain(".env");

    // Attempted secret allowRead must be pruned
    expect(merged.filesystem?.allowRead).not.toContain("~/.ssh");
    expect(merged.filesystem?.allowRead).not.toContain("/etc/shadow");
  });

  it("ADVERSARIAL: Untrusted project config can only tighten restrictions", () => {
    const trustedBase = DEFAULT_CONFIG;

    const projectConfig: Partial<SandboxConfig> = {
      filesystem: {
        denyRead: ["./proprietary-dataset"],
        denyWrite: ["./release-notes.md"],
      },
      network: {
        deniedDomains: ["untrusted-cdn.com"],
      },
    };

    const merged = mergeProjectConfig(trustedBase, projectConfig);
    expect(merged.filesystem?.denyRead).toContain("./proprietary-dataset");
    expect(merged.filesystem?.denyWrite).toContain("./release-notes.md");
    expect(merged.network?.deniedDomains).toContain("untrusted-cdn.com");
  });
});

describe("Phase 1: Directory Containment & Sibling Protection", () => {
  it("correctly identifies path containment using isPathContained", () => {
    const root = "/home/advik/project";

    // Direct child
    expect(isPathContained(root, "/home/advik/project/src/main.ts")).toBe(true);
    // Root itself
    expect(isPathContained(root, "/home/advik/project")).toBe(true);
    // Deeply nested child
    expect(isPathContained(root, "/home/advik/project/deep/sub/dir/file.txt")).toBe(true);

    // ADVERSARIAL: Sibling directory attack (starts with same prefix string)
    expect(isPathContained(root, "/home/advik/project-secret")).toBe(false);
    expect(isPathContained(root, "/home/advik/project-secret/passwords.txt")).toBe(false);

    // Parent directory traversal
    expect(isPathContained(root, "/home/advik")).toBe(false);
    expect(isPathContained(root, "/etc/passwd")).toBe(false);
  });
});

describe("Phase 1: Glob Semantics & Wildcard Matching", () => {
  it("differentiates single-component wildcard (*) from recursive (**)", () => {
    const singleGlob = globToRegex("/tmp/*.txt");
    expect(singleGlob.test("/tmp/file.txt")).toBe(true);
    // Must NOT match nested subdirectories
    expect(singleGlob.test("/tmp/nested/file.txt")).toBe(false);

    const recursiveGlob = globToRegex("/tmp/**/*.txt");
    expect(recursiveGlob.test("/tmp/nested/file.txt")).toBe(true);
    expect(recursiveGlob.test("/tmp/a/b/c/file.txt")).toBe(true);
  });

  it("matches filename globs without matching directory separators", () => {
    const envGlob = globToRegex(".env*");
    expect(envGlob.test(".env")).toBe(true);
    expect(envGlob.test(".env.local")).toBe(true);
    expect(envGlob.test(".env.production")).toBe(true);
    expect(envGlob.test(".env/subfile")).toBe(false); // Does not match slash
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

  it("ADVERSARIAL: Agent cannot inspect or modify its own sandbox policies", () => {
    expect(isSecretPath(".pi/sandbox.json", [], cwd)).toBe(true);
    expect(isSecretPath(".pi/settings.json", [], cwd)).toBe(true);
    expect(isSecretPath("~/.pi/agent/sandbox.json", [], cwd)).toBe(true);

    expect(decideWritePolicy(".pi/sandbox.json", [".", "/tmp"], [], cwd)).toBe("deny");
    expect(decideWritePolicy("~/.pi/agent/sandbox.json", [".", "/tmp"], [], cwd)).toBe("deny");
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

    // Writing to system directories in MANDATORY_INVARIANTS.denyWrite (/etc, /usr, /boot) is denied immediately
    expect(decideWritePolicy("/etc/hosts", [".", "/tmp"], [], cwd)).toBe("deny");

    // Writing outside workspace to non-system file requires prompt
    expect(decideWritePolicy("/var/log/custom.log", [".", "/tmp"], [], cwd)).toBe("prompt");
    expect(decideWritePolicy("/home/user/.bashrc", [".", "/tmp"], [], cwd)).toBe("prompt");

    // Writing to custom allowed absolute path is allowed
    expect(
      decideWritePolicy("/var/log/my-app/app.log", [".", "/tmp", "/var/log/my-app"], [], cwd),
    ).toBe("allow");
  });
});
