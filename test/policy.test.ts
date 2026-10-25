import { describe, expect, it } from "bun:test";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import {
  canonicalizePath,
  decideReadPolicy,
  decideWritePolicy,
  isSecretPath,
  matchesPattern,
} from "../src/policy.ts";

describe("Policy Engine - Path & Secret Protection", () => {
  const cwd = process.cwd();

  it("canonicalizes traversal paths (../../)", () => {
    // cwd is /home/ybl/git/pi-setup/extensions/claudelike-pisandbox (6 segments: /, home, ybl, git, pi-setup, extensions, claudelike-pisandbox)
    const malicious = resolve(cwd, "../../../../../../etc/passwd");
    const canonical = canonicalizePath(malicious, cwd);
    expect(canonical).toBe("/etc/passwd");
  });

  it("expands tilde paths to homedir", () => {
    const sshPath = canonicalizePath("~/.ssh/id_rsa", cwd);
    expect(sshPath).toBe(join(homedir(), ".ssh", "id_rsa"));
  });

  it("detects sensitive secrets by filename glob and directory prefix", () => {
    expect(isSecretPath("~/.ssh/id_rsa", [], cwd)).toBe(true);
    expect(isSecretPath("~/.aws/credentials", [], cwd)).toBe(true);
    expect(isSecretPath("~/.gnupg/secring.gpg", [], cwd)).toBe(true);
    expect(isSecretPath(".env", [], cwd)).toBe(true);
    expect(isSecretPath(".env.local", [], cwd)).toBe(true);
    expect(isSecretPath(".env.production", [], cwd)).toBe(true);
    expect(isSecretPath("server.key", [], cwd)).toBe(true);
    expect(isSecretPath("cert.pem", [], cwd)).toBe(true);
    expect(isSecretPath("/etc/shadow", [], cwd)).toBe(true);
  });

  it("allows safe files inside project", () => {
    expect(isSecretPath("src/index.ts", [], cwd)).toBe(false);
    expect(isSecretPath("README.md", [], cwd)).toBe(false);
    expect(isSecretPath("package.json", [], cwd)).toBe(false);
  });

  it("enforces decideReadPolicy correctly", () => {
    // Secret read is denied
    expect(decideReadPolicy("~/.ssh/id_rsa", [], ["~/.ssh"], cwd)).toBe("deny");
    expect(decideReadPolicy("/etc/shadow", [], ["/etc/shadow"], cwd)).toBe("deny");

    // Project files are allowed
    expect(decideReadPolicy("package.json", [], [], cwd)).toBe("allow");
  });

  it("enforces decideWritePolicy with absolute and relative paths", () => {
    // Writing .env inside project is denied
    expect(decideWritePolicy(".env", [".", "/tmp"], [".env*"], cwd)).toBe("deny");

    // Writing inside cwd is allowed
    expect(decideWritePolicy("src/new-file.ts", [".", "/tmp"], [], cwd)).toBe("allow");
    expect(decideWritePolicy("/tmp/test.log", [".", "/tmp"], [], cwd)).toBe("allow");

    // Writing outside cwd to arbitrary system file prompts
    expect(decideWritePolicy("/etc/hosts", [".", "/tmp"], [], cwd)).toBe("prompt");
    expect(decideWritePolicy("/var/log/system.log", [".", "/tmp"], [], cwd)).toBe("prompt");

    // Custom allowed absolute path succeeds
    expect(
      decideWritePolicy("/var/log/my-app/debug.log", [".", "/tmp", "/var/log/my-app"], [], cwd),
    ).toBe("allow");
  });
});
