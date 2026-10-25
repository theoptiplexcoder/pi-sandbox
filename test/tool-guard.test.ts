import { describe, expect, it } from "bun:test";
import { decideReadPolicy, decideWritePolicy } from "../src/policy.ts";

describe("In-Process Tool Guard Policies", () => {
  const cwd = "/home/user/project";
  const allowWrite = [".", "/tmp"];
  const denyWrite = [".env", ".env.*", "*.pem", "*.key", "id_rsa*"];
  const denyRead = ["~/.ssh", "~/.aws", "~/.gnupg", "/etc/shadow"];

  it("blocks reading SSH keys and secrets", () => {
    expect(decideReadPolicy("~/.ssh/id_rsa", [], denyRead, cwd)).toBe("deny");
    expect(decideReadPolicy("/etc/shadow", [], denyRead, cwd)).toBe("deny");
    expect(decideReadPolicy("~/.aws/credentials", [], denyRead, cwd)).toBe("deny");
  });

  it("blocks writing or editing .env file inside workspace", () => {
    expect(decideWritePolicy(".env", allowWrite, denyWrite, cwd)).toBe("deny");
    expect(decideWritePolicy("/home/user/project/.env", allowWrite, denyWrite, cwd)).toBe("deny");
    expect(decideWritePolicy(".env.production", allowWrite, denyWrite, cwd)).toBe("deny");
    expect(decideWritePolicy("server.key", allowWrite, denyWrite, cwd)).toBe("deny");
  });

  it("allows safe writes inside workspace and /tmp", () => {
    expect(decideWritePolicy("src/app.ts", allowWrite, denyWrite, cwd)).toBe("allow");
    expect(decideWritePolicy("/tmp/test.tmp", allowWrite, denyWrite, cwd)).toBe("allow");
  });

  it("requires prompt when writing outside workspace", () => {
    expect(decideWritePolicy("/etc/cron.d/job", allowWrite, denyWrite, cwd)).toBe("prompt");
    expect(decideWritePolicy("/home/user/.bashrc", allowWrite, denyWrite, cwd)).toBe("prompt");
  });
});
