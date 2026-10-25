import { describe, expect, it } from "bun:test";
import { DEFAULT_CONFIG, type SandboxConfig } from "../src/config.ts";
import { decideReadPolicy, decideWritePolicy } from "../src/policy.ts";
import { evaluateToolCall, type ToolGuardOptions } from "../src/tool-guard.ts";

describe("Phase 2: In-Process Tool Guard Policy Tests", () => {
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
    // /etc is in mandatory denyWrite, so it denies
    expect(decideWritePolicy("/etc/cron.d/job", allowWrite, denyWrite, cwd)).toBe("deny");
    // Writing outside workspace to non-system file requires prompt
    expect(decideWritePolicy("/var/log/my-custom-app.log", allowWrite, denyWrite, cwd)).toBe("prompt");
    expect(decideWritePolicy("/home/user/.bashrc", allowWrite, denyWrite, cwd)).toBe("prompt");
  });
});

describe("Phase 2: In-Process Tool Call Interception & Fail-Safe Verification", () => {
  const cwd = "/home/user/project";

  const defaultOptions: ToolGuardOptions = {
    config: DEFAULT_CONFIG,
  };

  it("blocks READ tool calls targeting secrets", async () => {
    const event = {
      toolName: "read",
      input: { path: "~/.ssh/id_rsa" },
    };

    const result = await evaluateToolCall(event, { cwd }, defaultOptions);
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain("denied by security policy");
  });

  it("blocks WRITE tool calls targeting .env", async () => {
    const event = {
      toolName: "write",
      input: { path: ".env", content: "SECRET=123" },
    };

    const result = await evaluateToolCall(event, { cwd }, defaultOptions);
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain("denied by security policy");
  });

  it("blocks EDIT tool calls targeting .pi/sandbox.json (self-tampering prevention)", async () => {
    const event = {
      toolName: "edit",
      input: { path: ".pi/sandbox.json", edits: [] },
    };

    const result = await evaluateToolCall(event, { cwd }, defaultOptions);
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain("denied by security policy");
  });

  it("allows valid tool calls inside project workspace", async () => {
    const readEvent = {
      toolName: "read",
      input: { path: "src/main.ts" },
    };
    const readResult = await evaluateToolCall(readEvent, { cwd }, defaultOptions);
    expect(readResult).toBeUndefined(); // Allowed

    const writeEvent = {
      toolName: "write",
      input: { path: "src/main.ts", content: "console.log('ok');" },
    };
    const writeResult = await evaluateToolCall(writeEvent, { cwd }, defaultOptions);
    expect(writeResult).toBeUndefined(); // Allowed
  });

  it("blocks invalid/empty path parameters fail-closed", async () => {
    const invalidEvent = {
      toolName: "read",
      input: { path: "" },
    };
    const result = await evaluateToolCall(invalidEvent, { cwd }, defaultOptions);
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain("Invalid or empty path");
  });

  it("blocks external write in non-interactive mode without prompting", async () => {
    const externalWriteEvent = {
      toolName: "write",
      input: { path: "/var/log/app.log", content: "data" },
    };

    // No askPermission callback provided (headless/non-interactive)
    const result = await evaluateToolCall(externalWriteEvent, { cwd }, defaultOptions);
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain("requires explicit user approval");
  });

  it("honors interactive approval when askPermission returns true", async () => {
    const externalWriteEvent = {
      toolName: "write",
      input: { path: "/var/log/app.log", content: "data" },
    };

    const interactiveOptions: ToolGuardOptions = {
      config: DEFAULT_CONFIG,
      askPermission: async (_msg, _path) => true, // User approves
    };

    const result = await evaluateToolCall(externalWriteEvent, { cwd }, interactiveOptions);
    expect(result).toBeUndefined(); // Allowed through user approval
  });

  it("honors interactive denial when askPermission returns false", async () => {
    const externalWriteEvent = {
      toolName: "write",
      input: { path: "/var/log/app.log", content: "data" },
    };

    const interactiveOptions: ToolGuardOptions = {
      config: DEFAULT_CONFIG,
      askPermission: async (_msg, _path) => false, // User denies
    };

    const result = await evaluateToolCall(externalWriteEvent, { cwd }, interactiveOptions);
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain("User denied permission");
  });

  it("bypasses guard completely when sandbox is disabled by operator", async () => {
    const disabledOptions: ToolGuardOptions = {
      config: { ...DEFAULT_CONFIG, enabled: false },
    };

    const secretReadEvent = {
      toolName: "read",
      input: { path: "~/.ssh/id_rsa" },
    };

    const result = await evaluateToolCall(secretReadEvent, { cwd }, disabledOptions);
    expect(result).toBeUndefined(); // Allowed because sandbox is explicitly disabled
  });
});
