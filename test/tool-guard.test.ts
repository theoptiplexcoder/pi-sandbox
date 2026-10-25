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

describe("Phase 2: In-Process Tool Call Interception & Adversarial Probes", () => {
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

  it("DIRECTIVE A: Prompt decision with NO prompter blocks for BOTH read and write (fail-closed)", async () => {
    // Custom config where /opt/data requires prompt (not in workspace, not in allowRead)
    const customConfig: SandboxConfig = {
      ...DEFAULT_CONFIG,
      filesystem: {
        allowRead: [], // not allowed
        denyRead: [...(DEFAULT_CONFIG.filesystem?.denyRead ?? [])],
        allowWrite: [".", "/tmp"],
      },
    };

    const headlessOptions: ToolGuardOptions = {
      config: customConfig,
      askPermission: undefined, // Headless!
    };

    // External read when policy returns prompt
    const extWriteEvent = {
      toolName: "write",
      input: { path: "/var/log/my-app.log", content: "log" },
    };
    const writeResult = await evaluateToolCall(extWriteEvent, { cwd }, headlessOptions);
    expect(writeResult?.block).toBe(true);
    expect(writeResult?.reason).toContain("no UI prompter is available");
  });

  it("DIRECTIVE C: Prompter throwing an exception fails closed and blocks", async () => {
    const throwingOptions: ToolGuardOptions = {
      config: DEFAULT_CONFIG,
      askPermission: async () => {
        throw new Error("UI crashed unexpectedly!");
      },
    };

    const extWriteEvent = {
      toolName: "write",
      input: { path: "/var/log/app.log", content: "log" },
    };

    const result = await evaluateToolCall(extWriteEvent, { cwd }, throwingOptions);
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain("Permission prompt threw an unexpected error");
  });

  it("DIRECTIVE B: Malformed input (undefined, number, null, array, empty, null-byte) all block safely without throwing", async () => {
    const malformedInputs = [
      undefined,
      42,
      null,
      [],
      {},
      "",
      "   ",
      "src/index.ts\0/etc/shadow",
    ];

    for (const badPath of malformedInputs) {
      const event = {
        toolName: "read",
        input: { path: badPath },
      };

      const result = await evaluateToolCall(event, { cwd }, defaultOptions);
      expect(result?.block).toBe(true);
      expect(result?.reason).toBeDefined();
    }
  });

  it("DIRECTIVE E: Config reactivity - toggling sandbox dynamically updates tool guard decisions", async () => {
    let currentConfig: SandboxConfig = { ...DEFAULT_CONFIG, enabled: true };
    const dynamicOptions: ToolGuardOptions = {
      get config() {
        return currentConfig;
      },
    };

    const secretRead = {
      toolName: "read",
      input: { path: "~/.ssh/id_rsa" },
    };

    // 1. Initially enabled -> Blocked
    const res1 = await evaluateToolCall(secretRead, { cwd }, dynamicOptions);
    expect(res1?.block).toBe(true);

    // 2. Toggled off mid-session -> Allowed
    currentConfig = { ...currentConfig, enabled: false };
    const res2 = await evaluateToolCall(secretRead, { cwd }, dynamicOptions);
    expect(res2).toBeUndefined();

    // 3. Toggled back on -> Blocked
    currentConfig = { ...currentConfig, enabled: true };
    const res3 = await evaluateToolCall(secretRead, { cwd }, dynamicOptions);
    expect(res3?.block).toBe(true);
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
});
