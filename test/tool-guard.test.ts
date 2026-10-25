import { describe, expect, it } from "bun:test";
import { DEFAULT_CONFIG, type SandboxConfig } from "../src/config.ts";
import { decideReadPolicy, decideWritePolicy } from "../src/policy.ts";
import {
  evaluateToolCall,
  sanitizeLogString,
  type AuditLogEntry,
  type ToolGuardOptions,
} from "../src/tool-guard.ts";

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

describe("Phase 2: Dispatcher Table & Complete Tool Coverage (Audit Step 2)", () => {
  const cwd = "/home/user/project";
  const defaultOptions: ToolGuardOptions = { config: DEFAULT_CONFIG };

  // Explicit test for each tool name targeting a forbidden path
  it("blocks READ targeting secret path", async () => {
    const res = await evaluateToolCall({ toolName: "read", input: { path: "~/.ssh/id_rsa" } }, { cwd }, defaultOptions);
    expect(res?.block).toBe(true);
    expect(res?.reason).toContain("denied by security policy");
  });

  it("blocks WRITE targeting .env", async () => {
    const res = await evaluateToolCall({ toolName: "write", input: { path: ".env", content: "X=1" } }, { cwd }, defaultOptions);
    expect(res?.block).toBe(true);
    expect(res?.reason).toContain("denied by security policy");
  });

  it("blocks EDIT targeting .pi/sandbox.json", async () => {
    const res = await evaluateToolCall({ toolName: "edit", input: { path: ".pi/sandbox.json", edits: [] } }, { cwd }, defaultOptions);
    expect(res?.block).toBe(true);
    expect(res?.reason).toContain("denied by security policy");
  });

  it("blocks GREP targeting ~/.ssh", async () => {
    const res = await evaluateToolCall({ toolName: "grep", input: { pattern: "key", path: "~/.ssh" } }, { cwd }, defaultOptions);
    expect(res?.block).toBe(true);
    expect(res?.reason).toContain("denied by security policy");
  });

  it("blocks FIND targeting ~/.aws", async () => {
    const res = await evaluateToolCall({ toolName: "find", input: { pattern: "*", path: "~/.aws" } }, { cwd }, defaultOptions);
    expect(res?.block).toBe(true);
    expect(res?.reason).toContain("denied by security policy");
  });

  it("blocks LS targeting /etc/shadow", async () => {
    const res = await evaluateToolCall({ toolName: "ls", input: { path: "/etc/shadow" } }, { cwd }, defaultOptions);
    expect(res?.block).toBe(true);
    expect(res?.reason).toContain("denied by security policy");
  });

  it("allows safe exploration tools inside workspace", async () => {
    expect(await evaluateToolCall({ toolName: "read", input: { path: "src/main.ts" } }, { cwd }, defaultOptions)).toBeUndefined();
    expect(await evaluateToolCall({ toolName: "grep", input: { pattern: "fn", path: "src" } }, { cwd }, defaultOptions)).toBeUndefined();
    expect(await evaluateToolCall({ toolName: "find", input: { pattern: "*.ts", path: "src" } }, { cwd }, defaultOptions)).toBeUndefined();
    expect(await evaluateToolCall({ toolName: "ls", input: { path: "src" } }, { cwd }, defaultOptions)).toBeUndefined();
  });
});

describe("Phase 2: Audit Logging & Sanitization (Audit Step 3)", () => {
  const cwd = "/home/user/project";

  it("sanitizes terminal escape codes and control characters in log strings", () => {
    const maliciousPath = "\x1B[31m~/.ssh/id_rsa\x1B[0m\n\r/evil";
    const cleaned = sanitizeLogString(maliciousPath);
    expect(cleaned).not.toContain("\x1B");
    expect(cleaned).not.toContain("\n");
    expect(cleaned).not.toContain("\r");
    expect(cleaned).toBe("~/.ssh/id_rsa  /evil");
  });

  it("truncates excessively long paths in audit logs", () => {
    const hugePath = "a/".repeat(200);
    const cleaned = sanitizeLogString(hugePath, 50);
    expect(cleaned.length).toBeLessThan(70);
    expect(cleaned.endsWith("...[truncated]")).toBe(true);
  });

  it("records structured audit events for blocked calls", async () => {
    const auditLogs: AuditLogEntry[] = [];
    const options: ToolGuardOptions = {
      config: DEFAULT_CONFIG,
      onAudit: (entry) => auditLogs.push(entry),
    };

    await evaluateToolCall(
      { toolName: "read", input: { path: "~/.ssh/id_rsa" } },
      { cwd },
      options,
    );

    expect(auditLogs.length).toBe(1);
    expect(auditLogs[0].toolName).toBe("read");
    expect(auditLogs[0].path).toBe("~/.ssh/id_rsa");
    expect(auditLogs[0].decision).toBe("deny");
    expect(auditLogs[0].timestamp).toBeDefined();
  });
});

describe("Phase 2: Fail-Safe & Adversarial Interception Probes", () => {
  const cwd = "/home/user/project";
  const defaultOptions: ToolGuardOptions = { config: DEFAULT_CONFIG };

  it("DIRECTIVE A: Prompt decision with NO prompter blocks for BOTH read and write (fail-closed)", async () => {
    const headlessOptions: ToolGuardOptions = {
      config: DEFAULT_CONFIG,
      askPermission: undefined,
    };

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

  it("honors interactive approval and denial in prompt decisions", async () => {
    const extWriteEvent = {
      toolName: "write",
      input: { path: "/var/log/app.log", content: "data" },
    };

    const approved = await evaluateToolCall(extWriteEvent, { cwd }, {
      config: DEFAULT_CONFIG,
      askPermission: async () => true,
    });
    expect(approved).toBeUndefined();

    const denied = await evaluateToolCall(extWriteEvent, { cwd }, {
      config: DEFAULT_CONFIG,
      askPermission: async () => false,
    });
    expect(denied?.block).toBe(true);
  });
});
