import { describe, expect, it } from "bun:test";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import activate, { saveProjectGrant } from "../index.ts";
import { promptPermission } from "../src/ui.ts";

describe("Phase 5: UI & Interactive Permission Prompting", () => {
  it("fails closed in headless / non-interactive context (hasUI === false)", async () => {
    const headlessCtx: any = {
      hasUI: false,
      ui: null,
    };

    const decision = await promptPermission(headlessCtx, "Write Request", "/var/log/app.log");
    expect(decision).toBe("abort");
  });

  it("sanitizes target and title against terminal injection", async () => {
    let capturedPrompt = "";
    const mockCtx: any = {
      hasUI: true,
      ui: {
        select: async (message: string, _options: string[]) => {
          capturedPrompt = message;
          return "Deny (Abort)";
        },
      },
    };

    const maliciousHost = "\x1B[31mevil.com\x1B[0m\n\r/secret";
    const decision = await promptPermission(mockCtx, "Network Request", maliciousHost);

    expect(decision).toBe("abort");
    expect(capturedPrompt).not.toContain("\x1B");
    expect(capturedPrompt).not.toContain("\nTarget: evil.com\x1B");
    expect(capturedPrompt).toContain("evil.com  /secret");
  });

  it("returns 'session' when operator approves for session", async () => {
    const mockCtx: any = {
      hasUI: true,
      ui: {
        select: async (_msg: string, options: string[]) => {
          return options[0]; // "Allow for this session"
        },
      },
    };

    const decision = await promptPermission(mockCtx, "Write Request", "/var/log/my-app");
    expect(decision).toBe("session");
  });

  it("returns 'project' when operator approves and saves to project", async () => {
    const mockCtx: any = {
      hasUI: true,
      ui: {
        select: async (_msg: string, options: string[]) => {
          return options[1]; // "Allow and save to project (.pi/sandbox.json)"
        },
      },
    };

    const decision = await promptPermission(mockCtx, "Network Request", "api.stripe.com");
    expect(decision).toBe("project");
  });
});

describe("Phase 5: Project-Local Grant Persistence", () => {
  it("persists domain and write path grants to .pi/sandbox.json cleanly", () => {
    const testDir = join(tmpdir(), `pi-sandbox-grant-test-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    saveProjectGrant(testDir, "domain", "api.stripe.com");
    saveProjectGrant(testDir, "writePath", "/var/log/my-app");

    const configPath = join(testDir, ".pi", "sandbox.json");
    expect(existsSync(configPath)).toBe(true);

    const saved = JSON.parse(readFileSync(configPath, "utf-8"));
    expect(saved.network?.allowedDomains).toContain("api.stripe.com");
    expect(saved.filesystem?.allowWrite).toContain("/var/log/my-app");

    rmSync(testDir, { recursive: true, force: true });
  });
});

describe("Phase 5: Extension Lifecycle & Registration Integration", () => {
  it("registers tools, commands, and hooks on activate() without errors", () => {
    const registeredTools: any[] = [];
    const registeredCommands: Record<string, any> = {};
    const registeredHooks: Record<string, any[]> = {};

    const mockPi: any = {
      registerTool: (tool: any) => registeredTools.push(tool),
      registerCommand: (name: string, def: any) => {
        registeredCommands[name] = def;
      },
      on: (event: string, handler: any) => {
        if (!registeredHooks[event]) registeredHooks[event] = [];
        registeredHooks[event].push(handler);
      },
    };

    // Activate extension
    activate(mockPi);

    // Verify bash tool replacement
    expect(registeredTools.length).toBe(1);
    expect(registeredTools[0].label).toContain("bash (sandboxed)");

    // Verify registered commands
    expect(registeredCommands["sandbox"]).toBeDefined();
    expect(registeredCommands["sandbox-toggle"]).toBeDefined();

    // Verify hooks registered
    expect(registeredHooks["tool_call"]).toBeDefined();
    expect(registeredHooks["user_bash"]).toBeDefined();
    expect(registeredHooks["session_start"]).toBeDefined();
    expect(registeredHooks["session_shutdown"]).toBeDefined();
  });
});
