import { describe, expect, it } from "bun:test";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import activate, { saveProjectGrant } from "../index.ts";
import { sweepStaleSocketDirs } from "../src/proxy/proxy-server.ts";
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
    expect(capturedPrompt).toContain("evil.com  /secret");
  });

  it("AUDIT FINDING 2: omits 'Allow and save to project' option for protected secrets", async () => {
    let capturedOptions: string[] = [];
    const mockCtx: any = {
      hasUI: true,
      cwd: "/home/user/project",
      ui: {
        select: async (_message: string, options: string[]) => {
          capturedOptions = options;
          return "Deny (Abort)";
        },
      },
    };

    // 1. Target is a secret path (.env)
    await promptPermission(mockCtx, "Secret Access", ".env");
    expect(capturedOptions).toContain("3. Only for now (allow to run once in this session)");
    expect(capturedOptions).toContain("4. Deny (Abort)");
    expect(capturedOptions).not.toContain("2. Only this time (save to project .pi/sandbox.json)");
    expect(capturedOptions).not.toContain("1. Always yes (save to global configuration)");

    // 2. Target is safe non-secret path (/var/log/my-app)
    await promptPermission(mockCtx, "Directory Access", "/var/log/my-app");
    expect(capturedOptions).toContain("1. Always yes (save to global configuration)");
    expect(capturedOptions).toContain("2. Only this time (save to project .pi/sandbox.json)");
  });

  it("returns 'always' when operator chooses always yes", async () => {
    const mockCtx: any = {
      hasUI: true,
      ui: {
        select: async (_msg: string, options: string[]) => {
          return options[0]; // "1. Always yes..."
        },
      },
    };

    const decision = await promptPermission(mockCtx, "Write Request", "/var/log/my-app");
    expect(decision).toBe("always");
  });

  it("returns 'project' when operator approves and saves to project", async () => {
    const mockCtx: any = {
      hasUI: true,
      ui: {
        select: async (_msg: string, options: string[]) => {
          return options[1]; // "2. Only this time..."
        },
      },
    };

    const decision = await promptPermission(mockCtx, "Network Request", "api.stripe.com");
    expect(decision).toBe("project");
  });

  it("returns 'session' when operator approves for session only", async () => {
    const mockCtx: any = {
      hasUI: true,
      ui: {
        select: async (_msg: string, options: string[]) => {
          return options[2]; // "3. Only for now..."
        },
      },
    };

    const decision = await promptPermission(mockCtx, "Write Request", "/var/log/my-app");
    expect(decision).toBe("session");
  });
});

describe("Phase 5: Project-Local Grant Persistence & Validation", () => {
  it("persists domain and write path grants to .pi/sandbox.json atomically", () => {
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

  it("rejects persisting grants targeting protected secrets", () => {
    const testDir = join(tmpdir(), `pi-sandbox-reject-secret-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    expect(() => {
      saveProjectGrant(testDir, "writePath", ".env");
    }).toThrow("Cannot save protected secret");

    expect(() => {
      saveProjectGrant(testDir, "writePath", "~/.ssh/id_rsa");
    }).toThrow("Cannot save protected secret");

    rmSync(testDir, { recursive: true, force: true });
  });
});

describe("Phase 5: Startup Socket Sweep & Dead Process Recovery", () => {
  it("cleans up stale socket directories belonging to dead PIDs while preserving live PIDs", () => {
    const testBaseDir = join(tmpdir(), `pi-sandbox-sweep-test-${Date.now()}`);
    mkdirSync(testBaseDir, { recursive: true });

    // 1. Directory with a dead PID (e.g. 9999999)
    const deadDir = join(testBaseDir, "proxy-pid-9999999-12345678-abc");
    mkdirSync(deadDir, { recursive: true });

    // 2. Directory with the current live PID
    const liveDir = join(testBaseDir, `proxy-pid-${process.pid}-12345678-xyz`);
    mkdirSync(liveDir, { recursive: true });

    // Run sweep
    sweepStaleSocketDirs(testBaseDir);

    // Dead PID dir should be removed
    expect(existsSync(deadDir)).toBe(false);
    // Current live PID dir must be preserved
    expect(existsSync(liveDir)).toBe(true);

    rmSync(testBaseDir, { recursive: true, force: true });
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

    activate(mockPi);

    expect(registeredTools.length).toBe(1);
    expect(registeredTools[0].label).toContain("bash (sandboxed)");

    expect(registeredCommands["sandbox"]).toBeDefined();
    expect(registeredCommands["sandbox-toggle"]).toBeDefined();

    expect(registeredHooks["tool_call"]).toBeDefined();
    expect(registeredHooks["user_bash"]).toBeDefined();
    expect(registeredHooks["session_start"]).toBeDefined();
    expect(registeredHooks["session_shutdown"]).toBeDefined();
  });
});
