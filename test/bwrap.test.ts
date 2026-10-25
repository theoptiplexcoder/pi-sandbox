import { describe, expect, it } from "bun:test";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { createSandboxedBashOps } from "../src/bash-operations.ts";
import { buildBwrapArgs, isBwrapAvailable } from "../src/bwrap.ts";
import { DEFAULT_CONFIG, type SandboxConfig } from "../src/config.ts";

describe("Phase 3: Bubblewrap Subprocess Containment Unit Tests", () => {
  const cwd = process.cwd();

  it("detects bwrap installation", () => {
    expect(isBwrapAvailable()).toBe(true);
  });

  it("builds strict bubblewrap argument flags", () => {
    const args = buildBwrapArgs({
      cwd,
      config: DEFAULT_CONFIG,
      unshareNet: true,
      proxyPort: 8080,
    });

    // 1. Root read-only
    expect(args).toContain("--ro-bind");
    expect(args).toContain("/");

    // 2. CWD writable
    expect(args).toContain("--bind");
    expect(args).toContain(cwd);

    // 3. Ephemeral tmp
    expect(args).toContain("--tmpfs");
    expect(args).toContain("/tmp");

    // 4. Network unshared
    expect(args).toContain("--unshare-net");

    // 5. Proxy environment variables
    expect(args).toContain("--setenv");
    expect(args).toContain("http_proxy");

    // 6. Process die with parent
    expect(args).toContain("--die-with-parent");

    // 7. Secret masking
    const sshDir = `${homedir()}/.ssh`;
    const sshIndex = args.indexOf(sshDir);
    if (sshIndex !== -1) {
      expect(args[sshIndex - 1]).toBe("--tmpfs");
    }
  });
});

describe("Phase 3: Live OS Kernel Enforcement & Functional Containment", () => {
  const bwrapAvailable = isBwrapAvailable();

  it("executes safe commands and writes successfully inside workspace CWD", async () => {
    if (!bwrapAvailable) return;

    const testDir = join(tmpdir(), `pi-sandbox-test-cwd-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    let stdout = "";
    const ops = createSandboxedBashOps(() => ({ config: DEFAULT_CONFIG }));

    const res = await ops.exec("echo 'hello from sandbox' > test.txt && cat test.txt", testDir, {
      onData: (d) => {
        stdout += d.toString();
      },
    });

    expect(res.exitCode).toBe(0);
    expect(stdout).toContain("hello from sandbox");
    expect(readFileSync(join(testDir, "test.txt"), "utf-8")).toContain("hello from sandbox");

    rmSync(testDir, { recursive: true, force: true });
  });

  it("fails kernel write attempts to root /etc filesystem (read-only filesystem error)", async () => {
    if (!bwrapAvailable) return;

    const testDir = join(tmpdir(), `pi-sandbox-test-ro-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    let stderr = "";
    const ops = createSandboxedBashOps(() => ({ config: DEFAULT_CONFIG }));

    const res = await ops.exec("touch /etc/evil-test-file.tmp 2>&1", testDir, {
      onData: (d) => {
        stderr += d.toString();
      },
    });

    expect(res.exitCode).not.toBe(0);
    expect(stderr.toLowerCase()).toContain("read-only file system");

    rmSync(testDir, { recursive: true, force: true });
  });

  it("shadows ~/.ssh directory: appears empty inside bwrap even when host has keys", async () => {
    if (!bwrapAvailable) return;

    const testDir = join(tmpdir(), `pi-sandbox-test-ssh-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    let output = "";
    const ops = createSandboxedBashOps(() => ({ config: DEFAULT_CONFIG }));

    const res = await ops.exec("ls -A ~/.ssh", testDir, {
      onData: (d) => {
        output += d.toString();
      },
    });

    expect(res.exitCode).toBe(0);
    // Inside the empty tmpfs, listing ~/.ssh must yield zero files!
    expect(output.trim()).toBe("");

    rmSync(testDir, { recursive: true, force: true });
  });

  it("protects existing .env files in CWD by remounting read-only", async () => {
    if (!bwrapAvailable) return;

    const testDir = join(tmpdir(), `pi-sandbox-test-env-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });
    writeFileSync(join(testDir, ".env"), "SECRET=ORIGINAL_KEY");

    let stderr = "";
    const ops = createSandboxedBashOps(() => ({ config: DEFAULT_CONFIG }));

    // Command attempts to overwrite .env
    const res = await ops.exec("echo 'OVERWRITTEN' > .env 2>&1", testDir, {
      onData: (d) => {
        stderr += d.toString();
      },
    });

    expect(res.exitCode).not.toBe(0);
    expect(stderr.toLowerCase()).toContain("read-only file system");

    // File content remains unchanged
    expect(readFileSync(join(testDir, ".env"), "utf-8")).toBe("SECRET=ORIGINAL_KEY");

    rmSync(testDir, { recursive: true, force: true });
  });

  it("isolates network namespace: raw socket access fails immediately", async () => {
    if (!bwrapAvailable) return;

    const testDir = join(tmpdir(), `pi-sandbox-test-net-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    let stderr = "";
    const ops = createSandboxedBashOps(() => ({ config: DEFAULT_CONFIG }));

    // In unshared net namespace with no interface up, DNS or IP connection immediately fails
    const res = await ops.exec("curl --connect-timeout 2 -I https://github.com 2>&1", testDir, {
      onData: (d) => {
        stderr += d.toString();
      },
    });

    expect(res.exitCode).not.toBe(0);
    // Curl returns Could not resolve host or Network unreachable
    expect(stderr).toMatch(/Could not resolve host|Network is unreachable|Failed to connect/i);

    rmSync(testDir, { recursive: true, force: true });
  });

  it("terminates process group on abort signal", async () => {
    if (!bwrapAvailable) return;

    const testDir = join(tmpdir(), `pi-sandbox-test-abort-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    const controller = new AbortController();
    const ops = createSandboxedBashOps(() => ({ config: DEFAULT_CONFIG }));

    // Schedule abort after 100ms
    setTimeout(() => controller.abort(), 100);

    const start = Date.now();
    try {
      await ops.exec("sleep 10", testDir, {
        onData: () => {},
        signal: controller.signal,
      });
      expect(true).toBe(false); // Should not reach here
    } catch (err: any) {
      expect(err.message).toBe("aborted");
      expect(Date.now() - start).toBeLessThan(1000); // Exited promptly
    }

    rmSync(testDir, { recursive: true, force: true });
  });

  it("terminates process group on execution timeout", async () => {
    if (!bwrapAvailable) return;

    const testDir = join(tmpdir(), `pi-sandbox-test-timeout-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    const ops = createSandboxedBashOps(() => ({ config: DEFAULT_CONFIG }));

    const start = Date.now();
    try {
      await ops.exec("sleep 10", testDir, {
        onData: () => {},
        timeout: 1, // 1 second timeout
      });
      expect(true).toBe(false); // Should not reach here
    } catch (err: any) {
      expect(err.message).toBe("timeout:1");
      expect(Date.now() - start).toBeLessThan(2000); // Exited promptly
    }

    rmSync(testDir, { recursive: true, force: true });
  });
});
