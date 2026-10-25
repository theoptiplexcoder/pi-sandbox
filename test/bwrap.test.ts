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

  it("builds hardened bubblewrap argument flags", () => {
    const args = buildBwrapArgs({
      cwd,
      config: DEFAULT_CONFIG,
      unshareNet: true,
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

    // 4. Mask host sockets and daemon runtime (/run, /var/run/docker.sock)
    expect(args).toContain("/run");

    // 5. Hardened process isolation
    expect(args).toContain("--new-session");
    expect(args).toContain("--unshare-pid");
    expect(args).toContain("--die-with-parent");

    // 6. Environment scrubbed via --clearenv
    expect(args).toContain("--clearenv");

    // 7. Network unshared
    expect(args).toContain("--unshare-net");

    // 8. Secret masking
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

  it("AUDIT FINDING A: recursively protects nested secrets (e.g. backend/.env)", async () => {
    if (!bwrapAvailable) return;

    const testDir = join(tmpdir(), `pi-sandbox-test-nested-${Date.now()}`);
    const nestedDir = join(testDir, "services", "backend");
    mkdirSync(nestedDir, { recursive: true });
    writeFileSync(join(nestedDir, ".env"), "API_KEY=VERY_SECRET_KEY");

    let stderr = "";
    const ops = createSandboxedBashOps(() => ({ config: DEFAULT_CONFIG }));

    // Command attempts to overwrite nested .env
    const res = await ops.exec("echo 'HAX' > services/backend/.env 2>&1", testDir, {
      onData: (d) => {
        stderr += d.toString();
      },
    });

    expect(res.exitCode).not.toBe(0);
    expect(stderr.toLowerCase()).toContain("read-only file system");

    // File content remains unaltered
    expect(readFileSync(join(nestedDir, ".env"), "utf-8")).toBe("API_KEY=VERY_SECRET_KEY");

    rmSync(testDir, { recursive: true, force: true });
  });

  it("AUDIT FINDING D: protects .git/hooks and .git/config from agent persistence attacks", async () => {
    if (!bwrapAvailable) return;

    const testDir = join(tmpdir(), `pi-sandbox-test-git-${Date.now()}`);
    const hooksDir = join(testDir, ".git", "hooks");
    mkdirSync(hooksDir, { recursive: true });
    writeFileSync(join(testDir, ".git", "config"), "[core]\n\trepositoryformatversion = 0");

    let stderr = "";
    const ops = createSandboxedBashOps(() => ({ config: DEFAULT_CONFIG }));

    // Attacker script attempts to implant a malicious pre-commit hook to escape sandbox on next host commit
    const res = await ops.exec("echo 'malicious script' > .git/hooks/pre-commit 2>&1", testDir, {
      onData: (d) => {
        stderr += d.toString();
      },
    });

    expect(res.exitCode).not.toBe(0);
    expect(stderr.toLowerCase()).toContain("read-only file system");

    rmSync(testDir, { recursive: true, force: true });
  });

  it("AUDIT HARDENING: scrubs host environment variables (e.g. GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY)", async () => {
    if (!bwrapAvailable) return;

    const testDir = join(tmpdir(), `pi-sandbox-test-env-scrub-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    // Inject temporary secret into host process.env for this test
    process.env.GITHUB_TOKEN = "ghp_super_secret_host_token_12345";
    process.env.AWS_SECRET_ACCESS_KEY = "aws_secret_key_67890";

    let stdout = "";
    const ops = createSandboxedBashOps(() => ({ config: DEFAULT_CONFIG }));

    const res = await ops.exec("echo GITHUB_TOKEN=$GITHUB_TOKEN; echo AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY", testDir, {
      onData: (d) => {
        stdout += d.toString();
      },
    });

    expect(res.exitCode).toBe(0);
    // Values must be completely blank inside the container
    expect(stdout).toContain("GITHUB_TOKEN=");
    expect(stdout).not.toContain("ghp_super_secret_host_token_12345");
    expect(stdout).not.toContain("aws_secret_key_67890");

    delete process.env.GITHUB_TOKEN;
    delete process.env.AWS_SECRET_ACCESS_KEY;

    rmSync(testDir, { recursive: true, force: true });
  });

  it("AUDIT HARDENING: masks host IPC sockets and docker.sock via /run tmpfs", async () => {
    if (!bwrapAvailable) return;

    const testDir = join(tmpdir(), `pi-sandbox-test-sockets-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    let stdout = "";
    const ops = createSandboxedBashOps(() => ({ config: DEFAULT_CONFIG }));

    // Attempt to access host docker socket or run user directory
    const res = await ops.exec("ls /run/docker.sock 2>&1; ls /var/run/docker.sock 2>&1", testDir, {
      onData: (d) => {
        stdout += d.toString();
      },
    });

    expect(res.exitCode).not.toBe(0);
    expect(stdout.toLowerCase()).toContain("no such file or directory");

    rmSync(testDir, { recursive: true, force: true });
  });

  it("isolates network namespace: raw socket access fails immediately", async () => {
    if (!bwrapAvailable) return;

    const testDir = join(tmpdir(), `pi-sandbox-test-net-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    let stderr = "";
    const ops = createSandboxedBashOps(() => ({ config: DEFAULT_CONFIG }));

    const res = await ops.exec("curl --connect-timeout 2 -I https://github.com 2>&1", testDir, {
      onData: (d) => {
        stderr += d.toString();
      },
    });

    expect(res.exitCode).not.toBe(0);
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
      expect(true).toBe(false);
    } catch (err: any) {
      expect(err.message).toBe("aborted");
      expect(Date.now() - start).toBeLessThan(1000);
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
        timeout: 1,
      });
      expect(true).toBe(false);
    } catch (err: any) {
      expect(err.message).toBe("timeout:1");
      expect(Date.now() - start).toBeLessThan(2000);
    }

    rmSync(testDir, { recursive: true, force: true });
  });
});
