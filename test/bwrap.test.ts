import { describe, expect, it } from "bun:test";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createSandboxedBashOps } from "../src/bash-operations.ts";
import {
  buildBwrapArgs,
  buildGitProtectionMounts,
  isBwrapAvailable,
  resolveGitDirectory,
} from "../src/bwrap.ts";
import { DEFAULT_CONFIG, type SandboxConfig } from "../src/config.ts";

describe("Phase 3: Bubblewrap Subprocess Containment Unit Tests", () => {
  const cwd = process.cwd();

  it("detects bwrap installation", () => {
    expect(isBwrapAvailable()).toBe(true);
  });

  it("builds hardened bubblewrap argument flags with tmpfs capping", () => {
    const args = buildBwrapArgs({
      cwd,
      config: DEFAULT_CONFIG,
      unshareNet: true,
      tmpfsBytes: 268435456, // 256MB cap
    });

    // 1. Root read-only
    expect(args).toContain("--ro-bind");
    expect(args).toContain("/");

    // 2. CWD writable
    expect(args).toContain("--bind");
    expect(args).toContain(cwd);

    // 3. Ephemeral tmp with size limit
    expect(args).toContain("--size");
    expect(args).toContain("268435456");
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

  it("resolves git directory for standard repos and worktrees", () => {
    const tempDir = join(tmpdir(), `pi-sandbox-gitdir-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });

    // Standard repo
    const standardRepo = join(tempDir, "standard");
    mkdirSync(join(standardRepo, ".git"), { recursive: true });
    expect(resolveGitDirectory(standardRepo)).toBe(join(standardRepo, ".git"));

    // Worktree pointer file
    const worktreeRepo = join(tempDir, "worktree");
    mkdirSync(worktreeRepo, { recursive: true });
    writeFileSync(join(worktreeRepo, ".git"), "gitdir: ../standard/.git/worktrees/wt1");
    expect(resolveGitDirectory(worktreeRepo)).toBe(resolve(worktreeRepo, "../standard/.git/worktrees/wt1"));

    rmSync(tempDir, { recursive: true, force: true });
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

    const res = await ops.exec("echo 'HAX' > services/backend/.env 2>&1", testDir, {
      onData: (d) => {
        stderr += d.toString();
      },
    });

    expect(res.exitCode).not.toBe(0);
    expect(stderr.toLowerCase()).toContain("read-only file system");
    expect(readFileSync(join(nestedDir, ".env"), "utf-8")).toBe("API_KEY=VERY_SECRET_KEY");

    rmSync(testDir, { recursive: true, force: true });
  });

  it("AUDIT FINDING D: protects .git/hooks and .git/config (pre-creates hooks dir so mkdir fails)", async () => {
    if (!bwrapAvailable) return;

    const testDir = join(tmpdir(), `pi-sandbox-test-git-${Date.now()}`);
    const gitDir = join(testDir, ".git");
    mkdirSync(gitDir, { recursive: true });
    // Intentionally do NOT create hooks directory on host beforehand
    writeFileSync(join(gitDir, "config"), "[core]\n\trepositoryformatversion = 0");

    let stderr = "";
    const ops = createSandboxedBashOps(() => ({ config: DEFAULT_CONFIG }));

    // Attacker attempts to mkdir .git/hooks or write a hook inside sandbox
    const res = await ops.exec("echo 'malicious script' > .git/hooks/pre-commit 2>&1", testDir, {
      onData: (d) => {
        stderr += d.toString();
      },
    });

    expect(res.exitCode).not.toBe(0);
    expect(stderr.toLowerCase()).toContain("read-only file system");

    rmSync(testDir, { recursive: true, force: true });
  });

  it("AUDIT HARDENING: git worktree protection resolves real gitdir and protects its hooks", async () => {
    if (!bwrapAvailable) return;

    const testDir = join(tmpdir(), `pi-sandbox-worktree-test-${Date.now()}`);
    const mainRepoGit = join(testDir, "main-repo", ".git");
    const worktreeDir = join(testDir, "worktree-1");
    const wtGitDir = join(mainRepoGit, "worktrees", "worktree-1");

    mkdirSync(wtGitDir, { recursive: true });
    mkdirSync(worktreeDir, { recursive: true });

    // Create gitdir pointer file in worktree
    writeFileSync(join(worktreeDir, ".git"), `gitdir: ${wtGitDir}`);
    writeFileSync(join(wtGitDir, "config"), "[core]\n\tworktree = true");

    let stderr = "";
    const ops = createSandboxedBashOps(() => ({ config: DEFAULT_CONFIG }));

    // Inside worktree, attempting to modify git hooks must fail
    const res = await ops.exec(`echo 'evil' > "${wtGitDir}/hooks/pre-commit" 2>&1`, worktreeDir, {
      onData: (d) => {
        stderr += d.toString();
      },
    });

    expect(res.exitCode).not.toBe(0);
    expect(stderr.toLowerCase()).toContain("read-only file system");

    rmSync(testDir, { recursive: true, force: true });
  });

  it("AUDIT HARDENING: terminal isolation with --new-session detaches controlling tty", async () => {
    if (!bwrapAvailable) return;

    const testDir = join(tmpdir(), `pi-sandbox-test-tty-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    let output = "";
    const ops = createSandboxedBashOps(() => ({ config: DEFAULT_CONFIG }));

    // Inside a new session without controlling terminal, opening /dev/tty directly fails with ENXIO
    const res = await ops.exec("cat /dev/tty 2>&1", testDir, {
      onData: (d) => {
        output += d.toString();
      },
    });

    expect(res.exitCode).not.toBe(0);
    expect(output.toLowerCase()).toMatch(/no such device or address|not a tty|cannot open/i);

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
