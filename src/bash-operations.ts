import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import type { BashOperations } from "@earendil-works/pi-coding-agent";
import { buildBwrapArgs, isBwrapAvailable } from "./bwrap.ts";
import type { SandboxConfig } from "./config.ts";

export interface SandboxedBashOptions {
  config: SandboxConfig;
  socketDir?: string;
  proxyPort?: number;
  socksPort?: number;
}

/**
 * Creates a sandboxed implementation of Pi's BashOperations.
 * Integrates directly with Pi's createBashTool and user_bash hook.
 */
export function createSandboxedBashOps(getOptions: () => SandboxedBashOptions): BashOperations {
  return {
    async exec(command, cwd, { onData, signal, timeout }) {
      if (!existsSync(cwd)) {
        throw new Error(`Working directory does not exist: ${cwd}`);
      }

      const { config, socketDir, proxyPort, socksPort } = getOptions();

      // If sandbox is explicitly disabled by operator, fall back to direct uncontained execution
      if (config.enabled === false) {
        return executeSubprocess("bash", ["-c", command], cwd, { onData, signal, timeout });
      }

      if (!isBwrapAvailable()) {
        throw new Error(
          "[claudelike-pisandbox] bubblewrap ('bwrap') is not installed or accessible on this system. Cannot execute commands safely.",
        );
      }

      const bwrapArgs = buildBwrapArgs({
        cwd,
        config,
        socketDir,
        proxyPort,
        socksPort,
        unshareNet: config.network?.enabled !== false,
      });

      // Execute bash inside the bubblewrap container
      const finalArgs = [...bwrapArgs, "--", "bash", "-c", command];

      return executeSubprocess("bwrap", finalArgs, cwd, { onData, signal, timeout });
    },
  };
}

/**
 * Executes a subprocess in its own process group with proper signal and timeout handling.
 */
function executeSubprocess(
  cmd: string,
  args: string[],
  cwd: string,
  {
    onData,
    signal,
    timeout,
  }: {
    onData: (data: Buffer) => void;
    signal?: AbortSignal;
    timeout?: number;
  },
): Promise<{ exitCode: number | null }> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd,
      detached: true, // Run in its own process group (-pid)
      stdio: ["ignore", "pipe", "pipe"],
    });

    let timedOut = false;
    let timeoutHandle: NodeJS.Timeout | undefined;

    if (timeout !== undefined && timeout > 0) {
      timeoutHandle = setTimeout(() => {
        timedOut = true;
        killProcessGroup(child.pid);
      }, timeout * 1000);
    }

    child.stdout?.on("data", onData);
    child.stderr?.on("data", onData);

    child.on("error", (err) => {
      if (timeoutHandle) clearTimeout(timeoutHandle);
      reject(err);
    });

    const onAbort = () => {
      killProcessGroup(child.pid);
    };

    signal?.addEventListener("abort", onAbort, { once: true });

    child.on("close", (code) => {
      if (timeoutHandle) clearTimeout(timeoutHandle);
      signal?.removeEventListener("abort", onAbort);

      if (signal?.aborted) {
        reject(new Error("aborted"));
      } else if (timedOut) {
        reject(new Error(`timeout:${timeout}`));
      } else {
        resolve({ exitCode: code });
      }
    });
  });
}

/**
 * Terminates an entire process tree using negative PID (SIGKILL).
 */
function killProcessGroup(pid: number | undefined) {
  if (!pid) return;
  try {
    process.kill(-pid, "SIGKILL");
  } catch {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // Ignore if process group already exited
    }
  }
}
