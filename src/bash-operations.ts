import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import type { BashOperations } from "@earendil-works/pi-coding-agent";
import { buildBwrapArgs, isBwrapAvailable } from "./bwrap.ts";
import type { SandboxConfig } from "./config.ts";

export interface SandboxedBashOptions {
  config: SandboxConfig;
  socketDir?: string;
}

/**
 * Creates a sandboxed implementation of Pi's BashOperations.
 */
export function createSandboxedBashOps(getOptions: () => SandboxedBashOptions): BashOperations {
  return {
    async exec(command, cwd, { onData, signal, timeout }) {
      if (!existsSync(cwd)) {
        throw new Error(`Working directory does not exist: ${cwd}`);
      }

      const { config, socketDir } = getOptions();

      // If sandbox is disabled or bwrap is unavailable, inform operator or fail-safe
      if (config.enabled === false) {
        // Fall back to direct spawn if explicitly disabled
        return executeSubprocess("bash", ["-c", command], cwd, { onData, signal, timeout });
      }

      if (!isBwrapAvailable()) {
        throw new Error(
          "[claudelike-pisandbox] bubblewrap ('bwrap') is not installed on this system. Cannot execute commands safely.",
        );
      }

      const bwrapArgs = buildBwrapArgs({
        cwd,
        config,
        socketDir,
        unshareNet: config.network?.enabled !== false,
      });

      // Pass command to bash inside bwrap
      const finalArgs = [...bwrapArgs, "--", "bash", "-c", command];

      return executeSubprocess("bwrap", finalArgs, cwd, { onData, signal, timeout });
    },
  };
}

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
      detached: true, // Run in its own process group
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

function killProcessGroup(pid: number | undefined) {
  if (!pid) return;
  try {
    process.kill(-pid, "SIGKILL");
  } catch {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // ignore
    }
  }
}
