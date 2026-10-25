import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
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
 *
 * If socketDir is provided (from the Phase 4 Unix domain socket proxy),
 * transparently launches an in-container Python loopback bridge that forwards
 * local TCP port 3128 to the Unix domain socket `/run/pi-sandbox/proxy.sock`,
 * enabling curl, git, and npm inside `--unshare-net` to reach the filtering proxy.
 */
export function createSandboxedBashOps(getOptions: () => SandboxedBashOptions): BashOperations {
  return {
    async exec(command, cwd, { onData, signal, timeout }) {
      if (!existsSync(cwd)) {
        throw new Error(`Working directory does not exist: ${cwd}`);
      }

      const { config, socketDir } = getOptions();

      // If sandbox is explicitly disabled by operator, fall back to direct uncontained execution
      if (config.enabled === false) {
        return executeSubprocess("bash", ["-c", command], cwd, { onData, signal, timeout });
      }

      if (!isBwrapAvailable()) {
        throw new Error(
          "[claudelike-pisandbox] bubblewrap ('bwrap') is not installed or accessible on this system. Cannot execute commands safely.",
        );
      }

      const currentDir = dirname(fileURLToPath(import.meta.url));
      const bridgeScriptPath = join(currentDir, "proxy", "bridge.py");

      const bwrapArgs = buildBwrapArgs({
        cwd,
        config,
        socketDir,
        bridgeScriptPath,
        unshareNet: config.network?.enabled !== false,
      });

      let finalCommand = command;

      // If Unix socket proxy is mounted in /run/pi-sandbox, spin up the local loopback bridge
      if (socketDir && existsSync(socketDir) && config.network?.enabled !== false) {
        finalCommand = `python3 /run/pi-sandbox/bridge.py &
BPID=$!
sleep 0.3
export http_proxy=http://127.0.0.1:3128
export https_proxy=http://127.0.0.1:3128
export HTTP_PROXY=http://127.0.0.1:3128
export HTTPS_PROXY=http://127.0.0.1:3128
${command}
C_EXIT=$?
kill -9 $BPID 2>/dev/null || true
exit $C_EXIT
`;
      }

      const finalArgs = [...bwrapArgs, "--", "bash", "-c", finalCommand];

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
