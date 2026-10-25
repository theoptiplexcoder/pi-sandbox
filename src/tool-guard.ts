import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import type { FilesystemConfig, SandboxConfig } from "./config.ts";
import { decideReadPolicy, decideWritePolicy, type FilePolicyDecision } from "./policy.ts";

/**
 * Options provided to the in-process tool guard.
 */
export interface ToolGuardOptions {
  /**
   * The active sandbox configuration.
   */
  config: SandboxConfig;
  /**
   * Interactive permission prompt callback.
   * If omitted or in non-interactive / headless mode, decisions requiring 'prompt' fail-closed to block.
   */
  askPermission?: (message: string, path: string) => Promise<boolean>;
  /**
   * Optional custom audit logger callback (for telemetry or testing).
   */
  onAudit?: (entry: AuditLogEntry) => void;
}

/**
 * Structured audit log entry.
 */
export interface AuditLogEntry {
  timestamp: string;
  toolName: string;
  path: string;
  decision: "deny" | "prompt_blocked" | "prompt_approved" | "error";
  reason: string;
}

/**
 * Result returned to Pi when blocking a tool call.
 */
export interface ToolBlockResult {
  block: boolean;
  reason?: string;
  terminate?: boolean;
}

/**
 * Sanitizes and truncates attacker-controlled path strings before writing to logs.
 * Strips ASCII/ANSI escape codes, replaces control characters (like newlines)
 * and truncates to 200 characters to prevent log injection or terminal corruption.
 */
export function sanitizeLogString(str: string, maxLength: number = 200): string {
  // Strip ANSI escape sequences and non-printable control characters
  const clean = str
    .replace(/\x1B\[[0-9;]*[a-zA-Z]/g, "") // ANSI escape codes
    .replace(/[\x00-\x1F\x7F-\x9F]/g, " ") // Control characters including \n, \r, \t, \0
    .trim();

  if (clean.length > maxLength) {
    return clean.slice(0, maxLength) + "...[truncated]";
  }
  return clean;
}

/**
 * Logs security audit events (blocks, prompts, and security exceptions).
 * Only logs blocks and prompts (never allowed routine operations) to avoid log noise.
 */
function recordAudit(
  entry: AuditLogEntry,
  onAudit?: (entry: AuditLogEntry) => void,
): void {
  if (onAudit) {
    try {
      onAudit(entry);
    } catch {
      // Ignore consumer audit logger crashes
    }
  }

  // Always output structured security notice to stderr
  const safePath = sanitizeLogString(entry.path);
  const safeReason = sanitizeLogString(entry.reason);
  console.error(
    `[${entry.timestamp}] [claudelike-pisandbox] [AUDIT] [${entry.decision.toUpperCase()}] tool=${entry.toolName} path="${safePath}" reason="${safeReason}"`,
  );
}

/**
 * Table definition for guarded file-system tools.
 * Each entry defines:
 * - getPath: extracts and validates the target path from the tool input.
 * - policy: the security decision function (decideReadPolicy or decideWritePolicy).
 * - rules: selects the relevant allow/deny rules from filesystem configuration.
 */
interface GuardedToolSpec {
  policy: (path: string, allow: string[], deny: string[], cwd: string) => FilePolicyDecision;
  rules: (fs: FilesystemConfig) => { allow: string[]; deny: string[] };
  getPath: (input: unknown) => string | undefined;
}

/**
 * Guarded tools lookup table.
 * Covers all Pi built-in filesystem tools:
 * - Direct file tools: 'read', 'write', 'edit'
 * - Exploration tools: 'grep', 'find', 'ls'
 */
const GUARDED_TOOLS: Record<string, GuardedToolSpec> = {
  read: {
    policy: decideReadPolicy,
    rules: (fs) => ({ allow: fs.allowRead ?? [], deny: fs.denyRead ?? [] }),
    getPath: (input) => (input as any)?.path,
  },
  write: {
    policy: decideWritePolicy,
    rules: (fs) => ({ allow: fs.allowWrite ?? [".", "/tmp"], deny: fs.denyWrite ?? [] }),
    getPath: (input) => (input as any)?.path,
  },
  edit: {
    policy: decideWritePolicy,
    rules: (fs) => ({ allow: fs.allowWrite ?? [".", "/tmp"], deny: fs.denyWrite ?? [] }),
    getPath: (input) => (input as any)?.path,
  },
  grep: {
    policy: decideReadPolicy,
    rules: (fs) => ({ allow: fs.allowRead ?? [], deny: fs.denyRead ?? [] }),
    getPath: (input) => (input as any)?.path ?? ".",
  },
  find: {
    policy: decideReadPolicy,
    rules: (fs) => ({ allow: fs.allowRead ?? [], deny: fs.denyRead ?? [] }),
    getPath: (input) => (input as any)?.path ?? ".",
  },
  ls: {
    policy: decideReadPolicy,
    rules: (fs) => ({ allow: fs.allowRead ?? [], deny: fs.denyRead ?? [] }),
    getPath: (input) => (input as any)?.path ?? ".",
  },
};

/**
 * Validates and sanitizes an extracted path parameter.
 * Rejects non-strings, empty strings, and null-byte poison attacks.
 */
function validatePathInput(rawPath: unknown): { valid: true; path: string } | { valid: false; reason: string } {
  if (typeof rawPath !== "string") {
    return {
      valid: false,
      reason: `Invalid path parameter: expected non-empty string, got ${typeof rawPath}.`,
    };
  }

  const trimmed = rawPath.trim();
  if (trimmed.length === 0) {
    return {
      valid: false,
      reason: "Invalid path parameter: path cannot be empty.",
    };
  }

  if (trimmed.includes("\0")) {
    return {
      valid: false,
      reason: "Poison null-byte detected in path parameter.",
    };
  }

  return { valid: true, path: trimmed };
}

/**
 * Shared helper to resolve 'prompt' decisions fail-closed across all tool types.
 */
async function resolvePrompt(
  toolName: string,
  targetPath: string,
  askPermission?: (message: string, path: string) => Promise<boolean>,
  onAudit?: (entry: AuditLogEntry) => void,
): Promise<ToolBlockResult | undefined> {
  const timestamp = new Date().toISOString();

  if (!askPermission) {
    const reason = `[Security Sandbox] Operation '${toolName}' on path '${targetPath}' outside allowed boundaries requires user approval, but no UI prompter is available.`;
    recordAudit({ timestamp, toolName, path: targetPath, decision: "prompt_blocked", reason }, onAudit);
    return { block: true, reason };
  }

  try {
    const approved = await askPermission(
      `Agent is requesting '${toolName}' access to path outside workspace: ${targetPath}`,
      targetPath,
    );
    if (!approved) {
      const reason = `[Security Sandbox] User denied permission for '${toolName}' on '${targetPath}'.`;
      recordAudit({ timestamp, toolName, path: targetPath, decision: "prompt_blocked", reason }, onAudit);
      return { block: true, reason };
    }

    recordAudit(
      {
        timestamp,
        toolName,
        path: targetPath,
        decision: "prompt_approved",
        reason: "User explicitly granted permission.",
      },
      onAudit,
    );
    return undefined; // Approved
  } catch (err: unknown) {
    // Fail-Closed: If the UI prompt dialog throws or aborts, block the call
    const reason = `[Security Sandbox Error] Permission prompt threw an unexpected error: ${err instanceof Error ? err.message : String(err)}. Operation blocked.`;
    recordAudit({ timestamp, toolName, path: targetPath, decision: "error", reason }, onAudit);
    return { block: true, reason };
  }
}

/**
 * Evaluates an in-process tool call event and determines if it should be allowed or blocked.
 * This is the exact logic executed inside pi.on("tool_call").
 *
 * Security Model:
 * - Lookup Table Dispatcher: Eliminates code duplication across tools.
 * - Complete Built-in Coverage: Guards read, write, edit, grep, find, and ls.
 * - Fail-Closed: Any unhandled exception, missing prompt, or malformed input blocks the tool.
 * - Audit Logging: Logs all blocks and prompts with sanitized path strings.
 */
export async function evaluateToolCall(
  event: unknown,
  ctx: { cwd: string },
  options: ToolGuardOptions,
): Promise<ToolBlockResult | undefined> {
  try {
    const { config, askPermission, onAudit } = options;

    // If sandbox is explicitly disabled by operator, bypass guard
    if (config.enabled === false) {
      return undefined;
    }

    const toolName = (event as any)?.toolName;
    if (typeof toolName !== "string") {
      return undefined; // Not a recognized tool call format
    }

    const spec = GUARDED_TOOLS[toolName];
    if (!spec) {
      // Tool not in guarded table (e.g. bash or custom tools, which are handled in Phase 3/4)
      return undefined;
    }

    const rawPath = spec.getPath((event as any).input);
    const pathValidation = validatePathInput(rawPath);
    if (!pathValidation.valid) {
      const reason = `[Security Sandbox] ${pathValidation.reason}`;
      recordAudit(
        {
          timestamp: new Date().toISOString(),
          toolName,
          path: String(rawPath ?? ""),
          decision: "deny",
          reason,
        },
        onAudit,
      );
      return { block: true, reason };
    }

    const targetPath = pathValidation.path;
    const baseCwd = ctx.cwd || process.cwd();
    const fsConfig = config.filesystem ?? {};
    const { allow, deny } = spec.rules(fsConfig);

    const decision = spec.policy(targetPath, allow, deny, baseCwd);

    if (decision === "deny") {
      const reason = `[Security Sandbox Violation] Operation '${toolName}' on '${targetPath}' is denied by security policy.`;
      recordAudit(
        {
          timestamp: new Date().toISOString(),
          toolName,
          path: targetPath,
          decision: "deny",
          reason,
        },
        onAudit,
      );
      return { block: true, reason };
    }

    if (decision === "prompt") {
      return await resolvePrompt(toolName, targetPath, askPermission, onAudit);
    }

    return undefined; // Allowed
  } catch (error: any) {
    const timestamp = new Date().toISOString();
    const reason = `[Security Sandbox Error] Failed to evaluate security policy safely: ${error?.message || String(error)}. Operation blocked.`;
    recordAudit(
      {
        timestamp,
        toolName: (event as any)?.toolName ?? "unknown",
        path: String((event as any)?.input?.path ?? ""),
        decision: "error",
        reason,
      },
      options?.onAudit,
    );
    return { block: true, reason };
  }
}

/**
 * Registers in-process interception on pi.on("tool_call") to secure
 * direct Node.js tools.
 */
export function registerToolGuard(pi: ExtensionAPI, getOptions: () => ToolGuardOptions) {
  pi.on("tool_call", async (event, ctx: ExtensionContext) => {
    return evaluateToolCall(event, { cwd: ctx.cwd || process.cwd() }, getOptions());
  });
}
