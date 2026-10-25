import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import type { SandboxConfig } from "./config.ts";
import { decideReadPolicy, decideWritePolicy } from "./policy.ts";

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
 * Shared helper to resolve 'prompt' decisions fail-closed across all tool types.
 */
async function resolvePrompt(
  operation: "read" | "write" | "edit",
  targetPath: string,
  askPermission?: (message: string, path: string) => Promise<boolean>,
): Promise<ToolBlockResult | undefined> {
  if (!askPermission) {
    return {
      block: true,
      reason: `[Security Sandbox] ${operation.toUpperCase()} to path '${targetPath}' outside allowed boundaries requires explicit user approval, but no UI prompter is available.`,
    };
  }

  try {
    const approved = await askPermission(
      `Agent is requesting to ${operation.toUpperCase()} path outside workspace: ${targetPath}`,
      targetPath,
    );
    if (!approved) {
      return {
        block: true,
        reason: `[Security Sandbox] User denied permission to ${operation} '${targetPath}'.`,
      };
    }
    return undefined; // Approved
  } catch (err: unknown) {
    // Fail-Closed: If the UI prompt dialog throws or aborts, block the call
    return {
      block: true,
      reason: `[Security Sandbox Error] Permission prompt threw an unexpected error: ${err instanceof Error ? err.message : String(err)}. Operation blocked.`,
    };
  }
}

/**
 * Validates and sanitizes a path argument from an untrusted tool call.
 * Rejects undefined, null, non-strings, empty strings, and null-bytes (\0).
 */
function validatePathInput(rawPath: unknown): { valid: true; path: string } | { valid: false; reason: string } {
  if (typeof rawPath !== "string") {
    return {
      valid: false,
      reason: `[Security Sandbox] Invalid path parameter: expected non-empty string, got ${typeof rawPath}.`,
    };
  }

  const trimmed = rawPath.trim();
  if (trimmed.length === 0) {
    return {
      valid: false,
      reason: "[Security Sandbox] Invalid path parameter: path cannot be empty.",
    };
  }

  if (trimmed.includes("\0")) {
    return {
      valid: false,
      reason: "[Security Sandbox] Poison null-byte detected in path parameter.",
    };
  }

  return { valid: true, path: trimmed };
}

/**
 * Evaluates an in-process tool call event and determines if it should be allowed or blocked.
 * This is the exact logic executed inside pi.on("tool_call").
 *
 * Security Model:
 * - Fail-Closed: Any unhandled exception or failed check blocks the tool.
 * - Non-interactive safe: If askPermission is missing, 'prompt' blocks.
 * - Input sanitized: Null bytes, empty paths, and wrong types are rejected upfront.
 */
export async function evaluateToolCall(
  event: unknown,
  ctx: { cwd: string },
  options: ToolGuardOptions,
): Promise<ToolBlockResult | undefined> {
  try {
    const { config, askPermission } = options;

    // If sandbox is explicitly disabled by operator, bypass guard
    if (config.enabled === false) {
      return undefined;
    }

    const baseCwd = ctx.cwd || process.cwd();
    const allowRead = config.filesystem?.allowRead ?? [];
    const denyRead = config.filesystem?.denyRead ?? [];
    const allowWrite = config.filesystem?.allowWrite ?? [".", "/tmp"];
    const denyWrite = config.filesystem?.denyWrite ?? [];

    // 1. Guard READ tool
    if (isToolCallEventType("read", event as any)) {
      const pathValidation = validatePathInput((event as any).input?.path);
      if (!pathValidation.valid) {
        return { block: true, reason: pathValidation.reason };
      }

      const targetPath = pathValidation.path;
      const decision = decideReadPolicy(targetPath, allowRead, denyRead, baseCwd);

      if (decision === "deny") {
        return {
          block: true,
          reason: `[Security Sandbox Violation] Reading '${targetPath}' is denied by security policy.`,
        };
      }

      if (decision === "prompt") {
        return await resolvePrompt("read", targetPath, askPermission);
      }
    }

    // 2. Guard WRITE tool
    if (isToolCallEventType("write", event as any)) {
      const pathValidation = validatePathInput((event as any).input?.path);
      if (!pathValidation.valid) {
        return { block: true, reason: pathValidation.reason };
      }

      const targetPath = pathValidation.path;
      const decision = decideWritePolicy(targetPath, allowWrite, denyWrite, baseCwd);

      if (decision === "deny") {
        return {
          block: true,
          reason: `[Security Sandbox Violation] Writing to '${targetPath}' is denied by security policy.`,
        };
      }

      if (decision === "prompt") {
        return await resolvePrompt("write", targetPath, askPermission);
      }
    }

    // 3. Guard EDIT tool
    if (isToolCallEventType("edit", event as any)) {
      const pathValidation = validatePathInput((event as any).input?.path);
      if (!pathValidation.valid) {
        return { block: true, reason: pathValidation.reason };
      }

      const targetPath = pathValidation.path;
      const decision = decideWritePolicy(targetPath, allowWrite, denyWrite, baseCwd);

      if (decision === "deny") {
        return {
          block: true,
          reason: `[Security Sandbox Violation] Editing '${targetPath}' is denied by security policy.`,
        };
      }

      if (decision === "prompt") {
        return await resolvePrompt("edit", targetPath, askPermission);
      }
    }

    return undefined; // Tool call permitted
  } catch (error: any) {
    // Fail-Closed: If any error throws, immediately block the tool call
    return {
      block: true,
      reason: `[Security Sandbox Error] Failed to evaluate security policy safely: ${error?.message || String(error)}. Operation blocked.`,
    };
  }
}

/**
 * Registers in-process interception on pi.on("tool_call") to secure
 * direct Node.js tools: read, write, and edit.
 */
export function registerToolGuard(pi: ExtensionAPI, getOptions: () => ToolGuardOptions) {
  pi.on("tool_call", async (event, ctx: ExtensionContext) => {
    return evaluateToolCall(event, { cwd: ctx.cwd || process.cwd() }, getOptions());
  });
}
