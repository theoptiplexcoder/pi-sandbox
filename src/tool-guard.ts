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
 * Evaluates an in-process tool call event and determines if it should be allowed or blocked.
 * This function is extracted to enable direct, deterministic testing without a live Pi harness.
 *
 * Security Model:
 * - Fail-Closed: If an unhandled error occurs during path inspection or policy evaluation,
 *   the tool call is immediately blocked.
 * - Non-Interactive Safe: If askPermission is not provided and the policy returns 'prompt',
 *   the tool call is blocked immediately.
 * - Handles read, write, and edit built-in tools.
 */
export async function evaluateToolCall(
  event: unknown,
  ctx: { cwd: string },
  options: ToolGuardOptions,
): Promise<ToolBlockResult | undefined> {
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

  try {
    // 1. Guard READ tool
    if (isToolCallEventType("read", event as any)) {
      const targetPath = (event as any).input?.path;
      if (typeof targetPath !== "string" || !targetPath.trim()) {
        return {
          block: true,
          reason: "[Security Sandbox] Invalid or empty path provided to 'read' tool.",
        };
      }

      const decision = decideReadPolicy(targetPath, allowRead, denyRead, baseCwd);

      if (decision === "deny") {
        return {
          block: true,
          reason: `[Security Sandbox Violation] Reading '${targetPath}' is denied by security policy.`,
        };
      }

      if (decision === "prompt") {
        if (askPermission) {
          const approved = await askPermission(
            `Agent is requesting to READ external file: ${targetPath}`,
            targetPath,
          );
          if (!approved) {
            return {
              block: true,
              reason: `[Security Sandbox] User denied permission to read '${targetPath}'.`,
            };
          }
        } else {
          return {
            block: true,
            reason: `[Security Sandbox] Reading path '${targetPath}' outside allowed boundaries requires explicit user approval.`,
          };
        }
      }
    }

    // 2. Guard WRITE tool
    if (isToolCallEventType("write", event as any)) {
      const targetPath = (event as any).input?.path;
      if (typeof targetPath !== "string" || !targetPath.trim()) {
        return {
          block: true,
          reason: "[Security Sandbox] Invalid or empty path provided to 'write' tool.",
        };
      }

      const decision = decideWritePolicy(targetPath, allowWrite, denyWrite, baseCwd);

      if (decision === "deny") {
        return {
          block: true,
          reason: `[Security Sandbox Violation] Writing to '${targetPath}' is denied by security policy.`,
        };
      }

      if (decision === "prompt") {
        if (askPermission) {
          const approved = await askPermission(
            `Agent is requesting to WRITE to file outside workspace: ${targetPath}`,
            targetPath,
          );
          if (!approved) {
            return {
              block: true,
              reason: `[Security Sandbox] User denied permission to write to '${targetPath}'.`,
            };
          }
        } else {
          return {
            block: true,
            reason: `[Security Sandbox] Writing to path '${targetPath}' outside allowed write boundaries requires explicit user approval.`,
          };
        }
      }
    }

    // 3. Guard EDIT tool
    if (isToolCallEventType("edit", event as any)) {
      const targetPath = (event as any).input?.path;
      if (typeof targetPath !== "string" || !targetPath.trim()) {
        return {
          block: true,
          reason: "[Security Sandbox] Invalid or empty path provided to 'edit' tool.",
        };
      }

      const decision = decideWritePolicy(targetPath, allowWrite, denyWrite, baseCwd);

      if (decision === "deny") {
        return {
          block: true,
          reason: `[Security Sandbox Violation] Editing '${targetPath}' is denied by security policy.`,
        };
      }

      if (decision === "prompt") {
        if (askPermission) {
          const approved = await askPermission(
            `Agent is requesting to EDIT file outside workspace: ${targetPath}`,
            targetPath,
          );
          if (!approved) {
            return {
              block: true,
              reason: `[Security Sandbox] User denied permission to edit '${targetPath}'.`,
            };
          }
        } else {
          return {
            block: true,
            reason: `[Security Sandbox] Editing path '${targetPath}' outside allowed write boundaries requires explicit user approval.`,
          };
        }
      }
    }

    return undefined; // Tool call permitted
  } catch (error: any) {
    // Fail-Closed: If policy evaluation throws unexpectedly, block the call
    return {
      block: true,
      reason: `[Security Sandbox Error] Failed to evaluate security policy safely: ${error?.message || error}. Operation blocked.`,
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
