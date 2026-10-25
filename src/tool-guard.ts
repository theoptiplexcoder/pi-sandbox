import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import type { SandboxConfig } from "./config.ts";
import { decideReadPolicy, decideWritePolicy } from "./policy.ts";

export interface ToolGuardOptions {
  config: SandboxConfig;
  askPermission?: (message: string, path: string) => Promise<boolean>;
}

/**
 * Registers in-process interception on pi.on("tool_call") to secure
 * direct Node.js tools: read, write, and edit.
 */
export function registerToolGuard(pi: ExtensionAPI, getOptions: () => ToolGuardOptions) {
  pi.on("tool_call", async (event, ctx: ExtensionContext) => {
    const { config, askPermission } = getOptions();
    if (config.enabled === false) {
      return;
    }

    const baseCwd = ctx.cwd || process.cwd();
    const allowRead = config.filesystem?.allowRead ?? [];
    const denyRead = config.filesystem?.denyRead ?? [];
    const allowWrite = config.filesystem?.allowWrite ?? [".", "/tmp"];
    const denyWrite = config.filesystem?.denyWrite ?? [];

    // 1. Guard READ tool
    if (isToolCallEventType("read", event)) {
      const targetPath = event.input.path;
      const decision = decideReadPolicy(targetPath, allowRead, denyRead, baseCwd);

      if (decision === "deny") {
        return {
          block: true,
          reason: `[Security Sandbox Violation] Reading '${targetPath}' is denied by security policy.`,
        };
      }

      if (decision === "prompt") {
        if (askPermission) {
          const approved = await askPermission(`Agent is requesting to READ external file: ${targetPath}`, targetPath);
          if (!approved) {
            return {
              block: true,
              reason: `[Security Sandbox] User denied permission to read '${targetPath}'.`,
            };
          }
        }
      }
    }

    // 2. Guard WRITE tool
    if (isToolCallEventType("write", event)) {
      const targetPath = event.input.path;
      const decision = decideWritePolicy(targetPath, allowWrite, denyWrite, baseCwd);

      if (decision === "deny") {
        return {
          block: true,
          reason: `[Security Sandbox Violation] Writing to '${targetPath}' is denied by security policy.`,
        };
      }

      if (decision === "prompt") {
        if (askPermission) {
          const approved = await askPermission(`Agent is requesting to WRITE to file outside workspace: ${targetPath}`, targetPath);
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
    if (isToolCallEventType("edit", event)) {
      const targetPath = event.input.path;
      const decision = decideWritePolicy(targetPath, allowWrite, denyWrite, baseCwd);

      if (decision === "deny") {
        return {
          block: true,
          reason: `[Security Sandbox Violation] Editing '${targetPath}' is denied by security policy.`,
        };
      }

      if (decision === "prompt") {
        if (askPermission) {
          const approved = await askPermission(`Agent is requesting to EDIT file outside workspace: ${targetPath}`, targetPath);
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
  });
}
