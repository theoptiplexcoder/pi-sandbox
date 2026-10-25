import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { sanitizeLogString } from "./tool-guard.ts";

/**
 * Result options returned by the interactive permission prompt.
 */
export type PromptDecision = "abort" | "session" | "project";

/**
 * Prompts the operator for security permissions when an unlisted domain or external path is accessed.
 *
 * Security Model:
 * 1. Headless / Non-Interactive Protection: If `ctx.hasUI === false`, automatically returns 'abort' (fail-closed).
 * 2. Path & Host Sanitization: Target hostnames and paths are sanitized to prevent terminal escape injection.
 * 3. Structured User Choices: Provides explicit options (session grant vs permanent grant vs abort).
 * 4. Exception Resilience: If ctx.ui.select throws or the prompt is dismissed, fails closed to 'abort'.
 *
 * @param ctx Current extension context.
 * @param title Alert title describing the operation.
 * @param target The target hostname or filesystem path.
 * @returns Promise<PromptDecision>
 */
export async function promptPermission(
  ctx: ExtensionContext,
  title: string,
  target: string,
): Promise<PromptDecision> {
  // Fail-closed in headless, non-interactive, or automated modes
  if (!ctx.hasUI || !ctx.ui?.select) {
    return "abort";
  }

  const safeTitle = sanitizeLogString(title, 100);
  const safeTarget = sanitizeLogString(target, 150);

  const options = [
    "Allow for this session",
    "Allow and save to project (.pi/sandbox.json)",
    "Deny (Abort)",
  ];

  try {
    const choice = await ctx.ui.select(
      `🔒 [Security Sandbox Alert] ${safeTitle}\nTarget: ${safeTarget}`,
      options,
    );

    if (choice === options[0]) return "session";
    if (choice === options[1]) return "project";
    return "abort";
  } catch {
    // Fail closed if dialog was cancelled, aborted, or threw an error
    return "abort";
  }
}
