import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { isSecretPath } from "./policy.ts";
import { sanitizeLogString } from "./tool-guard.ts";

/**
 * Result options returned by the interactive permission prompt.
 */
export type PromptDecision = "abort" | "session" | "project";

/**
 * Prompts the operator for security permissions when an unlisted domain or external path is accessed.
 *
 * Security Enhancements (Linus & Critic Directives):
 * 1. Headless / Non-Interactive Protection: If `ctx.hasUI === false`, automatically returns 'abort' (fail-closed).
 * 2. Escalation Prevention: If the target path or pattern violates mandatory security invariants (e.g. .env, ~/.ssh),
 *    the option to "Allow and save to project" is completely omitted from the menu. The agent cannot trick the user
 *    into persisting an invalid or dangerous grant.
 * 3. Path & Host Sanitization: Target hostnames and paths are sanitized to prevent terminal escape injection.
 * 4. Exception Resilience: If ctx.ui.select throws or the prompt is dismissed, fails closed to 'abort'.
 *
 * @param ctx Current extension context for the active session.
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

  // Check if target touches mandatory secret paths
  const isProtectedSecret = isSecretPath(target, [], ctx.cwd || process.cwd());

  const options = ["Allow for this session"];

  // Only offer permanent project-level saving if it's NOT a protected mandatory secret
  if (!isProtectedSecret) {
    options.push("Allow and save to project (.pi/sandbox.json)");
  }

  options.push("Deny (Abort)");

  try {
    const notice = isProtectedSecret
      ? `🔒 [Security Alert - Protected Secret] ${safeTitle}\nTarget: ${safeTarget}\n(Note: Permanent grants are disabled for protected secrets)`
      : `🔒 [Security Sandbox Alert] ${safeTitle}\nTarget: ${safeTarget}`;

    const choice = await ctx.ui.select(notice, options);

    if (choice === options[0]) return "session";
    if (choice === "Allow and save to project (.pi/sandbox.json)") return "project";
    return "abort";
  } catch {
    // Fail closed if dialog was cancelled, aborted, or threw an error
    return "abort";
  }
}
