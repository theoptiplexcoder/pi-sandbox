import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { isSecretPath } from "./policy.ts";
import { sanitizeLogString } from "./tool-guard.ts";

/**
 * Result options returned by the interactive permission prompt.
 * 1. "always": Save globally / default config (changes top config / ~/.pi/agent/sandbox.json)
 * 2. "project": Save to project level policy (.pi/sandbox.json)
 * 3. "session": Allow for now / run once in this session
 * 4. "abort": Deny and abort the operation
 */
export type PromptDecision = "always" | "project" | "session" | "abort";

export const PROMPT_OPTIONS = {
  ALWAYS: "1. Always yes (save to global configuration)",
  PROJECT: "2. Only this time (save to project .pi/sandbox.json)",
  SESSION: "3. Only for now (allow to run once in this session)",
  DENY: "4. Deny (Abort)",
} as const;

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

  const options: string[] = [];

  // Permanent grants are disabled if target is a protected mandatory secret (e.g. ~/.ssh, .env)
  if (!isProtectedSecret) {
    options.push(PROMPT_OPTIONS.ALWAYS);
    options.push(PROMPT_OPTIONS.PROJECT);
  }

  options.push(PROMPT_OPTIONS.SESSION);
  options.push(PROMPT_OPTIONS.DENY);

  try {
    const notice = isProtectedSecret
      ? `🔒 [Security Alert - Protected Secret] ${safeTitle}\nTarget: ${safeTarget}\n(Note: Permanent grants are disabled for protected secrets)`
      : `🔒 [Security Sandbox Alert] ${safeTitle}\nTarget: ${safeTarget}\nChoose an access policy option:`;

    const choice = await ctx.ui.select(notice, options);

    if (choice === PROMPT_OPTIONS.ALWAYS) return "always";
    if (choice === PROMPT_OPTIONS.PROJECT) return "project";
    if (choice === PROMPT_OPTIONS.SESSION) return "session";
    return "abort";
  } catch {
    // Fail closed if dialog was cancelled, aborted, or threw an error
    return "abort";
  }
}
