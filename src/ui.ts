import type { ExtensionContext } from "@earendil-works/pi-coding-agent";

export async function promptPermission(
  ctx: ExtensionContext,
  title: string,
  target: string,
): Promise<"abort" | "session" | "project"> {
  if (!ctx.hasUI) {
    // In headless or non-interactive mode, fail closed
    return "abort";
  }

  const options = [
    "Allow for this session",
    "Allow and save to project (.pi/sandbox.json)",
    "Deny (Abort)",
  ];

  const choice = await ctx.ui.select(
    `🔒 [Security Sandbox Alert] ${title}\nTarget: ${target}`,
    options,
  );

  if (choice === options[0]) return "session";
  if (choice === options[1]) return "project";
  return "abort";
}
