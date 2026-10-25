import { describe, expect, it } from "bun:test";
import { homedir } from "node:os";
import { buildBwrapArgs, isBwrapAvailable } from "../src/bwrap.ts";
import { DEFAULT_CONFIG } from "../src/config.ts";

describe("Bubblewrap Subprocess Containment", () => {
  const cwd = process.cwd();

  it("detects bwrap installation", () => {
    expect(isBwrapAvailable()).toBe(true);
  });

  it("builds strict bubblewrap argument flags", () => {
    const args = buildBwrapArgs({
      cwd,
      config: DEFAULT_CONFIG,
      unshareNet: true,
    });

    // Root read-only
    expect(args).toContain("--ro-bind");
    expect(args).toContain("/");

    // CWD writable
    expect(args).toContain("--bind");
    expect(args).toContain(cwd);

    // Ephemeral tmp
    expect(args).toContain("--tmpfs");
    expect(args).toContain("/tmp");

    // Network unshared
    expect(args).toContain("--unshare-net");

    // Process die with parent
    expect(args).toContain("--die-with-parent");

    // Mask secrets
    const sshDir = `${homedir()}/.ssh`;
    const sshIndex = args.indexOf(sshDir);
    if (sshIndex !== -1) {
      expect(args[sshIndex - 1]).toBe("--tmpfs");
    }
  });
});
