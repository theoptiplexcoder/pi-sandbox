import { describe, expect, test } from "bun:test";
import {
  DEFAULT_PROTECTED_BRANCHES,
  evaluateGitPushPolicy,
  extractPushTargetBranches,
  isGitPushCommand,
  matchesBranchPattern,
} from "../src/git-policy.ts";

describe("Git Push Policy & Non-Main Branch Enforcement", () => {
  test("detects git push commands accurately", () => {
    expect(isGitPushCommand("git push origin dev")).toBe(true);
    expect(isGitPushCommand("git push -u origin feature/login")).toBe(true);
    expect(isGitPushCommand("/usr/bin/git push origin dev")).toBe(true);
    expect(isGitPushCommand("npm test && git push origin dev")).toBe(true);
    expect(isGitPushCommand("git checkout dev")).toBe(false);
    expect(isGitPushCommand("git pull origin main")).toBe(false);
  });

  test("matches branch wildcard patterns correctly", () => {
    expect(matchesBranchPattern("main", ["main", "master"])).toBe(true);
    expect(matchesBranchPattern("master", ["main", "master"])).toBe(true);
    expect(matchesBranchPattern("release/v1.0", ["release/*"])).toBe(true);
    expect(matchesBranchPattern("production", ["prod*"])).toBe(true);
    expect(matchesBranchPattern("dev", ["main", "master"])).toBe(false);
    expect(matchesBranchPattern("dev", ["*"])).toBe(true);
  });

  test("extracts target branches from push arguments", () => {
    expect(extractPushTargetBranches("git push origin dev", process.cwd())).toEqual(["dev"]);
    expect(extractPushTargetBranches("git push -u origin dev", process.cwd())).toEqual(["dev"]);
    expect(extractPushTargetBranches("git push origin feature/test:dev", process.cwd())).toEqual(["dev"]);
    expect(extractPushTargetBranches("git push origin HEAD:refs/heads/feature/x", process.cwd())).toEqual(["feature/x"]);
  });

  test("blocks git push when gitPush is disabled in config", () => {
    const res = evaluateGitPushPolicy("git push origin dev", process.cwd(), {
      enabled: false,
    });
    expect(res.allowed).toBe(false);
    expect(res.reason).toContain("disabled in sandbox policy");
  });

  test("blocks git push to main and master branches", () => {
    const config = {
      enabled: true,
      protectedBranches: DEFAULT_PROTECTED_BRANCHES,
      allowBranches: ["*"],
    };

    const resMain = evaluateGitPushPolicy("git push origin main", process.cwd(), config);
    expect(resMain.allowed).toBe(false);
    expect(resMain.reason).toContain("protected branch 'main'");

    const resMaster = evaluateGitPushPolicy("git push origin master", process.cwd(), config);
    expect(resMaster.allowed).toBe(false);
    expect(resMaster.reason).toContain("protected branch 'master'");

    const resProd = evaluateGitPushPolicy("git push origin production", process.cwd(), config);
    expect(resProd.allowed).toBe(false);
    expect(resProd.reason).toContain("protected branch 'production'");
  });

  test("allows git push to non-main branch (e.g. dev, feature/*)", () => {
    const config = {
      enabled: true,
      protectedBranches: DEFAULT_PROTECTED_BRANCHES,
      allowBranches: ["*"],
    };

    const resDev = evaluateGitPushPolicy("git push origin dev", process.cwd(), config);
    expect(resDev.allowed).toBe(true);

    const resFeature = evaluateGitPushPolicy("git push origin feature/login", process.cwd(), config);
    expect(resFeature.allowed).toBe(true);
  });

  test("enforces allowBranches restriction if specified", () => {
    const config = {
      enabled: true,
      protectedBranches: ["main", "master"],
      allowBranches: ["dev", "feature/*"],
    };

    expect(evaluateGitPushPolicy("git push origin dev", process.cwd(), config).allowed).toBe(true);
    expect(evaluateGitPushPolicy("git push origin feature/abc", process.cwd(), config).allowed).toBe(true);
    expect(evaluateGitPushPolicy("git push origin hotfix/123", process.cwd(), config).allowed).toBe(false);
  });
});
