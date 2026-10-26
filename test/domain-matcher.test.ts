import { describe, expect, it } from "bun:test";
import { domainMatchesPattern, isDomainAllowed } from "../src/proxy/domain-matcher.ts";

describe("Domain Matcher & Allowlist", () => {
  it("matches exact domains", () => {
    expect(domainMatchesPattern("github.com", "github.com")).toBe(true);
    expect(domainMatchesPattern("api.github.com", "github.com")).toBe(false);
  });

  it("matches wildcard subdomains", () => {
    expect(domainMatchesPattern("github.com", "*.github.com")).toBe(true);
    expect(domainMatchesPattern("api.github.com", "*.github.com")).toBe(true);
    expect(domainMatchesPattern("raw.githubusercontent.com", "*.github.com")).toBe(false);
  });

  it("evaluates allowed and denied lists properly", () => {
    const allowed = ["github.com", "*.github.com", "*.npmjs.org"];
    const denied = ["malicious.github.com"];

    expect(isDomainAllowed("github.com", allowed, denied)).toBe(true);
    expect(isDomainAllowed("registry.npmjs.org", allowed, denied)).toBe(true);
    expect(isDomainAllowed("malicious.github.com", allowed, denied)).toBe(false);
    expect(isDomainAllowed("evil-c2.com", allowed, denied)).toBe(false);
  });
});
