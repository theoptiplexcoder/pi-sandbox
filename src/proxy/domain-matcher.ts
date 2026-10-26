export function domainMatchesPattern(domain: string, pattern: string): boolean {
  if (pattern === "*") return true;

  const cleanDomain = domain.toLowerCase().trim();
  const cleanPattern = pattern.toLowerCase().trim();

  if (cleanPattern.startsWith("*.")) {
    const root = cleanPattern.slice(2);
    return cleanDomain === root || cleanDomain.endsWith("." + root);
  }

  return cleanDomain === cleanPattern;
}

export function isDomainAllowed(
  domain: string,
  allowedDomains: string[] = [],
  deniedDomains: string[] = [],
): boolean {
  const clean = domain.toLowerCase().trim();

  // Denied takes precedence
  for (const pattern of deniedDomains) {
    if (domainMatchesPattern(clean, pattern)) {
      return false;
    }
  }

  // Allowed check
  for (const pattern of allowedDomains) {
    if (domainMatchesPattern(clean, pattern)) {
      return true;
    }
  }

  return false;
}
