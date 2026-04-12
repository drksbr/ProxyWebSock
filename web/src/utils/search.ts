function normalizeToken(value: unknown): string {
  return String(value ?? "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .trim();
}

export function searchTokens(query?: string): string[] {
  return normalizeToken(query)
    .split(/\s+/)
    .map((token) => token.trim())
    .filter(Boolean);
}

export function matchesSearch(
  query: string | undefined,
  fields: Array<unknown>,
): boolean {
  const tokens = searchTokens(query);
  if (!tokens.length) {
    return true;
  }
  const haystack = fields
    .map((field) => normalizeToken(field))
    .filter(Boolean)
    .join(" ");
  return tokens.every((token) => haystack.includes(token));
}
