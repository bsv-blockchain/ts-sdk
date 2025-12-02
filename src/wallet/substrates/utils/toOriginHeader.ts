export function toOriginHeader (originator: string, fallbackScheme = 'http'): string | undefined {
  // If the caller already gave us a scheme, assume it’s fine
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(originator)) {
    try {
      return new URL(originator).origin // trims any path/query
    } catch { /* fall through to fix-up */ }
  }

  // Otherwise, prepend the fallback scheme and validate
  try {
    return new URL(`${fallbackScheme}://${originator}`).origin
  } catch {
    throw new Error(`Invalid originator value: ${originator}`)
  }
}
