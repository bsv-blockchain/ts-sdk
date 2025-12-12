// src/primitives/hex.ts

// Accepts empty string because empty byte arrays are valid in Bitcoin.
const PURE_HEX_REGEX = /^[0-9a-fA-F]*$/

export function assertValidHex (msg: string): void {
  if (typeof msg !== 'string') {
    throw new TypeError('Invalid hex string')
  }

  // allow empty
  if (msg.length === 0) return

  if (!PURE_HEX_REGEX.test(msg)) {
    throw new Error('Invalid hex string')
  }
}

export function normalizeHex (msg: string): string {
  assertValidHex(msg)

  // If empty, return empty — never force to "00"
  if (msg.length === 0) return ''

  let normalized = msg.toLowerCase()

  // Pad odd-length hex
  if (normalized.length % 2 !== 0) {
    normalized = '0' + normalized
  }

  return normalized
}
