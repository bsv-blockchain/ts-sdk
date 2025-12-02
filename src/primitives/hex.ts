// src/primitives/hex.ts

const PURE_HEX_REGEX = /^[0-9a-fA-F]+$/;

export function assertValidHex(msg: string): void {
  if (typeof msg !== 'string' || msg.length === 0 || !PURE_HEX_REGEX.test(msg)) {
    throw new Error('Invalid hex string');
  }
}

export function normalizeHex(msg: string): string {
  assertValidHex(msg);

  // Lowercase first
  let normalized = msg.toLowerCase();

  // Prepend "0" if odd-length
  if (normalized.length % 2 === 1) {
    normalized = '0' + normalized;
  }

  return normalized;
}
