import { Sha256State } from './Types.js'

const SHA256_INITIAL = [
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19
]

const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

export function sha256Pad (message: number[]): number[] {
  assertBytes(message)
  const padded = message.slice()
  const bitLength = BigInt(message.length) * 8n
  padded.push(0x80)
  while ((padded.length % 64) !== 56) padded.push(0)
  for (let i = 7; i >= 0; i--) {
    padded.push(Number((bitLength >> BigInt(i * 8)) & 0xffn))
  }
  return padded
}

export function sha256Schedule (block: number[]): number[] {
  if (block.length !== 64) throw new Error('SHA-256 block must be 64 bytes')
  assertBytes(block)
  const w = new Array<number>(64)
  for (let i = 0; i < 16; i++) {
    w[i] = readU32BE(block, i * 4)
  }
  for (let i = 16; i < 64; i++) {
    w[i] = add32(
      smallSigma1(w[i - 2]),
      w[i - 7],
      smallSigma0(w[i - 15]),
      w[i - 16]
    )
  }
  return w
}

export function sha256CompressBlock (
  state: Sha256State,
  block: number[]
): Sha256State {
  if (state.words.length !== 8) {
    throw new Error('SHA-256 state must contain 8 words')
  }
  const w = sha256Schedule(block)
  let [a, b, c, d, e, f, g, h] = state.words.map(word => word >>> 0)
  for (let i = 0; i < 64; i++) {
    const t1 = add32(h, bigSigma1(e), ch(e, f, g), SHA256_K[i], w[i])
    const t2 = add32(bigSigma0(a), maj(a, b, c))
    h = g
    g = f
    f = e
    e = add32(d, t1)
    d = c
    c = b
    b = a
    a = add32(t1, t2)
  }
  return {
    words: [
      add32(state.words[0], a),
      add32(state.words[1], b),
      add32(state.words[2], c),
      add32(state.words[3], d),
      add32(state.words[4], e),
      add32(state.words[5], f),
      add32(state.words[6], g),
      add32(state.words[7], h)
    ]
  }
}

export function sha256Digest (message: number[]): number[] {
  let state: Sha256State = { words: SHA256_INITIAL.slice() }
  const padded = sha256Pad(message)
  for (let offset = 0; offset < padded.length; offset += 64) {
    state = sha256CompressBlock(state, padded.slice(offset, offset + 64))
  }
  const out: number[] = []
  for (const word of state.words) {
    out.push((word >>> 24) & 0xff)
    out.push((word >>> 16) & 0xff)
    out.push((word >>> 8) & 0xff)
    out.push(word & 0xff)
  }
  return out
}

export function hmacSha256 (
  key: number[],
  message: number[]
): number[] {
  assertBytes(key)
  assertBytes(message)
  let normalizedKey = key.slice()
  if (normalizedKey.length > 64) normalizedKey = sha256Digest(normalizedKey)
  while (normalizedKey.length < 64) normalizedKey.push(0)
  const innerPad = normalizedKey.map(byte => byte ^ 0x36)
  const outerPad = normalizedKey.map(byte => byte ^ 0x5c)
  return sha256Digest([...outerPad, ...sha256Digest([...innerPad, ...message])])
}

export function sha256CompressionTrace (
  message: number[]
): Sha256State[] {
  let state: Sha256State = { words: SHA256_INITIAL.slice() }
  const states = [state]
  const padded = sha256Pad(message)
  for (let offset = 0; offset < padded.length; offset += 64) {
    state = sha256CompressBlock(state, padded.slice(offset, offset + 64))
    states.push(state)
  }
  return states
}

function ch (x: number, y: number, z: number): number {
  return ((x & y) ^ (~x & z)) >>> 0
}

function maj (x: number, y: number, z: number): number {
  return ((x & y) ^ (x & z) ^ (y & z)) >>> 0
}

function bigSigma0 (x: number): number {
  return (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)) >>> 0
}

function bigSigma1 (x: number): number {
  return (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)) >>> 0
}

function smallSigma0 (x: number): number {
  return (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) >>> 0
}

function smallSigma1 (x: number): number {
  return (rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10)) >>> 0
}

function rotr (x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0
}

function add32 (...values: number[]): number {
  let sum = 0
  for (const value of values) sum = (sum + (value >>> 0)) >>> 0
  return sum
}

function readU32BE (bytes: number[], offset: number): number {
  return (
    ((bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3]) >>> 0
  )
}

function assertBytes (bytes: number[]): void {
  for (const byte of bytes) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error('Invalid byte')
    }
  }
}
