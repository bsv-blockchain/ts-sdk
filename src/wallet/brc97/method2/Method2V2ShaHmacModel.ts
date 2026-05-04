import { sha256Pad } from '../circuit/index.js'
import { METHOD2_SHA256_BLOCK_LAYOUT } from './Method2Sha256.js'
import {
  METHOD2_HMAC_BLOCK_SIZE,
  METHOD2_HMAC_KEY_SIZE,
  METHOD2_SHA256_DIGEST_SIZE
} from './Method2Hmac.js'
import { METHOD2_V2_FIELD_MUL_LAYOUT } from './Method2V2FieldMul.js'

export const METHOD2_V2_SHA_ROUNDS_PER_BLOCK = 64
export const METHOD2_V2_SHA_BITS_PER_WORD = 32
export const METHOD2_V2_HMAC_COMPRESSED_KEY_BYTES = METHOD2_HMAC_KEY_SIZE
export const METHOD2_V2_HMAC_LINKAGE_BYTES = METHOD2_SHA256_DIGEST_SIZE

export const METHOD2_V2_BIT_SERIAL_SHA_PRIVATE_WIDTH = 64
export const METHOD2_V2_BIT_SERIAL_SHA_PUBLIC_WIDTH = 18
export const METHOD2_V2_BIT_SERIAL_HMAC_KEY_BINDING_ROWS =
  METHOD2_V2_HMAC_COMPRESSED_KEY_BYTES * 8
export const METHOD2_V2_BIT_SERIAL_LINKAGE_BINDING_ROWS =
  METHOD2_V2_HMAC_LINKAGE_BYTES * 8

export const METHOD2_V2_SCALAR_CORE_ACTIVE_ROWS = 2747
export const METHOD2_V2_PROJECTED_MIXED_ADDS = 86
export const METHOD2_V2_PROJECTED_FIELD_MULS_PER_MIXED_ADD = 12
export const METHOD2_V2_PROJECTED_FIELD_MUL_ROWS = 18
export const METHOD2_V2_PROJECTED_NON_MUL_ROWS_PER_MIXED_ADD = 20
export const METHOD2_V2_PRODUCTION_BLOWUP = 16

export interface Method2V2ShaHmacBlockCounts {
  invoiceLength: number
  innerMessageLength: number
  outerMessageLength: number
  innerBlocks: number
  outerBlocks: number
  totalBlocks: number
}

export interface Method2V2ShaHmacShape {
  name: 'current-wide-round' | 'v2-bit-serial'
  activeRows: number
  paddedRows: number
  privateWidth: number
  publicWidth: number
  ldeRows: number
  traceArea: number
}

export interface Method2V2ShaHmacIntegrationProjection {
  sha: Method2V2ShaHmacShape
  scalarRows: number
  ecRows: number
  totalActiveRows: number
  totalPaddedRows: number
  maxPrivateWidth: number
  ldeRows: number
  traceArea: number
}

export interface Method2V2ShaHmacModel {
  counts: Method2V2ShaHmacBlockCounts
  currentWideRound: Method2V2ShaHmacShape
  bitSerial: Method2V2ShaHmacShape
  segmentedWithCurrentWideRound: Method2V2ShaHmacIntegrationProjection
  segmentedWithBitSerial: Method2V2ShaHmacIntegrationProjection
}

export function method2V2ShaHmacBlockCounts (
  invoiceLength: number
): Method2V2ShaHmacBlockCounts {
  if (!Number.isSafeInteger(invoiceLength) || invoiceLength < 0) {
    throw new Error('Method 2 V2 SHA/HMAC invoice length is invalid')
  }
  const innerInputLength = METHOD2_HMAC_BLOCK_SIZE + invoiceLength
  const outerInputLength = METHOD2_HMAC_BLOCK_SIZE + METHOD2_SHA256_DIGEST_SIZE
  const innerMessageLength = sha256Pad(new Array(innerInputLength).fill(0)).length
  const outerMessageLength = sha256Pad(new Array(outerInputLength).fill(0)).length
  const innerBlocks = innerMessageLength / METHOD2_HMAC_BLOCK_SIZE
  const outerBlocks = outerMessageLength / METHOD2_HMAC_BLOCK_SIZE
  if (!Number.isInteger(innerBlocks) || !Number.isInteger(outerBlocks)) {
    throw new Error('Method 2 V2 SHA/HMAC block count is not integral')
  }
  return {
    invoiceLength,
    innerMessageLength,
    outerMessageLength,
    innerBlocks,
    outerBlocks,
    totalBlocks: innerBlocks + outerBlocks
  }
}

export function method2V2ShaHmacModel (
  invoiceLength: number
): Method2V2ShaHmacModel {
  const counts = method2V2ShaHmacBlockCounts(invoiceLength)
  const currentWideRound = currentWideRoundShape(counts)
  const bitSerial = bitSerialShape(counts)
  return {
    counts,
    currentWideRound,
    bitSerial,
    segmentedWithCurrentWideRound: integrationProjection(currentWideRound),
    segmentedWithBitSerial: integrationProjection(bitSerial)
  }
}

export function method2V2ProjectedEcRows (): number {
  return METHOD2_V2_PROJECTED_MIXED_ADDS *
    (
      METHOD2_V2_PROJECTED_FIELD_MULS_PER_MIXED_ADD *
      METHOD2_V2_PROJECTED_FIELD_MUL_ROWS +
      METHOD2_V2_PROJECTED_NON_MUL_ROWS_PER_MIXED_ADD
    )
}

function currentWideRoundShape (
  counts: Method2V2ShaHmacBlockCounts
): Method2V2ShaHmacShape {
  const activeRows = counts.totalBlocks * METHOD2_V2_SHA_ROUNDS_PER_BLOCK +
    counts.totalBlocks
  const paddedRows = nextPowerOfTwo(activeRows)
  const privateWidth = METHOD2_SHA256_BLOCK_LAYOUT.width
  return {
    name: 'current-wide-round',
    activeRows,
    paddedRows,
    privateWidth,
    publicWidth: 8,
    ldeRows: paddedRows * METHOD2_V2_PRODUCTION_BLOWUP,
    traceArea: paddedRows * METHOD2_V2_PRODUCTION_BLOWUP * privateWidth
  }
}

function bitSerialShape (
  counts: Method2V2ShaHmacBlockCounts
): Method2V2ShaHmacShape {
  const activeRows = counts.totalBlocks *
    METHOD2_V2_SHA_ROUNDS_PER_BLOCK *
    METHOD2_V2_SHA_BITS_PER_WORD +
    METHOD2_V2_BIT_SERIAL_HMAC_KEY_BINDING_ROWS +
    METHOD2_V2_BIT_SERIAL_LINKAGE_BINDING_ROWS
  const paddedRows = nextPowerOfTwo(activeRows)
  return {
    name: 'v2-bit-serial',
    activeRows,
    paddedRows,
    privateWidth: METHOD2_V2_BIT_SERIAL_SHA_PRIVATE_WIDTH,
    publicWidth: METHOD2_V2_BIT_SERIAL_SHA_PUBLIC_WIDTH,
    ldeRows: paddedRows * METHOD2_V2_PRODUCTION_BLOWUP,
    traceArea: paddedRows *
      METHOD2_V2_PRODUCTION_BLOWUP *
      METHOD2_V2_BIT_SERIAL_SHA_PRIVATE_WIDTH
  }
}

function integrationProjection (
  sha: Method2V2ShaHmacShape
): Method2V2ShaHmacIntegrationProjection {
  const scalarRows = METHOD2_V2_SCALAR_CORE_ACTIVE_ROWS
  const ecRows = method2V2ProjectedEcRows()
  const totalActiveRows = scalarRows + ecRows + sha.activeRows
  const totalPaddedRows = nextPowerOfTwo(totalActiveRows)
  const maxPrivateWidth = Math.max(
    METHOD2_V2_FIELD_MUL_LAYOUT.width,
    sha.privateWidth
  )
  return {
    sha,
    scalarRows,
    ecRows,
    totalActiveRows,
    totalPaddedRows,
    maxPrivateWidth,
    ldeRows: totalPaddedRows * METHOD2_V2_PRODUCTION_BLOWUP,
    traceArea: totalPaddedRows *
      METHOD2_V2_PRODUCTION_BLOWUP *
      maxPrivateWidth
  }
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}
