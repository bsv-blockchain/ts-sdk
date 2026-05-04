import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import {
  hmacSha256,
  sha256Digest,
  sha256Pad,
  toBitsLE
} from '../circuit/index.js'
import { AirDefinition } from '../stark/Air.js'
import { F, FieldElement } from '../stark/Field.js'
import {
  StarkProof,
  StarkProverOptions,
  proveStark,
  serializeStarkProof,
  verifyStark
} from '../stark/Stark.js'
import {
  METHOD2_HMAC_BLOCK_SIZE,
  METHOD2_HMAC_INNER_PAD,
  METHOD2_HMAC_KEY_SIZE,
  METHOD2_HMAC_OUTER_PAD,
  METHOD2_SHA256_DIGEST_SIZE
} from './Method2Hmac.js'
import {
  METHOD2_SHA256_BLOCK_LAYOUT,
  METHOD2_SHA256_INITIAL_STATE,
  METHOD2_SHA256_K,
  buildMethod2Sha256BlockTrace,
  evaluateMethod2Sha256BlockTransition
} from './Method2Sha256.js'

export const METHOD2_PRIVATE_HMAC_SHA256_TRANSCRIPT_DOMAIN =
  'BRC97_METHOD2_PRIVATE_HMAC_SHA256_AIR_V1'
export const METHOD2_PRIVATE_HMAC_SHA256_PUBLIC_INPUT_ID =
  'BRC97_METHOD2_PRIVATE_HMAC_SHA256_PUBLIC_INPUT_V1'

export const METHOD2_PRIVATE_HMAC_SHA256_STARK_OPTIONS = {
  blowupFactor: 4,
  numQueries: 4,
  maxRemainderSize: 16,
  maskDegree: 1,
  cosetOffset: 3n,
  transcriptDomain: METHOD2_PRIVATE_HMAC_SHA256_TRANSCRIPT_DOMAIN
} as const

const SHA_WORD_BITS = 32
const SHA_STATE_WORDS = 8
const SHA_ROUNDS = 64
const SHA_RESULT_ROW = 64
const HMAC_BLOCK_STRIDE = SHA_RESULT_ROW + 1

export interface Method2PrivateHmacSha256Layout {
  shaWidth: number
  linkNext: number
  keyInit: number
  keyCarry: number
  innerKeyBlock: number
  outerKeyBlock: number
  captureInnerDigest: number
  digestCarry: number
  useInnerDigest: number
  keyBits: number
  innerDigestBits: number
  width: number
}

export interface Method2PrivateHmacSha256PublicInput {
  invoice: number[]
  linkage: number[]
  innerBlocks: number
  outerBlocks: number
  totalBlocks: number
  activeRows: number
  traceLength: number
}

export interface Method2PrivateHmacSha256Trace {
  publicInput: Method2PrivateHmacSha256PublicInput
  key: number[]
  innerDigest: number[]
  innerMessage: number[]
  outerMessage: number[]
  rows: FieldElement[][]
  layout: Method2PrivateHmacSha256Layout
}

export interface Method2PrivateHmacSha256Metrics {
  invoiceLength: number
  innerBlocks: number
  outerBlocks: number
  totalBlocks: number
  activeRows: number
  paddedRows: number
  traceWidth: number
  privateKeyBits: number
  privateInnerDigestBits: number
  committedCells: number
  proofBytes?: number
}

interface Method2PrivateHmacSha256BlockPlan {
  chain: 'inner' | 'outer'
  kind: 'inner-key' | 'inner-public' | 'outer-key' | 'outer-digest'
  blockIndex: number
  startRow: number
  resultRow: number
  linkToNext: boolean
}

interface Method2PrivateHmacSha256Selectors {
  linkNext: FieldElement[]
  keyInit: FieldElement[]
  keyCarry: FieldElement[]
  innerKeyBlock: FieldElement[]
  outerKeyBlock: FieldElement[]
  captureInnerDigest: FieldElement[]
  digestCarry: FieldElement[]
  useInnerDigest: FieldElement[]
}

export const METHOD2_PRIVATE_HMAC_SHA256_LAYOUT:
Method2PrivateHmacSha256Layout = {
  shaWidth: METHOD2_SHA256_BLOCK_LAYOUT.width,
  linkNext: METHOD2_SHA256_BLOCK_LAYOUT.width,
  keyInit: METHOD2_SHA256_BLOCK_LAYOUT.width + 1,
  keyCarry: METHOD2_SHA256_BLOCK_LAYOUT.width + 2,
  innerKeyBlock: METHOD2_SHA256_BLOCK_LAYOUT.width + 3,
  outerKeyBlock: METHOD2_SHA256_BLOCK_LAYOUT.width + 4,
  captureInnerDigest: METHOD2_SHA256_BLOCK_LAYOUT.width + 5,
  digestCarry: METHOD2_SHA256_BLOCK_LAYOUT.width + 6,
  useInnerDigest: METHOD2_SHA256_BLOCK_LAYOUT.width + 7,
  keyBits: METHOD2_SHA256_BLOCK_LAYOUT.width + 8,
  innerDigestBits: METHOD2_SHA256_BLOCK_LAYOUT.width + 8 +
    METHOD2_HMAC_KEY_SIZE * 8,
  width: METHOD2_SHA256_BLOCK_LAYOUT.width + 8 +
    METHOD2_HMAC_KEY_SIZE * 8 +
    METHOD2_SHA256_DIGEST_SIZE * 8
}

export function buildMethod2PrivateHmacSha256Trace (
  key: number[],
  invoice: number[],
  linkage: number[] = hmacSha256(key, invoice)
): Method2PrivateHmacSha256Trace {
  assertBytes(key, METHOD2_HMAC_KEY_SIZE, 'HMAC key')
  assertBytes(invoice, undefined, 'invoice')
  assertBytes(linkage, METHOD2_SHA256_DIGEST_SIZE, 'linkage')
  if (!bytesEqual(hmacSha256(key, invoice), linkage)) {
    throw new Error('Private HMAC-SHA256 linkage does not match key and invoice')
  }

  const publicInput = method2PrivateHmacSha256PublicInput(invoice, linkage)
  const layout = METHOD2_PRIVATE_HMAC_SHA256_LAYOUT
  const rows = new Array<FieldElement[]>(publicInput.traceLength)
    .fill([])
    .map(() => new Array<FieldElement>(layout.width).fill(0n))
  const keyBits = bytesToBits(key)
  const innerDigest = sha256Digest(innerHmacInput(key, invoice))
  const innerMessage = sha256Pad(innerHmacInput(key, invoice))
  const outerMessage = sha256Pad(outerHmacInput(key, innerDigest))
  const innerDigestBits = wordsToBitsLE(bytesToWordsBE(innerDigest))
  const blockPlans = hmacBlockPlans(publicInput)

  let innerState = METHOD2_SHA256_INITIAL_STATE.slice()
  let outerState = METHOD2_SHA256_INITIAL_STATE.slice()
  for (const block of blockPlans) {
    const message = block.chain === 'inner' ? innerMessage : outerMessage
    const initialState = block.chain === 'inner' ? innerState : outerState
    const blockBytes = message.slice(
      block.blockIndex * METHOD2_HMAC_BLOCK_SIZE,
      (block.blockIndex + 1) * METHOD2_HMAC_BLOCK_SIZE
    )
    const blockTrace = buildMethod2Sha256BlockTrace(initialState, blockBytes)
    for (let localRow = 0; localRow <= SHA_RESULT_ROW; localRow++) {
      const row = rows[block.startRow + localRow]
      const source = blockTrace.traceRows[localRow]
      for (let column = 0; column < layout.shaWidth; column++) {
        row[column] = source[column]
      }
    }
    if (block.chain === 'inner') {
      innerState = blockTrace.outputState
    } else {
      outerState = blockTrace.outputState
    }
  }

  const selectorValues = hmacSelectorValues(publicInput)
  for (let rowIndex = 0; rowIndex < rows.length; rowIndex++) {
    const row = rows[rowIndex]
    row[layout.linkNext] = selectorValues.linkNext[rowIndex]
    row[layout.keyInit] = selectorValues.keyInit[rowIndex]
    row[layout.keyCarry] = selectorValues.keyCarry[rowIndex]
    row[layout.innerKeyBlock] = selectorValues.innerKeyBlock[rowIndex]
    row[layout.outerKeyBlock] = selectorValues.outerKeyBlock[rowIndex]
    row[layout.captureInnerDigest] = selectorValues.captureInnerDigest[rowIndex]
    row[layout.digestCarry] = selectorValues.digestCarry[rowIndex]
    row[layout.useInnerDigest] = selectorValues.useInnerDigest[rowIndex]
    const digestActive = rowIndex >= innerFinalResultRow(publicInput)
    writeBits(row, layout.keyBits, keyBits)
    if (digestActive) writeBits(row, layout.innerDigestBits, innerDigestBits)
  }

  const trace = {
    publicInput,
    key: key.slice(),
    innerDigest,
    innerMessage,
    outerMessage,
    rows,
    layout
  }
  validateMethod2PrivateHmacSha256Trace(trace)
  return trace
}

export function method2PrivateHmacSha256PublicInput (
  invoice: number[],
  linkage: number[]
): Method2PrivateHmacSha256PublicInput {
  assertBytes(invoice, undefined, 'invoice')
  assertBytes(linkage, METHOD2_SHA256_DIGEST_SIZE, 'linkage')
  const innerMessageLength = sha256Pad([
    ...new Array<number>(METHOD2_HMAC_BLOCK_SIZE).fill(0),
    ...invoice
  ]).length
  const outerMessageLength = sha256Pad([
    ...new Array<number>(METHOD2_HMAC_BLOCK_SIZE).fill(0),
    ...new Array<number>(METHOD2_SHA256_DIGEST_SIZE).fill(0)
  ]).length
  const innerBlocks = innerMessageLength / METHOD2_HMAC_BLOCK_SIZE
  const outerBlocks = outerMessageLength / METHOD2_HMAC_BLOCK_SIZE
  if (!Number.isInteger(innerBlocks) || !Number.isInteger(outerBlocks)) {
    throw new Error('Private HMAC-SHA256 block count is invalid')
  }
  const totalBlocks = innerBlocks + outerBlocks
  const activeRows = totalBlocks * HMAC_BLOCK_STRIDE
  return {
    invoice: invoice.slice(),
    linkage: linkage.slice(),
    innerBlocks,
    outerBlocks,
    totalBlocks,
    activeRows,
    traceLength: nextPowerOfTwo(activeRows)
  }
}

export function buildMethod2PrivateHmacSha256Air (
  publicInput: Method2PrivateHmacSha256PublicInput
): AirDefinition {
  validateMethod2PrivateHmacSha256PublicInput(publicInput)
  const layout = METHOD2_PRIVATE_HMAC_SHA256_LAYOUT
  return {
    traceWidth: layout.width,
    transitionDegree: 8,
    publicInputDigest: method2PrivateHmacSha256PublicInputDigest(publicInput),
    boundaryConstraints: [
      ...method2PrivateHmacSha256BoundaryConstraints(publicInput)
    ],
    fullBoundaryColumns: method2PrivateHmacSha256FullBoundaryColumns(publicInput),
    evaluateTransition: (current, next) =>
      evaluateMethod2PrivateHmacSha256Transition(current, next, layout)
  }
}

export function proveMethod2PrivateHmacSha256 (
  trace: Method2PrivateHmacSha256Trace,
  options: StarkProverOptions = {}
): StarkProof {
  validateMethod2PrivateHmacSha256Trace(trace)
  const air = buildMethod2PrivateHmacSha256Air(trace.publicInput)
  return proveStark(air, trace.rows, {
    ...METHOD2_PRIVATE_HMAC_SHA256_STARK_OPTIONS,
    ...options,
    publicInputDigest: air.publicInputDigest,
    transcriptDomain: METHOD2_PRIVATE_HMAC_SHA256_TRANSCRIPT_DOMAIN
  })
}

export function verifyMethod2PrivateHmacSha256 (
  publicInput: Method2PrivateHmacSha256PublicInput,
  proof: StarkProof
): boolean {
  try {
    const air = buildMethod2PrivateHmacSha256Air(publicInput)
    return verifyStark(air, proof, {
      blowupFactor: proof.blowupFactor,
      numQueries: proof.numQueries,
      maxRemainderSize: proof.maxRemainderSize,
      maskDegree: proof.maskDegree,
      cosetOffset: proof.cosetOffset,
      traceDegreeBound: proof.traceDegreeBound,
      compositionDegreeBound: proof.compositionDegreeBound,
      publicInputDigest: air.publicInputDigest,
      transcriptDomain: METHOD2_PRIVATE_HMAC_SHA256_TRANSCRIPT_DOMAIN
    })
  } catch {
    return false
  }
}

export function evaluateMethod2PrivateHmacSha256Transition (
  current: FieldElement[],
  next: FieldElement[],
  layout: Method2PrivateHmacSha256Layout = METHOD2_PRIVATE_HMAC_SHA256_LAYOUT
): FieldElement[] {
  const constraints = evaluateMethod2Sha256BlockTransition(
    current.slice(0, layout.shaWidth),
    next.slice(0, layout.shaWidth),
    METHOD2_SHA256_BLOCK_LAYOUT
  )

  const keyInit = current[layout.keyInit]
  const keyCarry = current[layout.keyCarry]
  const linkNext = current[layout.linkNext]
  const innerKeyBlock = current[layout.innerKeyBlock]
  const outerKeyBlock = current[layout.outerKeyBlock]
  const captureInnerDigest = current[layout.captureInnerDigest]
  const digestCarry = current[layout.digestCarry]
  const useInnerDigest = current[layout.useInnerDigest]

  for (let bit = 0; bit < METHOD2_HMAC_KEY_SIZE * 8; bit++) {
    const keyBit = current[layout.keyBits + bit]
    constraints.push(F.mul(keyInit, booleanConstraint(keyBit)))
    constraints.push(F.mul(
      keyCarry,
      F.sub(next[layout.keyBits + bit], keyBit)
    ))
  }

  for (let bit = 0; bit < METHOD2_SHA256_DIGEST_SIZE * 8; bit++) {
    constraints.push(F.mul(
      digestCarry,
      F.sub(next[layout.innerDigestBits + bit], current[layout.innerDigestBits + bit])
    ))
  }

  for (let byteIndex = 0; byteIndex < METHOD2_HMAC_KEY_SIZE; byteIndex++) {
    for (let bit = 0; bit < 8; bit++) {
      const keyBit = current[layout.keyBits + byteIndex * 8 + bit]
      constraints.push(F.mul(
        innerKeyBlock,
        F.sub(
          scheduleByteBit(current, byteIndex, bit),
          xorBitWithConstant(keyBit, METHOD2_HMAC_INNER_PAD, bit)
        )
      ))
      constraints.push(F.mul(
        outerKeyBlock,
        F.sub(
          scheduleByteBit(current, byteIndex, bit),
          xorBitWithConstant(keyBit, METHOD2_HMAC_OUTER_PAD, bit)
        )
      ))
    }
  }

  for (let word = 0; word < SHA_STATE_WORDS; word++) {
    for (let bit = 0; bit < SHA_WORD_BITS; bit++) {
      const digestBitIndex = word * SHA_WORD_BITS + bit
      constraints.push(F.mul(
        captureInnerDigest,
        F.sub(
          current[layout.innerDigestBits + digestBitIndex],
          current[METHOD2_SHA256_BLOCK_LAYOUT.state + digestBitIndex]
        )
      ))
      constraints.push(F.mul(
        useInnerDigest,
        F.sub(
          current[METHOD2_SHA256_BLOCK_LAYOUT.schedule + digestBitIndex],
          current[layout.innerDigestBits + digestBitIndex]
        )
      ))
      constraints.push(F.mul(
        linkNext,
        F.sub(
          next[METHOD2_SHA256_BLOCK_LAYOUT.state + digestBitIndex],
          current[METHOD2_SHA256_BLOCK_LAYOUT.state + digestBitIndex]
        )
      ))
      constraints.push(F.mul(
        linkNext,
        F.sub(
          next[METHOD2_SHA256_BLOCK_LAYOUT.chain + digestBitIndex],
          current[METHOD2_SHA256_BLOCK_LAYOUT.chain + digestBitIndex]
        )
      ))
    }
  }

  return constraints
}

export function method2PrivateHmacSha256Metrics (
  trace: Method2PrivateHmacSha256Trace,
  proof?: StarkProof
): Method2PrivateHmacSha256Metrics {
  return {
    invoiceLength: trace.publicInput.invoice.length,
    innerBlocks: trace.publicInput.innerBlocks,
    outerBlocks: trace.publicInput.outerBlocks,
    totalBlocks: trace.publicInput.totalBlocks,
    activeRows: trace.publicInput.activeRows,
    paddedRows: trace.publicInput.traceLength,
    traceWidth: trace.layout.width,
    privateKeyBits: METHOD2_HMAC_KEY_SIZE * 8,
    privateInnerDigestBits: METHOD2_SHA256_DIGEST_SIZE * 8,
    committedCells: trace.publicInput.traceLength * trace.layout.width,
    proofBytes: proof === undefined ? undefined : serializeStarkProof(proof).length
  }
}

export function method2PrivateHmacSha256PublicInputDigest (
  publicInput: Method2PrivateHmacSha256PublicInput
): number[] {
  validateMethod2PrivateHmacSha256PublicInput(publicInput)
  const writer = new Writer()
  writer.write(toArray(METHOD2_PRIVATE_HMAC_SHA256_PUBLIC_INPUT_ID, 'utf8'))
  writer.writeVarIntNum(publicInput.invoice.length)
  writer.write(publicInput.invoice)
  writer.writeVarIntNum(publicInput.linkage.length)
  writer.write(publicInput.linkage)
  writer.writeVarIntNum(publicInput.innerBlocks)
  writer.writeVarIntNum(publicInput.outerBlocks)
  writer.writeVarIntNum(publicInput.totalBlocks)
  writer.writeVarIntNum(publicInput.activeRows)
  writer.writeVarIntNum(publicInput.traceLength)
  writer.writeVarIntNum(METHOD2_PRIVATE_HMAC_SHA256_LAYOUT.width)
  return sha256(writer.toArray())
}

export function validateMethod2PrivateHmacSha256Trace (
  trace: Method2PrivateHmacSha256Trace
): void {
  validateMethod2PrivateHmacSha256PublicInput(trace.publicInput)
  assertBytes(trace.key, METHOD2_HMAC_KEY_SIZE, 'HMAC key')
  if (!bytesEqual(hmacSha256(trace.key, trace.publicInput.invoice), trace.publicInput.linkage)) {
    throw new Error('Private HMAC-SHA256 trace linkage mismatch')
  }
  if (!bytesEqual(trace.innerDigest, sha256Digest(innerHmacInput(
    trace.key,
    trace.publicInput.invoice
  )))) {
    throw new Error('Private HMAC-SHA256 inner digest mismatch')
  }
  if (!bytesEqual(trace.innerMessage, sha256Pad(innerHmacInput(
    trace.key,
    trace.publicInput.invoice
  )))) {
    throw new Error('Private HMAC-SHA256 inner message mismatch')
  }
  if (!bytesEqual(trace.outerMessage, sha256Pad(outerHmacInput(
    trace.key,
    trace.innerDigest
  )))) {
    throw new Error('Private HMAC-SHA256 outer message mismatch')
  }
  if (trace.layout.width !== METHOD2_PRIVATE_HMAC_SHA256_LAYOUT.width) {
    throw new Error('Private HMAC-SHA256 layout mismatch')
  }
  if (trace.rows.length !== trace.publicInput.traceLength) {
    throw new Error('Private HMAC-SHA256 trace length mismatch')
  }
  for (const row of trace.rows) {
    if (row.length !== trace.layout.width) {
      throw new Error('Private HMAC-SHA256 trace row width mismatch')
    }
  }
}

export function validateMethod2PrivateHmacSha256PublicInput (
  publicInput: Method2PrivateHmacSha256PublicInput
): void {
  assertBytes(publicInput.invoice, undefined, 'invoice')
  assertBytes(publicInput.linkage, METHOD2_SHA256_DIGEST_SIZE, 'linkage')
  const expected = method2PrivateHmacSha256PublicInput(
    publicInput.invoice,
    publicInput.linkage
  )
  if (
    publicInput.innerBlocks !== expected.innerBlocks ||
    publicInput.outerBlocks !== expected.outerBlocks ||
    publicInput.totalBlocks !== expected.totalBlocks ||
    publicInput.activeRows !== expected.activeRows ||
    publicInput.traceLength !== expected.traceLength
  ) {
    throw new Error('Private HMAC-SHA256 public input shape mismatch')
  }
}

export function method2PrivateHmacSha256KeyForLink (
  trace: Method2PrivateHmacSha256Trace
): number[] {
  validateMethod2PrivateHmacSha256Trace(trace)
  return trace.key.slice()
}

function method2PrivateHmacSha256BoundaryConstraints (
  publicInput: Method2PrivateHmacSha256PublicInput
): AirDefinition['boundaryConstraints'] {
  const constraints: AirDefinition['boundaryConstraints'] = []
  const innerStart = 0
  const outerStart = publicInput.innerBlocks * HMAC_BLOCK_STRIDE
  constraints.push(...stateBoundaryConstraints(
    innerStart,
    METHOD2_SHA256_BLOCK_LAYOUT.state,
    METHOD2_SHA256_INITIAL_STATE
  ))
  constraints.push(...stateBoundaryConstraints(
    innerStart,
    METHOD2_SHA256_BLOCK_LAYOUT.chain,
    METHOD2_SHA256_INITIAL_STATE
  ))
  constraints.push(...stateBoundaryConstraints(
    outerStart,
    METHOD2_SHA256_BLOCK_LAYOUT.state,
    METHOD2_SHA256_INITIAL_STATE
  ))
  constraints.push(...stateBoundaryConstraints(
    outerStart,
    METHOD2_SHA256_BLOCK_LAYOUT.chain,
    METHOD2_SHA256_INITIAL_STATE
  ))
  constraints.push(...stateBoundaryConstraints(
    finalOuterResultRow(publicInput),
    METHOD2_SHA256_BLOCK_LAYOUT.state,
    bytesToWordsBE(publicInput.linkage)
  ))

  for (const binding of publicScheduleByteBindings(publicInput)) {
    for (let bit = 0; bit < 8; bit++) {
      constraints.push({
        column: scheduleByteBitColumn(binding.byteIndex, bit),
        row: binding.row,
        value: BigInt((binding.value >>> bit) & 1)
      })
    }
  }
  return constraints
}

function method2PrivateHmacSha256FullBoundaryColumns (
  publicInput: Method2PrivateHmacSha256PublicInput
): AirDefinition['fullBoundaryColumns'] {
  const layout = METHOD2_PRIVATE_HMAC_SHA256_LAYOUT
  const traceLength = publicInput.traceLength
  const columns: AirDefinition['fullBoundaryColumns'] = [
    {
      column: METHOD2_SHA256_BLOCK_LAYOUT.active,
      values: new Array<FieldElement>(traceLength).fill(0n)
    },
    {
      column: METHOD2_SHA256_BLOCK_LAYOUT.scheduleActive,
      values: new Array<FieldElement>(traceLength).fill(0n)
    },
    {
      column: METHOD2_SHA256_BLOCK_LAYOUT.last,
      values: new Array<FieldElement>(traceLength).fill(0n)
    },
    {
      column: layout.linkNext,
      values: new Array<FieldElement>(traceLength).fill(0n)
    },
    {
      column: layout.keyInit,
      values: new Array<FieldElement>(traceLength).fill(0n)
    },
    {
      column: layout.keyCarry,
      values: new Array<FieldElement>(traceLength).fill(0n)
    },
    {
      column: layout.innerKeyBlock,
      values: new Array<FieldElement>(traceLength).fill(0n)
    },
    {
      column: layout.outerKeyBlock,
      values: new Array<FieldElement>(traceLength).fill(0n)
    },
    {
      column: layout.captureInnerDigest,
      values: new Array<FieldElement>(traceLength).fill(0n)
    },
    {
      column: layout.digestCarry,
      values: new Array<FieldElement>(traceLength).fill(0n)
    },
    {
      column: layout.useInnerDigest,
      values: new Array<FieldElement>(traceLength).fill(0n)
    },
    ...Array.from({ length: SHA_WORD_BITS }, (_, bit) => ({
      column: METHOD2_SHA256_BLOCK_LAYOUT.k + bit,
      values: new Array<FieldElement>(traceLength).fill(0n)
    }))
  ]
  const byColumn = new Map(columns.map(column => [column.column, column.values]))
  const selectors = hmacSelectorValues(publicInput)
  byColumn.get(layout.linkNext)?.splice(0, traceLength, ...selectors.linkNext)
  byColumn.get(layout.keyInit)?.splice(0, traceLength, ...selectors.keyInit)
  byColumn.get(layout.keyCarry)?.splice(0, traceLength, ...selectors.keyCarry)
  byColumn.get(layout.innerKeyBlock)?.splice(0, traceLength, ...selectors.innerKeyBlock)
  byColumn.get(layout.outerKeyBlock)?.splice(0, traceLength, ...selectors.outerKeyBlock)
  byColumn.get(layout.captureInnerDigest)?.splice(
    0,
    traceLength,
    ...selectors.captureInnerDigest
  )
  byColumn.get(layout.digestCarry)?.splice(0, traceLength, ...selectors.digestCarry)
  byColumn.get(layout.useInnerDigest)?.splice(0, traceLength, ...selectors.useInnerDigest)

  for (const block of hmacBlockPlans(publicInput)) {
    for (let round = 0; round < SHA_ROUNDS; round++) {
      const row = block.startRow + round
      byColumn.get(METHOD2_SHA256_BLOCK_LAYOUT.active)?.splice(row, 1, 1n)
      byColumn.get(METHOD2_SHA256_BLOCK_LAYOUT.last)?.splice(
        row,
        1,
        round === SHA_ROUNDS - 1 ? 1n : 0n
      )
      byColumn.get(METHOD2_SHA256_BLOCK_LAYOUT.scheduleActive)?.splice(
        row,
        1,
        round < SHA_ROUNDS - 16 ? 1n : 0n
      )
      const kBits = numberToBitsLE(METHOD2_SHA256_K[round], SHA_WORD_BITS)
      for (let bit = 0; bit < SHA_WORD_BITS; bit++) {
        byColumn.get(METHOD2_SHA256_BLOCK_LAYOUT.k + bit)?.splice(
          row,
          1,
          BigInt(kBits[bit])
        )
      }
    }
  }
  return columns
}

function hmacSelectorValues (
  publicInput: Method2PrivateHmacSha256PublicInput
): Method2PrivateHmacSha256Selectors {
  const values = {
    linkNext: zeroColumn(publicInput),
    keyInit: zeroColumn(publicInput),
    keyCarry: zeroColumn(publicInput),
    innerKeyBlock: zeroColumn(publicInput),
    outerKeyBlock: zeroColumn(publicInput),
    captureInnerDigest: zeroColumn(publicInput),
    digestCarry: zeroColumn(publicInput),
    useInnerDigest: zeroColumn(publicInput)
  }
  values.keyInit[0] = 1n
  values.innerKeyBlock[0] = 1n
  values.outerKeyBlock[publicInput.innerBlocks * HMAC_BLOCK_STRIDE] = 1n
  values.captureInnerDigest[innerFinalResultRow(publicInput)] = 1n
  values.useInnerDigest[outerDigestBlockStartRow(publicInput)] = 1n
  for (let row = 0; row < publicInput.activeRows - 1; row++) {
    values.keyCarry[row] = 1n
  }
  for (
    let row = innerFinalResultRow(publicInput);
    row < outerDigestBlockStartRow(publicInput);
    row++
  ) {
    values.digestCarry[row] = 1n
  }
  for (const block of hmacBlockPlans(publicInput)) {
    if (!block.linkToNext) continue
    values.linkNext[block.resultRow] = 1n
  }
  return values
}

function publicScheduleByteBindings (
  publicInput: Method2PrivateHmacSha256PublicInput
): Array<{ row: number, byteIndex: number, value: number }> {
  const bindings: Array<{ row: number, byteIndex: number, value: number }> = []
  const publicInnerMessage = sha256Pad([
    ...new Array<number>(METHOD2_HMAC_BLOCK_SIZE).fill(0),
    ...publicInput.invoice
  ])
  const publicOuterMessage = sha256Pad([
    ...new Array<number>(METHOD2_HMAC_BLOCK_SIZE).fill(0),
    ...new Array<number>(METHOD2_SHA256_DIGEST_SIZE).fill(0)
  ])
  for (const block of hmacBlockPlans(publicInput)) {
    if (block.kind === 'inner-key') {
      for (let byte = METHOD2_HMAC_KEY_SIZE; byte < METHOD2_HMAC_BLOCK_SIZE; byte++) {
        bindings.push({
          row: block.startRow,
          byteIndex: byte,
          value: METHOD2_HMAC_INNER_PAD
        })
      }
    } else if (block.kind === 'outer-key') {
      for (let byte = METHOD2_HMAC_KEY_SIZE; byte < METHOD2_HMAC_BLOCK_SIZE; byte++) {
        bindings.push({
          row: block.startRow,
          byteIndex: byte,
          value: METHOD2_HMAC_OUTER_PAD
        })
      }
    } else if (block.kind === 'inner-public') {
      for (let byte = 0; byte < METHOD2_HMAC_BLOCK_SIZE; byte++) {
        bindings.push({
          row: block.startRow,
          byteIndex: byte,
          value: publicInnerMessage[block.blockIndex * METHOD2_HMAC_BLOCK_SIZE + byte]
        })
      }
    } else {
      for (let byte = METHOD2_SHA256_DIGEST_SIZE; byte < METHOD2_HMAC_BLOCK_SIZE; byte++) {
        bindings.push({
          row: block.startRow,
          byteIndex: byte,
          value: publicOuterMessage[block.blockIndex * METHOD2_HMAC_BLOCK_SIZE + byte]
        })
      }
    }
  }
  return bindings
}

function hmacBlockPlans (
  publicInput: Method2PrivateHmacSha256PublicInput
): Method2PrivateHmacSha256BlockPlan[] {
  const plans: Method2PrivateHmacSha256BlockPlan[] = []
  for (let block = 0; block < publicInput.innerBlocks; block++) {
    const startRow = block * HMAC_BLOCK_STRIDE
    plans.push({
      chain: 'inner',
      kind: block === 0 ? 'inner-key' : 'inner-public',
      blockIndex: block,
      startRow,
      resultRow: startRow + SHA_RESULT_ROW,
      linkToNext: block < publicInput.innerBlocks - 1
    })
  }
  const outerStart = publicInput.innerBlocks * HMAC_BLOCK_STRIDE
  for (let block = 0; block < publicInput.outerBlocks; block++) {
    const startRow = outerStart + block * HMAC_BLOCK_STRIDE
    plans.push({
      chain: 'outer',
      kind: block === 0 ? 'outer-key' : 'outer-digest',
      blockIndex: block,
      startRow,
      resultRow: startRow + SHA_RESULT_ROW,
      linkToNext: block < publicInput.outerBlocks - 1
    })
  }
  return plans
}

function stateBoundaryConstraints (
  row: number,
  offset: number,
  words: number[]
): AirDefinition['boundaryConstraints'] {
  const constraints: AirDefinition['boundaryConstraints'] = []
  for (let word = 0; word < words.length; word++) {
    const bits = numberToBitsLE(words[word], SHA_WORD_BITS)
    for (let bit = 0; bit < SHA_WORD_BITS; bit++) {
      constraints.push({
        row,
        column: offset + word * SHA_WORD_BITS + bit,
        value: BigInt(bits[bit])
      })
    }
  }
  return constraints
}

function innerHmacInput (key: number[], invoice: number[]): number[] {
  const keyBlock = hmacKeyBlock(key)
  return [
    ...keyBlock.map(byte => byte ^ METHOD2_HMAC_INNER_PAD),
    ...invoice
  ]
}

function outerHmacInput (key: number[], innerDigest: number[]): number[] {
  const keyBlock = hmacKeyBlock(key)
  return [
    ...keyBlock.map(byte => byte ^ METHOD2_HMAC_OUTER_PAD),
    ...innerDigest
  ]
}

function hmacKeyBlock (key: number[]): number[] {
  assertBytes(key, METHOD2_HMAC_KEY_SIZE, 'HMAC key')
  const keyBlock = key.slice()
  while (keyBlock.length < METHOD2_HMAC_BLOCK_SIZE) keyBlock.push(0)
  return keyBlock
}

function scheduleByteBit (
  row: FieldElement[],
  byteIndex: number,
  bit: number
): FieldElement {
  return row[scheduleByteBitColumn(byteIndex, bit)]
}

function scheduleByteBitColumn (
  byteIndex: number,
  bit: number
): number {
  const word = Math.floor(byteIndex / 4)
  const byteInWord = byteIndex % 4
  return METHOD2_SHA256_BLOCK_LAYOUT.schedule +
    word * SHA_WORD_BITS +
    (3 - byteInWord) * 8 +
    bit
}

function xorBitWithConstant (
  bit: FieldElement,
  constant: number,
  bitIndex: number
): FieldElement {
  return ((constant >>> bitIndex) & 1) === 0 ? bit : F.sub(1n, bit)
}

function bytesToBits (bytes: number[]): number[] {
  const out: number[] = []
  for (const byte of bytes) {
    out.push(...numberToBitsLE(byte, 8))
  }
  return out
}

function wordsToBitsLE (words: number[]): number[] {
  const out: number[] = []
  for (const word of words) out.push(...numberToBitsLE(word, SHA_WORD_BITS))
  return out
}

function numberToBitsLE (value: number, bits: number): number[] {
  return toBitsLE(BigInt(value >>> 0), bits)
}

function writeBits (
  row: FieldElement[],
  offset: number,
  bits: number[]
): void {
  for (let bit = 0; bit < bits.length; bit++) {
    row[offset + bit] = BigInt(bits[bit])
  }
}

function bytesToWordsBE (bytes: number[]): number[] {
  if (bytes.length % 4 !== 0) throw new Error('Byte length must be word-aligned')
  const words: number[] = []
  for (let offset = 0; offset < bytes.length; offset += 4) {
    words.push(
      ((bytes[offset] << 24) |
        (bytes[offset + 1] << 16) |
        (bytes[offset + 2] << 8) |
        bytes[offset + 3]) >>> 0
    )
  }
  return words
}

function innerFinalResultRow (
  publicInput: Method2PrivateHmacSha256PublicInput
): number {
  return publicInput.innerBlocks * HMAC_BLOCK_STRIDE - 1
}

function outerDigestBlockStartRow (
  publicInput: Method2PrivateHmacSha256PublicInput
): number {
  return (publicInput.innerBlocks + 1) * HMAC_BLOCK_STRIDE
}

function finalOuterResultRow (
  publicInput: Method2PrivateHmacSha256PublicInput
): number {
  return publicInput.activeRows - 1
}

function zeroColumn (
  publicInput: Method2PrivateHmacSha256PublicInput
): FieldElement[] {
  return new Array<FieldElement>(publicInput.traceLength).fill(0n)
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}

function assertBytes (
  bytes: number[],
  length: number | undefined,
  label: string
): void {
  if (length !== undefined && bytes.length !== length) {
    throw new Error(`Invalid ${label} length`)
  }
  for (const byte of bytes) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`Invalid ${label} byte`)
    }
  }
}

function bytesEqual (left: number[], right: number[]): boolean {
  return left.length === right.length &&
    left.every((byte, index) => byte === right[index])
}

function booleanConstraint (value: FieldElement): FieldElement {
  return F.mul(value, F.sub(value, 1n))
}
