import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import {
  hmacSha256,
  sha256Digest,
  sha256Pad,
  sha256Schedule
} from '../circuit/Sha256.js'
import { toBitsLE } from '../circuit/Limbs.js'
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
  METHOD2_SHA256_INITIAL_STATE,
  METHOD2_SHA256_K
} from './Method2Sha256.js'

export const METHOD2_COMPACT_HMAC_SHA256_TRANSCRIPT_DOMAIN =
  'BRC97_METHOD2_COMPACT_HMAC_SHA256_AIR_V1'
export const METHOD2_COMPACT_HMAC_SHA256_PUBLIC_INPUT_ID =
  'BRC97_METHOD2_COMPACT_HMAC_SHA256_PUBLIC_INPUT_V1'

export const METHOD2_COMPACT_HMAC_SHA256_STARK_OPTIONS = {
  blowupFactor: 4,
  numQueries: 4,
  maxRemainderSize: 16,
  maskDegree: 1,
  cosetOffset: 3n,
  transcriptDomain: METHOD2_COMPACT_HMAC_SHA256_TRANSCRIPT_DOMAIN
} as const

const WORD_BITS = 32
const CHUNK_BITS = 16
const CHUNK_BASE = 1n << BigInt(CHUNK_BITS)
const WORD_CHUNKS = 2
const STATE_WORDS = 8
const SCHEDULE_WINDOW = 16
const SHA_ROUNDS = 64
const SHA_RESULT_ROW = 64
const BLOCK_STRIDE = SHA_RESULT_ROW + 1

export interface Method2CompactHmacSha256Layout {
  active: number
  scheduleActive: number
  last: number
  linkNext: number
  keyInit: number
  keyCarry: number
  innerKeyBlock: number
  outerKeyBlock: number
  captureInnerDigest: number
  digestCarry: number
  useInnerDigest: number
  chain: number
  state: number
  schedule: number
  k: number
  sigma0: number
  sigma1: number
  ch: number
  maj: number
  smallSigma0: number
  smallSigma1: number
  t1: number
  t2: number
  roundA: number
  roundE: number
  t1Carry: number
  t2Carry: number
  roundACarry: number
  roundECarry: number
  scheduleCarry: number
  finalCarry: number
  aBits: number
  bBits: number
  cBits: number
  eBits: number
  fBits: number
  gBits: number
  schedule1Bits: number
  schedule14Bits: number
  keyBytes: number
  innerKeyBytes: number
  outerKeyBytes: number
  keyCheckBits: number
  keyCheckSelectors: number
  innerDigestChunks: number
  width: number
}

export interface Method2CompactHmacSha256PublicInput {
  invoice: number[]
  linkage: number[]
  innerBlocks: number
  outerBlocks: number
  totalBlocks: number
  activeRows: number
  traceLength: number
}

export interface Method2CompactHmacSha256Trace {
  publicInput: Method2CompactHmacSha256PublicInput
  key: number[]
  innerDigest: number[]
  innerMessage: number[]
  outerMessage: number[]
  rows: FieldElement[][]
  layout: Method2CompactHmacSha256Layout
}

export interface Method2CompactHmacSha256Metrics {
  invoiceLength: number
  innerBlocks: number
  outerBlocks: number
  totalBlocks: number
  activeRows: number
  paddedRows: number
  traceWidth: number
  committedCells: number
  proofBytes?: number
}

interface CompactBlockPlan {
  chain: 'inner' | 'outer'
  kind: 'inner-key' | 'inner-public' | 'outer-key' | 'outer-digest'
  blockIndex: number
  startRow: number
  resultRow: number
  linkToNext: boolean
}

interface CompactSelectors {
  active: FieldElement[]
  scheduleActive: FieldElement[]
  last: FieldElement[]
  linkNext: FieldElement[]
  keyInit: FieldElement[]
  keyCarry: FieldElement[]
  innerKeyBlock: FieldElement[]
  outerKeyBlock: FieldElement[]
  captureInnerDigest: FieldElement[]
  digestCarry: FieldElement[]
  useInnerDigest: FieldElement[]
  keyCheckSelectors: FieldElement[][]
}

export const METHOD2_COMPACT_HMAC_SHA256_LAYOUT:
Method2CompactHmacSha256Layout = (() => {
  let offset = 0
  const take = (width: number): number => {
    const current = offset
    offset += width
    return current
  }
  const layout = {
    active: take(1),
    scheduleActive: take(1),
    last: take(1),
    linkNext: take(1),
    keyInit: take(1),
    keyCarry: take(1),
    innerKeyBlock: take(1),
    outerKeyBlock: take(1),
    captureInnerDigest: take(1),
    digestCarry: take(1),
    useInnerDigest: take(1),
    chain: take(STATE_WORDS * WORD_CHUNKS),
    state: take(STATE_WORDS * WORD_CHUNKS),
    schedule: take(SCHEDULE_WINDOW * WORD_CHUNKS),
    k: take(WORD_CHUNKS),
    sigma0: take(WORD_CHUNKS),
    sigma1: take(WORD_CHUNKS),
    ch: take(WORD_CHUNKS),
    maj: take(WORD_CHUNKS),
    smallSigma0: take(WORD_CHUNKS),
    smallSigma1: take(WORD_CHUNKS),
    t1: take(WORD_CHUNKS),
    t2: take(WORD_CHUNKS),
    roundA: take(WORD_CHUNKS),
    roundE: take(WORD_CHUNKS),
    t1Carry: take(WORD_CHUNKS),
    t2Carry: take(WORD_CHUNKS),
    roundACarry: take(WORD_CHUNKS),
    roundECarry: take(WORD_CHUNKS),
    scheduleCarry: take(WORD_CHUNKS),
    finalCarry: take(STATE_WORDS * WORD_CHUNKS),
    aBits: take(WORD_BITS),
    bBits: take(WORD_BITS),
    cBits: take(WORD_BITS),
    eBits: take(WORD_BITS),
    fBits: take(WORD_BITS),
    gBits: take(WORD_BITS),
    schedule1Bits: take(WORD_BITS),
    schedule14Bits: take(WORD_BITS),
    keyBytes: take(METHOD2_HMAC_KEY_SIZE),
    innerKeyBytes: take(METHOD2_HMAC_KEY_SIZE),
    outerKeyBytes: take(METHOD2_HMAC_KEY_SIZE),
    keyCheckBits: take(24),
    keyCheckSelectors: take(METHOD2_HMAC_KEY_SIZE),
    innerDigestChunks: take(STATE_WORDS * WORD_CHUNKS),
    width: 0
  }
  layout.width = offset
  return layout
})()

export function buildMethod2CompactHmacSha256Trace (
  key: number[],
  invoice: number[],
  linkage: number[] = hmacSha256(key, invoice),
  options: { minTraceLength?: number } = {}
): Method2CompactHmacSha256Trace {
  assertBytes(key, METHOD2_HMAC_KEY_SIZE, 'HMAC key')
  assertBytes(invoice, undefined, 'invoice')
  assertBytes(linkage, METHOD2_SHA256_DIGEST_SIZE, 'linkage')
  if (!bytesEqual(hmacSha256(key, invoice), linkage)) {
    throw new Error('Compact HMAC-SHA256 linkage does not match key and invoice')
  }
  const publicInput = method2CompactHmacSha256PublicInput(
    invoice,
    linkage,
    options
  )
  const layout = METHOD2_COMPACT_HMAC_SHA256_LAYOUT
  const inactiveRow = new Array<FieldElement>(layout.width).fill(0n)
  const rows = new Array<FieldElement[]>(publicInput.traceLength)
    .fill(inactiveRow)
  for (let rowIndex = 0; rowIndex < publicInput.activeRows; rowIndex++) {
    rows[rowIndex] = inactiveRow.slice()
  }
  const innerKeyBytes = key.map(byte => byte ^ METHOD2_HMAC_INNER_PAD)
  const outerKeyBytes = key.map(byte => byte ^ METHOD2_HMAC_OUTER_PAD)
  const innerDigest = sha256Digest(innerHmacInput(key, invoice))
  const innerMessage = sha256Pad(innerHmacInput(key, invoice))
  const outerMessage = sha256Pad(outerHmacInput(key, innerDigest))
  const innerDigestWords = bytesToWordsBE(innerDigest)
  const selectors = compactSelectorValues(publicInput)

  for (let rowIndex = 0; rowIndex < publicInput.activeRows; rowIndex++) {
    const row = rows[rowIndex]
    row[layout.active] = selectors.active[rowIndex]
    row[layout.scheduleActive] = selectors.scheduleActive[rowIndex]
    row[layout.last] = selectors.last[rowIndex]
    row[layout.linkNext] = selectors.linkNext[rowIndex]
    row[layout.keyInit] = selectors.keyInit[rowIndex]
    row[layout.keyCarry] = selectors.keyCarry[rowIndex]
    row[layout.innerKeyBlock] = selectors.innerKeyBlock[rowIndex]
    row[layout.outerKeyBlock] = selectors.outerKeyBlock[rowIndex]
    row[layout.captureInnerDigest] = selectors.captureInnerDigest[rowIndex]
    row[layout.digestCarry] = selectors.digestCarry[rowIndex]
    row[layout.useInnerDigest] = selectors.useInnerDigest[rowIndex]
    writeByteColumns(row, layout.keyBytes, key)
    writeByteColumns(row, layout.innerKeyBytes, innerKeyBytes)
    writeByteColumns(row, layout.outerKeyBytes, outerKeyBytes)
    for (let byteIndex = 0; byteIndex < METHOD2_HMAC_KEY_SIZE; byteIndex++) {
      row[layout.keyCheckSelectors + byteIndex] =
        selectors.keyCheckSelectors[byteIndex][rowIndex]
    }
    if (rowIndex < METHOD2_HMAC_KEY_SIZE) {
      writeBits(
        row,
        layout.keyCheckBits,
        numberToBitsLE(key[rowIndex], 8)
      )
      writeBits(
        row,
        layout.keyCheckBits + 8,
        numberToBitsLE(innerKeyBytes[rowIndex], 8)
      )
      writeBits(
        row,
        layout.keyCheckBits + 16,
        numberToBitsLE(outerKeyBytes[rowIndex], 8)
      )
    }
    if (rowIndex >= innerFinalResultRow(publicInput)) {
      writeWords(row, layout.innerDigestChunks, innerDigestWords)
    }
  }

  let innerState = METHOD2_SHA256_INITIAL_STATE.slice()
  let outerState = METHOD2_SHA256_INITIAL_STATE.slice()
  for (const block of compactBlockPlans(publicInput)) {
    const message = block.chain === 'inner' ? innerMessage : outerMessage
    const initialState = block.chain === 'inner' ? innerState : outerState
    const blockBytes = message.slice(
      block.blockIndex * METHOD2_HMAC_BLOCK_SIZE,
      (block.blockIndex + 1) * METHOD2_HMAC_BLOCK_SIZE
    )
    const outputState = writeCompactBlockRows(
      rows,
      block.startRow,
      initialState,
      blockBytes,
      layout
    )
    if (block.chain === 'inner') {
      innerState = outputState
    } else {
      outerState = outputState
    }
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
  validateMethod2CompactHmacSha256Trace(trace)
  return trace
}

export function method2CompactHmacSha256PublicInput (
  invoice: number[],
  linkage: number[],
  options: { minTraceLength?: number } = {}
): Method2CompactHmacSha256PublicInput {
  assertBytes(invoice, undefined, 'invoice')
  assertBytes(linkage, METHOD2_SHA256_DIGEST_SIZE, 'linkage')
  const innerBlocks = sha256Pad([
    ...new Array<number>(METHOD2_HMAC_BLOCK_SIZE).fill(0),
    ...invoice
  ]).length / METHOD2_HMAC_BLOCK_SIZE
  const outerBlocks = sha256Pad([
    ...new Array<number>(METHOD2_HMAC_BLOCK_SIZE).fill(0),
    ...new Array<number>(METHOD2_SHA256_DIGEST_SIZE).fill(0)
  ]).length / METHOD2_HMAC_BLOCK_SIZE
  if (!Number.isInteger(innerBlocks) || !Number.isInteger(outerBlocks)) {
    throw new Error('Compact HMAC-SHA256 block count is invalid')
  }
  const totalBlocks = innerBlocks + outerBlocks
  const activeRows = totalBlocks * BLOCK_STRIDE
  return {
    invoice: invoice.slice(),
    linkage: linkage.slice(),
    innerBlocks,
    outerBlocks,
    totalBlocks,
    activeRows,
    traceLength: nextPowerOfTwo(Math.max(
      activeRows,
      options.minTraceLength ?? 0
    ))
  }
}

export function buildMethod2CompactHmacSha256Air (
  publicInput: Method2CompactHmacSha256PublicInput
): AirDefinition {
  validateMethod2CompactHmacSha256PublicInput(publicInput)
  const layout = METHOD2_COMPACT_HMAC_SHA256_LAYOUT
  return {
    traceWidth: layout.width,
    transitionDegree: 8,
    publicInputDigest: method2CompactHmacSha256PublicInputDigest(publicInput),
    boundaryConstraints: compactBoundaryConstraints(publicInput),
    fullBoundaryColumns: compactFullBoundaryColumns(publicInput),
    evaluateTransition: (current, next) =>
      evaluateMethod2CompactHmacSha256Transition(current, next, layout)
  }
}

export function proveMethod2CompactHmacSha256 (
  trace: Method2CompactHmacSha256Trace,
  options: StarkProverOptions = {}
): StarkProof {
  validateMethod2CompactHmacSha256Trace(trace)
  const air = buildMethod2CompactHmacSha256Air(trace.publicInput)
  return proveStark(air, trace.rows, {
    ...METHOD2_COMPACT_HMAC_SHA256_STARK_OPTIONS,
    ...options,
    publicInputDigest: air.publicInputDigest,
    transcriptDomain: METHOD2_COMPACT_HMAC_SHA256_TRANSCRIPT_DOMAIN
  })
}

export function verifyMethod2CompactHmacSha256 (
  publicInput: Method2CompactHmacSha256PublicInput,
  proof: StarkProof
): boolean {
  try {
    if (!method2CompactHmacSha256ProofMeetsMinimumProfile(proof)) {
      return false
    }
    const air = buildMethod2CompactHmacSha256Air(publicInput)
    return verifyStark(air, proof, {
      blowupFactor: proof.blowupFactor,
      numQueries: proof.numQueries,
      maxRemainderSize: proof.maxRemainderSize,
      maskDegree: proof.maskDegree,
      cosetOffset: proof.cosetOffset,
      traceDegreeBound: proof.traceDegreeBound,
      compositionDegreeBound: proof.compositionDegreeBound,
      publicInputDigest: air.publicInputDigest,
      transcriptDomain: METHOD2_COMPACT_HMAC_SHA256_TRANSCRIPT_DOMAIN
    })
  } catch {
    return false
  }
}

function method2CompactHmacSha256ProofMeetsMinimumProfile (
  proof: StarkProof
): boolean {
  return proof.blowupFactor >=
    METHOD2_COMPACT_HMAC_SHA256_STARK_OPTIONS.blowupFactor &&
    proof.numQueries >= METHOD2_COMPACT_HMAC_SHA256_STARK_OPTIONS.numQueries &&
    proof.maxRemainderSize <=
      METHOD2_COMPACT_HMAC_SHA256_STARK_OPTIONS.maxRemainderSize &&
    proof.maskDegree >= METHOD2_COMPACT_HMAC_SHA256_STARK_OPTIONS.maskDegree &&
    proof.cosetOffset !== 0n
}

export function evaluateMethod2CompactHmacSha256Transition (
  current: FieldElement[],
  next: FieldElement[],
  layout: Method2CompactHmacSha256Layout = METHOD2_COMPACT_HMAC_SHA256_LAYOUT
): FieldElement[] {
  const active = current[layout.active]
  const scheduleActive = current[layout.scheduleActive]
  const last = current[layout.last]
  const notLast = F.mul(active, F.sub(1n, last))
  const isLast = F.mul(active, last)
  const constraints: FieldElement[] = [
    booleanConstraint(active),
    booleanConstraint(scheduleActive),
    booleanConstraint(last),
    F.mul(scheduleActive, F.sub(scheduleActive, active)),
    F.mul(last, F.sub(last, active))
  ]

  const chain = readWords(current, layout.chain, STATE_WORDS)
  const state = readWords(current, layout.state, STATE_WORDS)
  const nextChain = readWords(next, layout.chain, STATE_WORDS)
  const nextState = readWords(next, layout.state, STATE_WORDS)
  const schedule = readWords(current, layout.schedule, SCHEDULE_WINDOW)
  const nextSchedule = readWords(next, layout.schedule, SCHEDULE_WINDOW)
  const k = readWord(current, layout.k)
  const sigma0 = readWord(current, layout.sigma0)
  const sigma1 = readWord(current, layout.sigma1)
  const ch = readWord(current, layout.ch)
  const maj = readWord(current, layout.maj)
  const smallSigma0 = readWord(current, layout.smallSigma0)
  const smallSigma1 = readWord(current, layout.smallSigma1)
  const t1 = readWord(current, layout.t1)
  const t2 = readWord(current, layout.t2)
  const roundA = readWord(current, layout.roundA)
  const roundE = readWord(current, layout.roundE)

  const aBits = wordBits(current, layout.aBits)
  const bBits = wordBits(current, layout.bBits)
  const cBits = wordBits(current, layout.cBits)
  const eBits = wordBits(current, layout.eBits)
  const fBits = wordBits(current, layout.fBits)
  const gBits = wordBits(current, layout.gBits)
  const schedule1Bits = wordBits(current, layout.schedule1Bits)
  const schedule14Bits = wordBits(current, layout.schedule14Bits)

  constraints.push(...gated(active, bitBooleanConstraintsForBits(aBits)))
  constraints.push(...gated(active, bitBooleanConstraintsForBits(bBits)))
  constraints.push(...gated(active, bitBooleanConstraintsForBits(cBits)))
  constraints.push(...gated(active, bitBooleanConstraintsForBits(eBits)))
  constraints.push(...gated(active, bitBooleanConstraintsForBits(fBits)))
  constraints.push(...gated(active, bitBooleanConstraintsForBits(gBits)))
  constraints.push(...gated(active, bitBooleanConstraintsForBits(schedule1Bits)))
  constraints.push(...gated(active, bitBooleanConstraintsForBits(schedule14Bits)))

  constraints.push(...gated(active, wordEqualsBits(state[0], aBits)))
  constraints.push(...gated(active, wordEqualsBits(state[1], bBits)))
  constraints.push(...gated(active, wordEqualsBits(state[2], cBits)))
  constraints.push(...gated(active, wordEqualsBits(state[4], eBits)))
  constraints.push(...gated(active, wordEqualsBits(state[5], fBits)))
  constraints.push(...gated(active, wordEqualsBits(state[6], gBits)))
  constraints.push(...gated(active, wordEqualsBits(schedule[1], schedule1Bits)))
  constraints.push(...gated(active, wordEqualsBits(schedule[14], schedule14Bits)))

  constraints.push(...gated(active, wordEqualsBits(
    sigma0,
    bigSigma0Bits(aBits)
  )))
  constraints.push(...gated(active, wordEqualsBits(
    sigma1,
    bigSigma1Bits(eBits)
  )))
  constraints.push(...gated(active, wordEqualsBits(
    ch,
    chBits(eBits, fBits, gBits)
  )))
  constraints.push(...gated(active, wordEqualsBits(
    maj,
    majBits(aBits, bBits, cBits)
  )))
  constraints.push(...gated(active, wordEqualsBits(
    smallSigma0,
    smallSigma0Bits(schedule1Bits)
  )))
  constraints.push(...gated(active, wordEqualsBits(
    smallSigma1,
    smallSigma1Bits(schedule14Bits)
  )))

  constraints.push(...gated(active, addWordsConstraint(
    [state[7], sigma1, ch, k, schedule[0]],
    t1,
    current,
    layout.t1Carry,
    5
  )))
  constraints.push(...gated(active, addWordsConstraint(
    [sigma0, maj],
    t2,
    current,
    layout.t2Carry,
    2
  )))
  constraints.push(...gated(active, addWordsConstraint(
    [t1, t2],
    roundA,
    current,
    layout.roundACarry,
    2
  )))
  constraints.push(...gated(active, addWordsConstraint(
    [state[3], t1],
    roundE,
    current,
    layout.roundECarry,
    2
  )))

  const roundOutput = [
    roundA,
    state[0],
    state[1],
    state[2],
    roundE,
    state[4],
    state[5],
    state[6]
  ]
  for (let word = 0; word < STATE_WORDS; word++) {
    constraints.push(...gated(notLast, wordEquality(nextState[word], roundOutput[word])))
    constraints.push(...gated(notLast, wordEquality(nextChain[word], chain[word])))
    constraints.push(...gated(isLast, addWordsConstraint(
      [chain[word], roundOutput[word]],
      nextState[word],
      current,
      layout.finalCarry + word * WORD_CHUNKS,
      2
    )))
    constraints.push(...gated(isLast, wordEquality(nextChain[word], nextState[word])))
  }

  for (let word = 0; word < SCHEDULE_WINDOW - 1; word++) {
    constraints.push(...gated(notLast, wordEquality(nextSchedule[word], schedule[word + 1])))
  }
  constraints.push(...gated(F.mul(notLast, scheduleActive), addWordsConstraint(
    [smallSigma1, schedule[9], smallSigma0, schedule[0]],
    nextSchedule[15],
    current,
    layout.scheduleCarry,
    4
  )))
  constraints.push(...gated(F.mul(notLast, F.sub(1n, scheduleActive)), [
    nextSchedule[15][0],
    nextSchedule[15][1]
  ]))

  constraints.push(...compactHmacLinkConstraints(current, next, layout))
  return constraints
}

export function method2CompactHmacSha256Metrics (
  trace: Method2CompactHmacSha256Trace,
  proof?: StarkProof
): Method2CompactHmacSha256Metrics {
  return {
    invoiceLength: trace.publicInput.invoice.length,
    innerBlocks: trace.publicInput.innerBlocks,
    outerBlocks: trace.publicInput.outerBlocks,
    totalBlocks: trace.publicInput.totalBlocks,
    activeRows: trace.publicInput.activeRows,
    paddedRows: trace.publicInput.traceLength,
    traceWidth: trace.layout.width,
    committedCells: trace.publicInput.traceLength * trace.layout.width,
    proofBytes: proof === undefined ? undefined : serializeStarkProof(proof).length
  }
}

export function method2CompactHmacSha256KeyForLink (
  trace: Method2CompactHmacSha256Trace
): number[] {
  validateMethod2CompactHmacSha256Trace(trace)
  return trace.key.slice()
}

export function method2CompactHmacSha256PublicInputDigest (
  publicInput: Method2CompactHmacSha256PublicInput
): number[] {
  validateMethod2CompactHmacSha256PublicInput(publicInput)
  const writer = new Writer()
  writer.write(toArray(METHOD2_COMPACT_HMAC_SHA256_PUBLIC_INPUT_ID, 'utf8'))
  writer.writeVarIntNum(publicInput.invoice.length)
  writer.write(publicInput.invoice)
  writer.writeVarIntNum(publicInput.linkage.length)
  writer.write(publicInput.linkage)
  writer.writeVarIntNum(publicInput.innerBlocks)
  writer.writeVarIntNum(publicInput.outerBlocks)
  writer.writeVarIntNum(publicInput.totalBlocks)
  writer.writeVarIntNum(publicInput.activeRows)
  writer.writeVarIntNum(publicInput.traceLength)
  writer.writeVarIntNum(METHOD2_COMPACT_HMAC_SHA256_LAYOUT.width)
  return sha256(writer.toArray())
}

export function validateMethod2CompactHmacSha256Trace (
  trace: Method2CompactHmacSha256Trace
): void {
  validateMethod2CompactHmacSha256PublicInput(trace.publicInput)
  assertBytes(trace.key, METHOD2_HMAC_KEY_SIZE, 'HMAC key')
  if (!bytesEqual(hmacSha256(trace.key, trace.publicInput.invoice), trace.publicInput.linkage)) {
    throw new Error('Compact HMAC-SHA256 trace linkage mismatch')
  }
  if (!bytesEqual(trace.innerDigest, sha256Digest(innerHmacInput(
    trace.key,
    trace.publicInput.invoice
  )))) {
    throw new Error('Compact HMAC-SHA256 inner digest mismatch')
  }
  if (!bytesEqual(trace.innerMessage, sha256Pad(innerHmacInput(
    trace.key,
    trace.publicInput.invoice
  )))) {
    throw new Error('Compact HMAC-SHA256 inner message mismatch')
  }
  if (!bytesEqual(trace.outerMessage, sha256Pad(outerHmacInput(
    trace.key,
    trace.innerDigest
  )))) {
    throw new Error('Compact HMAC-SHA256 outer message mismatch')
  }
  if (trace.layout.width !== METHOD2_COMPACT_HMAC_SHA256_LAYOUT.width) {
    throw new Error('Compact HMAC-SHA256 layout mismatch')
  }
  if (trace.rows.length !== trace.publicInput.traceLength) {
    throw new Error('Compact HMAC-SHA256 trace length mismatch')
  }
  for (const row of trace.rows) {
    if (row.length !== trace.layout.width) {
      throw new Error('Compact HMAC-SHA256 trace row width mismatch')
    }
  }
}

export function validateMethod2CompactHmacSha256PublicInput (
  publicInput: Method2CompactHmacSha256PublicInput
): void {
  assertBytes(publicInput.invoice, undefined, 'invoice')
  assertBytes(publicInput.linkage, METHOD2_SHA256_DIGEST_SIZE, 'linkage')
  const expected = method2CompactHmacSha256PublicInput(
    publicInput.invoice,
    publicInput.linkage
  )
  if (
    publicInput.innerBlocks !== expected.innerBlocks ||
    publicInput.outerBlocks !== expected.outerBlocks ||
    publicInput.totalBlocks !== expected.totalBlocks ||
    publicInput.activeRows !== expected.activeRows
  ) {
    throw new Error('Compact HMAC-SHA256 public input shape mismatch')
  }
  if (
    !isPowerOfTwo(publicInput.traceLength) ||
    publicInput.traceLength < expected.traceLength
  ) {
    throw new Error('Compact HMAC-SHA256 public input trace length mismatch')
  }
}

function writeCompactBlockRows (
  rows: FieldElement[][],
  startRow: number,
  initialState: number[],
  block: number[],
  layout: Method2CompactHmacSha256Layout
): number[] {
  const schedule = sha256Schedule(block)
  let working = initialState.slice()
  for (let round = 0; round < SHA_ROUNDS; round++) {
    const row = rows[startRow + round]
    writeWords(row, layout.chain, initialState)
    writeWords(row, layout.state, working)
    writeWords(row, layout.schedule, scheduleWindow(schedule, round))
    writeWord(row, layout.k, METHOD2_SHA256_K[round])
    writeRoundHelpers(row, working, schedule, round, layout)
    working = nextWorkingState(working, schedule[round], METHOD2_SHA256_K[round])
  }
  const outputState = addStateWords(initialState, working)
  writeWords(rows[startRow + SHA_RESULT_ROW], layout.state, outputState)
  writeWords(rows[startRow + SHA_RESULT_ROW], layout.chain, outputState)
  return outputState
}

function writeRoundHelpers (
  row: FieldElement[],
  working: number[],
  schedule: number[],
  round: number,
  layout: Method2CompactHmacSha256Layout
): void {
  const sigma1 = bigSigma1(working[4])
  const chValue = ch(working[4], working[5], working[6])
  const sigma0 = bigSigma0(working[0])
  const majValue = maj(working[0], working[1], working[2])
  const small0 = smallSigma0(schedule[round + 1] ?? 0)
  const small1 = smallSigma1(schedule[round + 14] ?? 0)
  const t1 = add32(working[7], sigma1, chValue, METHOD2_SHA256_K[round], schedule[round])
  const t2 = add32(sigma0, majValue)
  const roundA = add32(t1, t2)
  const roundE = add32(working[3], t1)
  writeWord(row, layout.sigma0, sigma0)
  writeWord(row, layout.sigma1, sigma1)
  writeWord(row, layout.ch, chValue)
  writeWord(row, layout.maj, majValue)
  writeWord(row, layout.smallSigma0, small0)
  writeWord(row, layout.smallSigma1, small1)
  writeWord(row, layout.t1, t1)
  writeWord(row, layout.t2, t2)
  writeWord(row, layout.roundA, roundA)
  writeWord(row, layout.roundE, roundE)
  writeCarryChunks(row, layout.t1Carry, [
    working[7],
    sigma1,
    chValue,
    METHOD2_SHA256_K[round],
    schedule[round]
  ], t1)
  writeCarryChunks(row, layout.t2Carry, [sigma0, majValue], t2)
  writeCarryChunks(row, layout.roundACarry, [t1, t2], roundA)
  writeCarryChunks(row, layout.roundECarry, [working[3], t1], roundE)
  writeCarryChunks(row, layout.scheduleCarry, [
    small1,
    schedule[round + 9] ?? 0,
    small0,
    schedule[round]
  ], add32(small1, schedule[round + 9] ?? 0, small0, schedule[round]))
  const roundOutput = [
    roundA,
    working[0],
    working[1],
    working[2],
    roundE,
    working[4],
    working[5],
    working[6]
  ]
  for (let word = 0; word < STATE_WORDS; word++) {
    writeCarryChunks(
      row,
      layout.finalCarry + word * WORD_CHUNKS,
      [rowWordValue(readWord(row, layout.chain + word * WORD_CHUNKS)), roundOutput[word]],
      add32(rowWordValue(readWord(row, layout.chain + word * WORD_CHUNKS)), roundOutput[word])
    )
  }
  writeBits(row, layout.aBits, numberToBitsLE(working[0], WORD_BITS))
  writeBits(row, layout.bBits, numberToBitsLE(working[1], WORD_BITS))
  writeBits(row, layout.cBits, numberToBitsLE(working[2], WORD_BITS))
  writeBits(row, layout.eBits, numberToBitsLE(working[4], WORD_BITS))
  writeBits(row, layout.fBits, numberToBitsLE(working[5], WORD_BITS))
  writeBits(row, layout.gBits, numberToBitsLE(working[6], WORD_BITS))
  writeBits(row, layout.schedule1Bits, numberToBitsLE(schedule[round + 1] ?? 0, WORD_BITS))
  writeBits(row, layout.schedule14Bits, numberToBitsLE(schedule[round + 14] ?? 0, WORD_BITS))
}

function compactHmacLinkConstraints (
  current: FieldElement[],
  next: FieldElement[],
  layout: Method2CompactHmacSha256Layout
): FieldElement[] {
  const constraints: FieldElement[] = []
  for (let byteIndex = 0; byteIndex < METHOD2_HMAC_KEY_SIZE; byteIndex++) {
    constraints.push(F.mul(
      current[layout.keyCarry],
      F.sub(
        next[layout.keyBytes + byteIndex],
        current[layout.keyBytes + byteIndex]
      )
    ))
    constraints.push(F.mul(
      current[layout.keyCarry],
      F.sub(
        next[layout.innerKeyBytes + byteIndex],
        current[layout.innerKeyBytes + byteIndex]
      )
    ))
    constraints.push(F.mul(
      current[layout.keyCarry],
      F.sub(
        next[layout.outerKeyBytes + byteIndex],
        current[layout.outerKeyBytes + byteIndex]
      )
    ))
  }
  constraints.push(...keyByteCheckConstraints(current, layout))
  for (let chunk = 0; chunk < STATE_WORDS * WORD_CHUNKS; chunk++) {
    constraints.push(F.mul(
      current[layout.digestCarry],
      F.sub(
        next[layout.innerDigestChunks + chunk],
        current[layout.innerDigestChunks + chunk]
      )
    ))
  }
  constraints.push(...keyBlockScheduleConstraints(
    current,
    layout,
    current[layout.innerKeyBlock],
    layout.innerKeyBytes,
    METHOD2_HMAC_INNER_PAD
  ))
  constraints.push(...keyBlockScheduleConstraints(
    current,
    layout,
    current[layout.outerKeyBlock],
    layout.outerKeyBytes,
    METHOD2_HMAC_OUTER_PAD
  ))
  for (let word = 0; word < STATE_WORDS; word++) {
    const digestWord = readWord(
      current,
      layout.innerDigestChunks + word * WORD_CHUNKS
    )
    constraints.push(F.mul(
      current[layout.captureInnerDigest],
      F.sub(digestWord[0], current[layout.state + word * WORD_CHUNKS])
    ))
    constraints.push(F.mul(
      current[layout.captureInnerDigest],
      F.sub(digestWord[1], current[layout.state + word * WORD_CHUNKS + 1])
    ))
    constraints.push(F.mul(
      current[layout.useInnerDigest],
      F.sub(readWord(current, layout.schedule + word * WORD_CHUNKS)[0], digestWord[0])
    ))
    constraints.push(F.mul(
      current[layout.useInnerDigest],
      F.sub(readWord(current, layout.schedule + word * WORD_CHUNKS)[1], digestWord[1])
    ))
    constraints.push(F.mul(
      current[layout.linkNext],
      F.sub(next[layout.state + word * WORD_CHUNKS], current[layout.state + word * WORD_CHUNKS])
    ))
    constraints.push(F.mul(
      current[layout.linkNext],
      F.sub(next[layout.state + word * WORD_CHUNKS + 1], current[layout.state + word * WORD_CHUNKS + 1])
    ))
    constraints.push(F.mul(
      current[layout.linkNext],
      F.sub(next[layout.chain + word * WORD_CHUNKS], current[layout.state + word * WORD_CHUNKS])
    ))
    constraints.push(F.mul(
      current[layout.linkNext],
      F.sub(next[layout.chain + word * WORD_CHUNKS + 1], current[layout.state + word * WORD_CHUNKS + 1])
    ))
  }
  return constraints
}

function keyBlockScheduleConstraints (
  row: FieldElement[],
  layout: Method2CompactHmacSha256Layout,
  selector: FieldElement,
  byteOffset: number,
  pad: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  for (let word = 0; word < SCHEDULE_WINDOW; word++) {
    const bytes: FieldElement[] = []
    for (let byte = 0; byte < 4; byte++) {
      const byteIndex = word * 4 + byte
      if (byteIndex < METHOD2_HMAC_KEY_SIZE) {
        bytes.push(row[byteOffset + byteIndex])
      } else {
        bytes.push(BigInt(pad))
      }
    }
    const lo = F.add(bytes[3], F.mul(256n, bytes[2]))
    const hi = F.add(bytes[1], F.mul(256n, bytes[0]))
    constraints.push(F.mul(
      selector,
      F.sub(row[layout.schedule + word * WORD_CHUNKS], lo)
    ))
    constraints.push(F.mul(
      selector,
      F.sub(row[layout.schedule + word * WORD_CHUNKS + 1], hi)
    ))
  }
  return constraints
}

function keyByteCheckConstraints (
  row: FieldElement[],
  layout: Method2CompactHmacSha256Layout
): FieldElement[] {
  const constraints: FieldElement[] = []
  const keyBits = row.slice(layout.keyCheckBits, layout.keyCheckBits + 8)
  const innerBits = row.slice(layout.keyCheckBits + 8, layout.keyCheckBits + 16)
  const outerBits = row.slice(layout.keyCheckBits + 16, layout.keyCheckBits + 24)
  for (let byteIndex = 0; byteIndex < METHOD2_HMAC_KEY_SIZE; byteIndex++) {
    const selector = row[layout.keyCheckSelectors + byteIndex]
    constraints.push(...gated(selector, bitBooleanConstraintsForBits(keyBits)))
    constraints.push(...gated(selector, bitBooleanConstraintsForBits(innerBits)))
    constraints.push(...gated(selector, bitBooleanConstraintsForBits(outerBits)))
    constraints.push(F.mul(
      selector,
      F.sub(row[layout.keyBytes + byteIndex], bitsToByte(keyBits))
    ))
    constraints.push(F.mul(
      selector,
      F.sub(row[layout.innerKeyBytes + byteIndex], bitsToByte(innerBits))
    ))
    constraints.push(F.mul(
      selector,
      F.sub(row[layout.outerKeyBytes + byteIndex], bitsToByte(outerBits))
    ))
    for (let bit = 0; bit < 8; bit++) {
      constraints.push(F.mul(
        selector,
        F.sub(
          innerBits[bit],
          xorBitWithConstant(keyBits[bit], METHOD2_HMAC_INNER_PAD, bit)
        )
      ))
      constraints.push(F.mul(
        selector,
        F.sub(
          outerBits[bit],
          xorBitWithConstant(keyBits[bit], METHOD2_HMAC_OUTER_PAD, bit)
        )
      ))
    }
  }
  return constraints
}

function bitBooleanConstraintsForBits (
  bits: FieldElement[]
): FieldElement[] {
  return bits.map(booleanConstraint)
}

function bitsToByte (bits: FieldElement[]): FieldElement {
  let value = 0n
  for (let bit = 0; bit < 8; bit++) {
    value = F.add(value, F.mul(bits[bit], 1n << BigInt(bit)))
  }
  return value
}

function xorBitWithConstant (
  bit: FieldElement,
  constant: number,
  bitIndex: number
): FieldElement {
  return ((constant >>> bitIndex) & 1) === 0 ? bit : F.sub(1n, bit)
}

function compactBoundaryConstraints (
  publicInput: Method2CompactHmacSha256PublicInput
): AirDefinition['boundaryConstraints'] {
  const constraints: AirDefinition['boundaryConstraints'] = []
  constraints.push(...wordBoundaryConstraints(0, METHOD2_COMPACT_HMAC_SHA256_LAYOUT.chain, METHOD2_SHA256_INITIAL_STATE))
  constraints.push(...wordBoundaryConstraints(0, METHOD2_COMPACT_HMAC_SHA256_LAYOUT.state, METHOD2_SHA256_INITIAL_STATE))
  const outerStart = publicInput.innerBlocks * BLOCK_STRIDE
  constraints.push(...wordBoundaryConstraints(outerStart, METHOD2_COMPACT_HMAC_SHA256_LAYOUT.chain, METHOD2_SHA256_INITIAL_STATE))
  constraints.push(...wordBoundaryConstraints(outerStart, METHOD2_COMPACT_HMAC_SHA256_LAYOUT.state, METHOD2_SHA256_INITIAL_STATE))
  constraints.push(...wordBoundaryConstraints(
    finalOuterResultRow(publicInput),
    METHOD2_COMPACT_HMAC_SHA256_LAYOUT.state,
    bytesToWordsBE(publicInput.linkage)
  ))
  for (const binding of publicScheduleWordBindings(publicInput)) {
    constraints.push({
      row: binding.row,
      column: METHOD2_COMPACT_HMAC_SHA256_LAYOUT.schedule + binding.word * WORD_CHUNKS,
      value: BigInt(binding.wordValue & 0xffff)
    })
    constraints.push({
      row: binding.row,
      column: METHOD2_COMPACT_HMAC_SHA256_LAYOUT.schedule + binding.word * WORD_CHUNKS + 1,
      value: BigInt(binding.wordValue >>> 16)
    })
  }
  return constraints
}

function compactFullBoundaryColumns (
  publicInput: Method2CompactHmacSha256PublicInput
): AirDefinition['fullBoundaryColumns'] {
  const layout = METHOD2_COMPACT_HMAC_SHA256_LAYOUT
  const selectors = compactSelectorValues(publicInput)
  const fixed = [
    { column: layout.active, values: selectors.active },
    { column: layout.scheduleActive, values: selectors.scheduleActive },
    { column: layout.last, values: selectors.last },
    { column: layout.linkNext, values: selectors.linkNext },
    { column: layout.keyInit, values: selectors.keyInit },
    { column: layout.keyCarry, values: selectors.keyCarry },
    { column: layout.innerKeyBlock, values: selectors.innerKeyBlock },
    { column: layout.outerKeyBlock, values: selectors.outerKeyBlock },
    { column: layout.captureInnerDigest, values: selectors.captureInnerDigest },
    { column: layout.digestCarry, values: selectors.digestCarry },
    { column: layout.useInnerDigest, values: selectors.useInnerDigest }
  ]
  const keyCheckColumns = Array.from(
    { length: METHOD2_HMAC_KEY_SIZE },
    (_, byteIndex) => ({
      column: layout.keyCheckSelectors + byteIndex,
      values: selectors.keyCheckSelectors[byteIndex]
    })
  )
  const kColumns = Array.from({ length: WORD_CHUNKS }, (_, chunk) => ({
    column: layout.k + chunk,
    values: new Array<FieldElement>(publicInput.traceLength).fill(0n)
  }))
  for (const block of compactBlockPlans(publicInput)) {
    for (let round = 0; round < SHA_ROUNDS; round++) {
      const chunks = wordToChunks(METHOD2_SHA256_K[round])
      for (let chunk = 0; chunk < WORD_CHUNKS; chunk++) {
        kColumns[chunk].values[block.startRow + round] = chunks[chunk]
      }
    }
  }
  return [...fixed, ...keyCheckColumns, ...kColumns]
}

function compactSelectorValues (
  publicInput: Method2CompactHmacSha256PublicInput
): CompactSelectors {
  const values = {
    active: zeroColumn(publicInput),
    scheduleActive: zeroColumn(publicInput),
    last: zeroColumn(publicInput),
    linkNext: zeroColumn(publicInput),
    keyInit: zeroColumn(publicInput),
    keyCarry: zeroColumn(publicInput),
    innerKeyBlock: zeroColumn(publicInput),
    outerKeyBlock: zeroColumn(publicInput),
    captureInnerDigest: zeroColumn(publicInput),
    digestCarry: zeroColumn(publicInput),
    useInnerDigest: zeroColumn(publicInput),
    keyCheckSelectors: Array.from(
      { length: METHOD2_HMAC_KEY_SIZE },
      () => zeroColumn(publicInput)
    )
  }
  values.keyInit[0] = 1n
  values.innerKeyBlock[0] = 1n
  values.outerKeyBlock[publicInput.innerBlocks * BLOCK_STRIDE] = 1n
  values.captureInnerDigest[innerFinalResultRow(publicInput)] = 1n
  values.useInnerDigest[outerDigestBlockStartRow(publicInput)] = 1n
  for (let byteIndex = 0; byteIndex < METHOD2_HMAC_KEY_SIZE; byteIndex++) {
    values.keyCheckSelectors[byteIndex][byteIndex] = 1n
  }
  for (let row = 0; row < publicInput.activeRows - 1; row++) values.keyCarry[row] = 1n
  for (
    let row = innerFinalResultRow(publicInput);
    row < outerDigestBlockStartRow(publicInput);
    row++
  ) {
    values.digestCarry[row] = 1n
  }
  for (const block of compactBlockPlans(publicInput)) {
    if (block.linkToNext) values.linkNext[block.resultRow] = 1n
    for (let round = 0; round < SHA_ROUNDS; round++) {
      values.active[block.startRow + round] = 1n
      values.last[block.startRow + round] = round === SHA_ROUNDS - 1 ? 1n : 0n
      values.scheduleActive[block.startRow + round] = round < SHA_ROUNDS - 16 ? 1n : 0n
    }
  }
  return values
}

function publicScheduleWordBindings (
  publicInput: Method2CompactHmacSha256PublicInput
): Array<{ row: number, word: number, wordValue: number }> {
  const bindings: Array<{ row: number, word: number, wordValue: number }> = []
  const publicInnerMessage = sha256Pad([
    ...new Array<number>(METHOD2_HMAC_BLOCK_SIZE).fill(0),
    ...publicInput.invoice
  ])
  const publicOuterMessage = sha256Pad([
    ...new Array<number>(METHOD2_HMAC_BLOCK_SIZE).fill(0),
    ...new Array<number>(METHOD2_SHA256_DIGEST_SIZE).fill(0)
  ])
  for (const block of compactBlockPlans(publicInput)) {
    if (block.kind === 'inner-key' || block.kind === 'outer-key') {
      continue
    }
    const message = block.chain === 'inner' ? publicInnerMessage : publicOuterMessage
    const firstWord = block.kind === 'outer-digest' ? 8 : 0
    for (let word = firstWord; word < SCHEDULE_WINDOW; word++) {
      bindings.push({
        row: block.startRow,
        word,
        wordValue: readU32BE(message, block.blockIndex * METHOD2_HMAC_BLOCK_SIZE + word * 4)
      })
    }
  }
  return bindings
}

function compactBlockPlans (
  publicInput: Method2CompactHmacSha256PublicInput
): CompactBlockPlan[] {
  const plans: CompactBlockPlan[] = []
  for (let block = 0; block < publicInput.innerBlocks; block++) {
    const startRow = block * BLOCK_STRIDE
    plans.push({
      chain: 'inner',
      kind: block === 0 ? 'inner-key' : 'inner-public',
      blockIndex: block,
      startRow,
      resultRow: startRow + SHA_RESULT_ROW,
      linkToNext: block < publicInput.innerBlocks - 1
    })
  }
  const outerStart = publicInput.innerBlocks * BLOCK_STRIDE
  for (let block = 0; block < publicInput.outerBlocks; block++) {
    const startRow = outerStart + block * BLOCK_STRIDE
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

function addWordsConstraint (
  operands: FieldElement[][],
  output: FieldElement[],
  row: FieldElement[],
  carryOffset: number,
  maxOperands: number
): FieldElement[] {
  const lowCarry = row[carryOffset]
  const highCarry = row[carryOffset + 1]
  let lowSum = 0n
  let highSum = lowCarry
  for (const operand of operands) {
    lowSum = F.add(lowSum, operand[0])
    highSum = F.add(highSum, operand[1])
  }
  return [
    F.sub(lowSum, F.add(output[0], F.mul(CHUNK_BASE, lowCarry))),
    F.sub(highSum, F.add(output[1], F.mul(CHUNK_BASE, highCarry))),
    smallRangeConstraint(lowCarry, maxOperands),
    smallRangeConstraint(highCarry, maxOperands)
  ]
}

function wordEqualsBits (
  word: FieldElement[],
  bits: FieldElement[]
): FieldElement[] {
  const chunks = bitsToChunks(bits)
  return [
    F.sub(word[0], chunks[0]),
    F.sub(word[1], chunks[1])
  ]
}

function bitsToChunks (bits: FieldElement[]): FieldElement[] {
  let lo = 0n
  let hi = 0n
  for (let bit = 0; bit < CHUNK_BITS; bit++) {
    lo = F.add(lo, F.mul(bits[bit], BigInt(1 << bit)))
    hi = F.add(hi, F.mul(bits[bit + CHUNK_BITS], BigInt(1 << bit)))
  }
  return [lo, hi]
}

function readWords (
  row: FieldElement[],
  offset: number,
  words: number
): FieldElement[][] {
  return Array.from({ length: words }, (_, word) =>
    readWord(row, offset + word * WORD_CHUNKS)
  )
}

function readWord (
  row: FieldElement[],
  offset: number
): FieldElement[] {
  return row.slice(offset, offset + WORD_CHUNKS)
}

function writeWords (
  row: FieldElement[],
  offset: number,
  words: number[]
): void {
  for (let word = 0; word < words.length; word++) {
    writeWord(row, offset + word * WORD_CHUNKS, words[word])
  }
}

function writeWord (
  row: FieldElement[],
  offset: number,
  word: number
): void {
  const chunks = wordToChunks(word)
  row[offset] = chunks[0]
  row[offset + 1] = chunks[1]
}

function wordToChunks (word: number): FieldElement[] {
  return [
    BigInt(word & 0xffff),
    BigInt((word >>> 16) & 0xffff)
  ]
}

function rowWordValue (word: FieldElement[]): number {
  return ((Number(word[1]) << 16) | Number(word[0])) >>> 0
}

function writeCarryChunks (
  row: FieldElement[],
  offset: number,
  operands: number[],
  output: number
): void {
  const lowSum = operands.reduce((sum, word) => sum + (word & 0xffff), 0)
  const lowCarry = Math.floor((lowSum - (output & 0xffff)) / 0x10000)
  const highSum = operands.reduce((sum, word) => sum + ((word >>> 16) & 0xffff), lowCarry)
  const highCarry = Math.floor((highSum - ((output >>> 16) & 0xffff)) / 0x10000)
  row[offset] = BigInt(lowCarry)
  row[offset + 1] = BigInt(highCarry)
}

function scheduleWindow (schedule: number[], round: number): number[] {
  return Array.from({ length: SCHEDULE_WINDOW }, (_, index) =>
    schedule[round + index] ?? 0
  )
}

function wordBits (
  row: FieldElement[],
  offset: number
): FieldElement[] {
  return row.slice(offset, offset + WORD_BITS)
}

function wordEquality (
  left: FieldElement[],
  right: FieldElement[]
): FieldElement[] {
  return [
    F.sub(left[0], right[0]),
    F.sub(left[1], right[1])
  ]
}

function gated (
  selector: FieldElement,
  constraints: FieldElement[]
): FieldElement[] {
  return constraints.map(constraint => F.mul(selector, constraint))
}

function wordBoundaryConstraints (
  row: number,
  offset: number,
  words: number[]
): AirDefinition['boundaryConstraints'] {
  const constraints: AirDefinition['boundaryConstraints'] = []
  for (let word = 0; word < words.length; word++) {
    const chunks = wordToChunks(words[word])
    constraints.push({
      row,
      column: offset + word * WORD_CHUNKS,
      value: chunks[0]
    })
    constraints.push({
      row,
      column: offset + word * WORD_CHUNKS + 1,
      value: chunks[1]
    })
  }
  return constraints
}

function innerHmacInput (key: number[], invoice: number[]): number[] {
  return [
    ...hmacKeyBlock(key).map(byte => byte ^ METHOD2_HMAC_INNER_PAD),
    ...invoice
  ]
}

function outerHmacInput (key: number[], innerDigest: number[]): number[] {
  return [
    ...hmacKeyBlock(key).map(byte => byte ^ METHOD2_HMAC_OUTER_PAD),
    ...innerDigest
  ]
}

function hmacKeyBlock (key: number[]): number[] {
  const out = key.slice()
  while (out.length < METHOD2_HMAC_BLOCK_SIZE) out.push(0)
  return out
}

function chBits (
  x: FieldElement[],
  y: FieldElement[],
  z: FieldElement[]
): FieldElement[] {
  return x.map((bit, index) => F.add(
    F.mul(bit, y[index]),
    F.mul(F.sub(1n, bit), z[index])
  ))
}

function majBits (
  x: FieldElement[],
  y: FieldElement[],
  z: FieldElement[]
): FieldElement[] {
  return x.map((bit, index) => F.sub(
    F.add(F.add(
      F.mul(bit, y[index]),
      F.mul(bit, z[index])
    ), F.mul(y[index], z[index])),
    F.mul(2n, F.mul(F.mul(bit, y[index]), z[index]))
  ))
}

function bigSigma0Bits (bits: FieldElement[]): FieldElement[] {
  return xor3Bits(rotrBits(bits, 2), rotrBits(bits, 13), rotrBits(bits, 22))
}

function bigSigma1Bits (bits: FieldElement[]): FieldElement[] {
  return xor3Bits(rotrBits(bits, 6), rotrBits(bits, 11), rotrBits(bits, 25))
}

function smallSigma0Bits (bits: FieldElement[]): FieldElement[] {
  return xor3Bits(rotrBits(bits, 7), rotrBits(bits, 18), shrBits(bits, 3))
}

function smallSigma1Bits (bits: FieldElement[]): FieldElement[] {
  return xor3Bits(rotrBits(bits, 17), rotrBits(bits, 19), shrBits(bits, 10))
}

function xor3Bits (
  left: FieldElement[],
  middle: FieldElement[],
  right: FieldElement[]
): FieldElement[] {
  return left.map((bit, index) => xor3(bit, middle[index], right[index]))
}

function rotrBits (bits: FieldElement[], amount: number): FieldElement[] {
  return bits.map((_, bit) => bits[(bit + amount) % WORD_BITS])
}

function shrBits (bits: FieldElement[], amount: number): FieldElement[] {
  return bits.map((_, bit) => bit + amount < WORD_BITS ? bits[bit + amount] : 0n)
}

function xor3 (
  x: FieldElement,
  y: FieldElement,
  z: FieldElement
): FieldElement {
  return F.add(
    F.sub(
      F.sub(
        F.sub(F.add(F.add(x, y), z), F.mul(2n, F.mul(x, y))),
        F.mul(2n, F.mul(x, z))
      ),
      F.mul(2n, F.mul(y, z))
    ),
    F.mul(4n, F.mul(F.mul(x, y), z))
  )
}

function nextWorkingState (
  working: number[],
  w: number,
  k: number
): number[] {
  const t1 = add32(
    working[7],
    bigSigma1(working[4]),
    ch(working[4], working[5], working[6]),
    k,
    w
  )
  const t2 = add32(bigSigma0(working[0]), maj(working[0], working[1], working[2]))
  return [
    add32(t1, t2),
    working[0],
    working[1],
    working[2],
    add32(working[3], t1),
    working[4],
    working[5],
    working[6]
  ]
}

function addStateWords (left: number[], right: number[]): number[] {
  return left.map((word, index) => add32(word, right[index]))
}

function ch (x: number, y: number, z: number): number {
  return ((x & y) ^ (~x & z)) >>> 0
}

function maj (x: number, y: number, z: number): number {
  return ((x & z) ^ (x & y) ^ (y & z)) >>> 0
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
  return ((x >>> n) | (x << (WORD_BITS - n))) >>> 0
}

function add32 (...values: number[]): number {
  return values.reduce((sum, value) => (sum + (value >>> 0)) >>> 0, 0)
}

function readU32BE (bytes: number[], offset: number): number {
  return (
    ((bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3]) >>> 0
  )
}

function bytesToWordsBE (bytes: number[]): number[] {
  if (bytes.length % 4 !== 0) throw new Error('Byte length must be word-aligned')
  const out: number[] = []
  for (let i = 0; i < bytes.length; i += 4) out.push(readU32BE(bytes, i))
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
  for (let bit = 0; bit < bits.length; bit++) row[offset + bit] = BigInt(bits[bit])
}

function writeByteColumns (
  row: FieldElement[],
  offset: number,
  bytes: number[]
): void {
  for (let byteIndex = 0; byteIndex < bytes.length; byteIndex++) {
    row[offset + byteIndex] = BigInt(bytes[byteIndex])
  }
}

function innerFinalResultRow (
  publicInput: Method2CompactHmacSha256PublicInput
): number {
  return publicInput.innerBlocks * BLOCK_STRIDE - 1
}

function outerDigestBlockStartRow (
  publicInput: Method2CompactHmacSha256PublicInput
): number {
  return (publicInput.innerBlocks + 1) * BLOCK_STRIDE
}

function finalOuterResultRow (
  publicInput: Method2CompactHmacSha256PublicInput
): number {
  return publicInput.activeRows - 1
}

function zeroColumn (
  publicInput: Method2CompactHmacSha256PublicInput
): FieldElement[] {
  return new Array<FieldElement>(publicInput.traceLength).fill(0n)
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}

function isPowerOfTwo (value: number): boolean {
  return Number.isSafeInteger(value) && value > 0 && (value & (value - 1)) === 0
}

function smallRangeConstraint (
  value: FieldElement,
  max: number
): FieldElement {
  let out = 1n
  for (let i = 0; i <= max; i++) out = F.mul(out, F.sub(value, BigInt(i)))
  return out
}

function booleanConstraint (value: FieldElement): FieldElement {
  return F.mul(value, F.sub(value, 1n))
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
