import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import { AirDefinition } from '../stark/Air.js'
import { F, FieldElement } from '../stark/Field.js'
import {
  LOG_LOOKUP_ROW_KIND,
  LOG_LOOKUP_TUPLE_ARITY,
  compressLogLookupTuple
} from '../stark/LogLookupBus.js'
import {
  StarkProof,
  StarkProverOptions,
  serializeStarkProof
} from '../stark/Stark.js'
import { FiatShamirTranscript } from '../stark/Transcript.js'
import { hmacSha256 } from '../circuit/Sha256.js'
import {
  METHOD2_COMPACT_HMAC_SHA256_LAYOUT,
  Method2CompactHmacSha256PublicInput,
  buildMethod2CompactHmacSha256Air,
  buildMethod2CompactHmacSha256Trace,
  method2CompactHmacSha256KeyForLink,
  method2CompactHmacSha256PublicInput,
  validateMethod2CompactHmacSha256PublicInput
} from './Method2CompactHmacSha256.js'
import {
  METHOD2_HMAC_INNER_PAD,
  METHOD2_HMAC_KEY_SIZE,
  METHOD2_HMAC_OUTER_PAD,
  METHOD2_SHA256_DIGEST_SIZE
} from './Method2Hmac.js'
import {
  METHOD2_LOOKUP_SHA_TAG_AND4,
  METHOD2_LOOKUP_SHA_TAG_XOR4,
  buildMethod2LookupShaHmacTable,
  method2LookupShaHmacTableDigest
} from './Method2LookupShaHmac.js'

export const METHOD2_LOOKUP_BATCHED_HMAC_SHA256_TRANSCRIPT_DOMAIN =
  'BRC69_METHOD2_LOOKUP_BATCHED_HMAC_SHA256_AIR_V1'
export const METHOD2_LOOKUP_BATCHED_HMAC_SHA256_PUBLIC_INPUT_ID =
  'BRC69_METHOD2_LOOKUP_BATCHED_HMAC_SHA256_PUBLIC_INPUT_V1'

export const METHOD2_LOOKUP_BATCHED_HMAC_SHA256_STARK_OPTIONS = {
  blowupFactor: 16,
  numQueries: 48,
  maxRemainderSize: 16,
  maskDegree: 192,
  cosetOffset: 7n,
  transcriptDomain: METHOD2_LOOKUP_BATCHED_HMAC_SHA256_TRANSCRIPT_DOMAIN
} as const

const SHA_ROUNDS = 64
const BLOCK_STRIDE = SHA_ROUNDS + 1
const NIBBLES_PER_WORD = 8
const TABLE_ROWS = 512
const REQUESTS_PER_ROUND = 128
const REQUESTS_PER_CHUNK = 8
const LOOKUP_CHUNKS_PER_COMPACT_ROW = REQUESTS_PER_ROUND / REQUESTS_PER_CHUNK
const WORD_BITS = 32
const CHUNK_BITS = 16
const CHUNK_BASE = 1n << BigInt(CHUNK_BITS)
const WORD_CHUNKS = 2
const STATE_WORDS = 8
const SCHEDULE_WINDOW = 16
const BIT_LANE_WORDS = 4
const BIT_LANE_WIDTH = BIT_LANE_WORDS * WORD_BITS

const LINK_XOR_SIGMA0_FIRST = 1
const LINK_XOR_SIGMA0_SECOND = 2
const LINK_XOR_SIGMA1_FIRST = 3
const LINK_XOR_SIGMA1_SECOND = 4
const LINK_CH_AND_EF = 5
const LINK_CH_AND_NOT_E_G = 6
const LINK_CH_XOR = 7
const LINK_MAJ_AND_AB = 8
const LINK_MAJ_AND_AC = 9
const LINK_MAJ_AND_BC = 10
const LINK_MAJ_XOR_AB_AC = 11
const LINK_MAJ_XOR_TEMP_BC = 12
const LINK_XOR_SMALL0_FIRST = 13
const LINK_XOR_SMALL0_SECOND = 14
const LINK_XOR_SMALL1_FIRST = 15
const LINK_XOR_SMALL1_SECOND = 16

export interface Method2LookupBatchedHmacSha256Layout {
  compact: number
  bitLane: number
  kind: number
  tag: number
  multiplicity: number
  publicTuple: number
  requestInverse0: number
  requestInverse1: number
  supplyInverse0: number
  supplyInverse1: number
  accumulator0: number
  accumulator1: number
  requestCount: number
  supplyCount: number
  compactTransitionActive: number
  compactRepeatActive: number
  groupSelector: number
  keyBytes: number
  width: number
}

interface Method2NarrowHmacCoreLayout {
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
  keyBytes: number
  innerKeyBytes: number
  outerKeyBytes: number
  keyCheckBits: number
  keyCheckSelectors: number
  innerDigestChunks: number
  width: number
}

export interface Method2LookupBatchedHmacSha256PublicInput {
  relation: 'lookup-batched-hmac-sha256'
  invoice: number[]
  linkage: number[]
  innerBlocks: number
  outerBlocks: number
  totalBlocks: number
  compactActiveRows: number
  compactTraceLength: number
  activeRows: number
  traceLength: number
  expectedLookupRequests: number
  lookupTableRows: number
  tableDigest: number[]
}

export interface Method2LookupBatchedHmacSha256Trace {
  publicInput: Method2LookupBatchedHmacSha256PublicInput
  rows: FieldElement[][]
  layout: Method2LookupBatchedHmacSha256Layout
  compact: ReturnType<typeof buildMethod2CompactHmacSha256Trace>
}

export interface Method2LookupBatchedHmacSha256Metrics {
  invoiceLength: number
  innerBlocks: number
  outerBlocks: number
  totalBlocks: number
  activeRows: number
  paddedRows: number
  traceWidth: number
  compactWidth: number
  lookupRequests: number
  lookupTableRows: number
  committedCells: number
  proofBytes?: number
}

interface LinkDescriptor {
  code: number
  nibble: number
  tag: FieldElement
}

interface LookupBatchedChallenges {
  alphaPowers0: FieldElement[]
  alphaPowers1: FieldElement[]
  compactPowers0: FieldElement[]
  compactPowers1: FieldElement[]
  beta0: FieldElement
  beta1: FieldElement
}

const METHOD2_NARROW_HMAC_CORE_LAYOUT: Method2NarrowHmacCoreLayout = (() => {
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

export const METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT:
Method2LookupBatchedHmacSha256Layout = (() => {
  const compact = 0
  const bitLane = METHOD2_NARROW_HMAC_CORE_LAYOUT.width
  const kind = bitLane + BIT_LANE_WIDTH
  const tag = kind + 1
  const multiplicity = tag + 1
  const publicTuple = multiplicity + 1
  const requestInverse0 = publicTuple + LOG_LOOKUP_TUPLE_ARITY
  const requestInverse1 = requestInverse0 + REQUESTS_PER_CHUNK
  const supplyInverse0 = requestInverse1 + REQUESTS_PER_CHUNK
  const supplyInverse1 = supplyInverse0 + 1
  const accumulator0 = supplyInverse1 + 1
  const accumulator1 = accumulator0 + 1
  const requestCount = accumulator1 + 1
  const supplyCount = requestCount + 1
  const compactTransitionActive = supplyCount + 1
  const compactRepeatActive = compactTransitionActive + 1
  const groupSelector = compactRepeatActive + 1
  return {
    compact,
    bitLane,
    kind,
    tag,
    multiplicity,
    publicTuple,
    requestInverse0,
    requestInverse1,
    supplyInverse0,
    supplyInverse1,
    accumulator0,
    accumulator1,
    requestCount,
    supplyCount,
    compactTransitionActive,
    compactRepeatActive,
    groupSelector,
    keyBytes: compact + METHOD2_NARROW_HMAC_CORE_LAYOUT.keyBytes,
    width: groupSelector + LOOKUP_CHUNKS_PER_COMPACT_ROW
  }
})()

export function buildMethod2LookupBatchedHmacSha256Trace (
  key: number[],
  invoice: number[],
  linkage: number[] = hmacSha256(key, invoice),
  options: { minTraceLength?: number } = {}
): Method2LookupBatchedHmacSha256Trace {
  assertBytes(key, METHOD2_HMAC_KEY_SIZE, 'HMAC key')
  assertBytes(invoice, undefined, 'invoice')
  assertBytes(linkage, METHOD2_SHA256_DIGEST_SIZE, 'linkage')
  if (!bytesEqual(hmacSha256(key, invoice), linkage)) {
    throw new Error('Lookup-batched HMAC-SHA256 linkage does not match key and invoice')
  }
  const compact = buildMethod2CompactHmacSha256Trace(key, invoice, linkage)
  const publicInput = method2LookupBatchedHmacSha256PublicInput(
    invoice,
    linkage,
    options
  )
  const challenges = deriveLookupBatchedChallenges(
    method2LookupBatchedHmacSha256PublicInputDigest(publicInput)
  )
  const rows = Array.from(
    { length: publicInput.traceLength },
    () => new Array<FieldElement>(
      METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.width
    ).fill(0n)
  )
  const descriptors = roundLinkDescriptors()
  const multiplicities = new Array<number>(TABLE_ROWS).fill(0)
  const table = buildMethod2LookupShaHmacTable()
  const tableIndex = new Map<string, number>()
  table.forEach((row, index) => {
    tableIndex.set(tupleKey(row.tag, row.values), index)
  })
  let accumulator0 = 0n
  let accumulator1 = 0n
  let requestCount = 0n
  let supplyCount = 0n

  for (let compactRowIndex = 0; compactRowIndex < publicInput.compactActiveRows; compactRowIndex++) {
    const compactRow = compact.rows[compactRowIndex]
    const requestCompactRow = isCompactRequestRow(
      compactRowIndex,
      publicInput.compactActiveRows
    )
    for (let chunk = 0; chunk < LOOKUP_CHUNKS_PER_COMPACT_ROW; chunk++) {
      const rowIndex = compactChunkRow(compactRowIndex, chunk)
      const row = rows[rowIndex]
      copyCompactCoreIntoNarrow(
        row,
        METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.compact,
        compactRow
      )
      writeBitLanesForLookupChunk(
        row,
        METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.bitLane,
        compactRow,
        chunk
      )
      row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.kind] = requestCompactRow
        ? LOG_LOOKUP_ROW_KIND.request
        : LOG_LOOKUP_ROW_KIND.inactive
      row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.compactRepeatActive] =
        chunk + 1 < LOOKUP_CHUNKS_PER_COMPACT_ROW ? 1n : 0n
      row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.compactTransitionActive] =
        chunk + 1 === LOOKUP_CHUNKS_PER_COMPACT_ROW &&
        compactRowIndex + 1 < publicInput.compactActiveRows
          ? 1n
          : 0n
      if (requestCompactRow) {
        row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.groupSelector + chunk] =
          1n
      }
      row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.accumulator0] = accumulator0
      row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.accumulator1] = accumulator1
      row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.requestCount] = requestCount
      row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.supplyCount] = supplyCount
      if (requestCompactRow) {
        const chunkDescriptors = descriptors.slice(
          chunk * REQUESTS_PER_CHUNK,
          (chunk + 1) * REQUESTS_PER_CHUNK
        )
        chunkDescriptors.forEach((descriptor, index) => {
          const tuple = expectedLookupTupleFromCompactRow(
            compactRow,
            descriptor.code,
            descriptor.nibble
          )
          const tablePosition = tableIndex.get(tupleKey(descriptor.tag, tuple))
          if (tablePosition === undefined) {
            throw new Error('Lookup-batched HMAC-SHA256 request is missing from table')
          }
          multiplicities[tablePosition]++
          const compressed0 = compressLogLookupTuple(
            descriptor.tag,
            tuple,
            challenges.alphaPowers0
          )
          const compressed1 = compressLogLookupTuple(
            descriptor.tag,
            tuple,
            challenges.alphaPowers1
          )
          row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.requestInverse0 + index] =
            F.inv(F.add(challenges.beta0, compressed0))
          row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.requestInverse1 + index] =
            F.inv(F.add(challenges.beta1, compressed1))
        })
        for (const descriptor of chunkDescriptors) {
          const tuple = expectedLookupTupleFromCompactRow(
            compactRow,
            descriptor.code,
            descriptor.nibble
          )
          accumulator0 = F.add(accumulator0, F.inv(F.add(
            challenges.beta0,
            compressLogLookupTuple(
              descriptor.tag,
              tuple,
              challenges.alphaPowers0
            )
          )))
          accumulator1 = F.add(accumulator1, F.inv(F.add(
            challenges.beta1,
            compressLogLookupTuple(
              descriptor.tag,
              tuple,
              challenges.alphaPowers1
            )
          )))
        }
        requestCount = F.add(requestCount, BigInt(REQUESTS_PER_CHUNK))
      }
    }
  }

  table.forEach((tableRow, index) => {
    const rowIndex = compactChunkRows(publicInput) + index
    const row = rows[rowIndex]
    row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.kind] =
      LOG_LOOKUP_ROW_KIND.supply
    row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.tag] = tableRow.tag
    row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.multiplicity] =
      BigInt(multiplicities[index])
    writeTuple(
      row,
      METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.publicTuple,
      tableRow.values
    )
    row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.accumulator0] = accumulator0
    row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.accumulator1] = accumulator1
    row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.requestCount] = requestCount
    row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.supplyCount] = supplyCount
    const compressed0 = compressLogLookupTuple(
      tableRow.tag,
      tableRow.values,
      challenges.alphaPowers0
    )
    const compressed1 = compressLogLookupTuple(
      tableRow.tag,
      tableRow.values,
      challenges.alphaPowers1
    )
    row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.supplyInverse0] =
      F.inv(F.add(challenges.beta0, compressed0))
    row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.supplyInverse1] =
      F.inv(F.add(challenges.beta1, compressed1))
    accumulator0 = F.sub(
      accumulator0,
      F.mul(BigInt(multiplicities[index]), row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.supplyInverse0])
    )
    accumulator1 = F.sub(
      accumulator1,
      F.mul(BigInt(multiplicities[index]), row[METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.supplyInverse1])
    )
    supplyCount = F.add(supplyCount, BigInt(multiplicities[index]))
  })
  for (let rowIndex = publicInput.activeRows; rowIndex < publicInput.traceLength; rowIndex++) {
    rows[rowIndex][METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.accumulator0] =
      accumulator0
    rows[rowIndex][METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.accumulator1] =
      accumulator1
    rows[rowIndex][METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.requestCount] =
      requestCount
    rows[rowIndex][METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.supplyCount] =
      supplyCount
  }

  const trace = {
    publicInput,
    rows,
    layout: METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT,
    compact
  }
  validateMethod2LookupBatchedHmacSha256Trace(trace)
  return trace
}

export function method2LookupBatchedHmacSha256PublicInput (
  invoice: number[],
  linkage: number[],
  options: { minTraceLength?: number } = {}
): Method2LookupBatchedHmacSha256PublicInput {
  const compact = method2CompactHmacSha256PublicInput(invoice, linkage)
  const expectedLookupRequests = compact.totalBlocks * SHA_ROUNDS *
    REQUESTS_PER_ROUND
  const activeRows =
    compact.activeRows * LOOKUP_CHUNKS_PER_COMPACT_ROW + TABLE_ROWS
  const traceLength = nextPowerOfTwo(Math.max(
    activeRows + 1,
    options.minTraceLength ?? 0
  ))
  return {
    relation: 'lookup-batched-hmac-sha256',
    invoice: invoice.slice(),
    linkage: linkage.slice(),
    innerBlocks: compact.innerBlocks,
    outerBlocks: compact.outerBlocks,
    totalBlocks: compact.totalBlocks,
    compactActiveRows: compact.activeRows,
    compactTraceLength: compact.traceLength,
    activeRows,
    traceLength,
    expectedLookupRequests,
    lookupTableRows: TABLE_ROWS,
    tableDigest: method2LookupShaHmacTableDigest()
  }
}

export function buildMethod2LookupBatchedHmacSha256Air (
  publicInput: Method2LookupBatchedHmacSha256PublicInput
): AirDefinition {
  validateMethod2LookupBatchedHmacSha256PublicInput(publicInput)
  const compactPublicInput = compactPublicInputFromBatched(publicInput)
  const compactAir = buildMethod2CompactHmacSha256Air(compactPublicInput)
  const challenges = deriveLookupBatchedChallenges(
    method2LookupBatchedHmacSha256PublicInputDigest(publicInput)
  )
  return {
    traceWidth: METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.width,
    transitionDegree: 10,
    publicInputDigest:
      method2LookupBatchedHmacSha256PublicInputDigest(publicInput),
    boundaryConstraints: [
      ...remapCompactBoundaryConstraints(
        compactAir.boundaryConstraints,
        publicInput
      ),
      ...lookupBoundaryConstraints(publicInput)
    ],
    fullBoundaryColumns: [
      ...remapCompactFullBoundaryColumns(
        compactAir.fullBoundaryColumns ?? [],
        publicInput
      ),
      ...lookupFullBoundaryColumns(publicInput)
    ],
    evaluateTransition: (current, next) =>
      evaluateLookupBatchedHmacTransition(current, next, challenges)
  }
}

export function proveMethod2LookupBatchedHmacSha256 (
  trace: Method2LookupBatchedHmacSha256Trace,
  options: StarkProverOptions = {}
): StarkProof {
  void trace
  void options
  throw new Error(
    'Standalone lookup-batched HMAC proofs are disabled; use proof type 1 with compact HMAC and phased bus commitments'
  )
}

export function verifyMethod2LookupBatchedHmacSha256 (
  publicInput: Method2LookupBatchedHmacSha256PublicInput,
  proof: StarkProof
): boolean {
  void publicInput
  void proof
  return false
}

export function evaluateLookupBatchedHmacTransition (
  current: FieldElement[],
  next: FieldElement[],
  challenges: LookupBatchedChallenges
): FieldElement[] {
  const layout = METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT
  const compactCurrent = current.slice(
    layout.compact,
    layout.compact + METHOD2_NARROW_HMAC_CORE_LAYOUT.width
  )
  const compactNext = next.slice(
    layout.compact,
    layout.compact + METHOD2_NARROW_HMAC_CORE_LAYOUT.width
  )
  const bitLaneCurrent = current.slice(
    layout.bitLane,
    layout.bitLane + BIT_LANE_WIDTH
  )
  const request = kindSelector(current[layout.kind], LOG_LOOKUP_ROW_KIND.request)
  const supply = kindSelector(current[layout.kind], LOG_LOOKUP_ROW_KIND.supply)
  const inactive = kindSelector(current[layout.kind], LOG_LOOKUP_ROW_KIND.inactive)
  const transitionActive = current[layout.compactTransitionActive]
  const repeatActive = current[layout.compactRepeatActive]
  const groupSelectors = Array.from(
    { length: LOOKUP_CHUNKS_PER_COMPACT_ROW },
    (_, index) => current[layout.groupSelector + index]
  )
  const requestGroupSelector = groupSelectors.reduce(
    (total, selector) => F.add(total, selector),
    0n
  )
  const constraints: FieldElement[] = [
    kindDomainConstraint(current[layout.kind]),
    booleanConstraint(transitionActive),
    booleanConstraint(repeatActive),
    F.mul(transitionActive, repeatActive),
    F.sub(request, requestGroupSelector),
    F.mul(inactive, current[layout.multiplicity])
  ]
  for (const selector of groupSelectors) {
    constraints.push(booleanConstraint(selector))
  }
  constraints.push(...gated(
    transitionActive,
    evaluateMethod2NarrowHmacCoreTransition(
      compactCurrent,
      compactNext,
      METHOD2_NARROW_HMAC_CORE_LAYOUT
    )
  ))
  constraints.push(F.mul(
    repeatActive,
    compressedCompactDifference(
      compactCurrent,
      compactNext,
      challenges.compactPowers0
    )
  ))
  constraints.push(F.mul(
    repeatActive,
    compressedCompactDifference(
      compactCurrent,
      compactNext,
      challenges.compactPowers1
    )
  ))
  let delta0 = 0n
  let delta1 = 0n
  const descriptors = roundLinkDescriptors()
  for (let group = 0; group < LOOKUP_CHUNKS_PER_COMPACT_ROW; group++) {
    const selector = groupSelectors[group]
    for (let slot = 0; slot < REQUESTS_PER_CHUNK; slot++) {
      const descriptor = descriptors[group * REQUESTS_PER_CHUNK + slot]
      const tuple = expectedLookupTuple(
        compactCurrent,
        bitLaneCurrent,
        descriptor.code,
        descriptor.nibble
      )
      const compressed0 = compressLogLookupTuple(
        descriptor.tag,
        tuple,
        challenges.alphaPowers0
      )
      const compressed1 = compressLogLookupTuple(
        descriptor.tag,
        tuple,
        challenges.alphaPowers1
      )
      const inverse0 = current[layout.requestInverse0 + slot]
      const inverse1 = current[layout.requestInverse1 + slot]
      constraints.push(F.mul(
        selector,
        F.sub(F.mul(F.add(challenges.beta0, compressed0), inverse0), 1n)
      ))
      constraints.push(F.mul(
        selector,
        F.sub(F.mul(F.add(challenges.beta1, compressed1), inverse1), 1n)
      ))
      constraints.push(...gated(selector, helperOutputBindingConstraints(
        compactCurrent,
        bitLaneCurrent,
        tuple,
        descriptor
      )))
    }
  }
  constraints.push(...bitLaneBindingConstraints(
    compactCurrent,
    bitLaneCurrent,
    groupSelectors
  ))
  for (let slot = 0; slot < REQUESTS_PER_CHUNK; slot++) {
    const inverse0 = current[layout.requestInverse0 + slot]
    const inverse1 = current[layout.requestInverse1 + slot]
    constraints.push(F.mul(F.sub(1n, request), inverse0))
    constraints.push(F.mul(F.sub(1n, request), inverse1))
    delta0 = F.add(delta0, F.mul(request, inverse0))
    delta1 = F.add(delta1, F.mul(request, inverse1))
  }
  const supplyTuple = current.slice(
    layout.publicTuple,
    layout.publicTuple + LOG_LOOKUP_TUPLE_ARITY
  )
  const supplyCompressed0 = compressLogLookupTuple(
    current[layout.tag],
    supplyTuple,
    challenges.alphaPowers0
  )
  const supplyCompressed1 = compressLogLookupTuple(
    current[layout.tag],
    supplyTuple,
    challenges.alphaPowers1
  )
  constraints.push(F.mul(
    supply,
    F.sub(
      F.mul(F.add(challenges.beta0, supplyCompressed0), current[layout.supplyInverse0]),
      1n
    )
  ))
  constraints.push(F.mul(
    supply,
    F.sub(
      F.mul(F.add(challenges.beta1, supplyCompressed1), current[layout.supplyInverse1]),
      1n
    )
  ))
  delta0 = F.sub(
    delta0,
    F.mul(supply, F.mul(current[layout.multiplicity], current[layout.supplyInverse0]))
  )
  delta1 = F.sub(
    delta1,
    F.mul(supply, F.mul(current[layout.multiplicity], current[layout.supplyInverse1]))
  )
  constraints.push(F.sub(next[layout.accumulator0], F.add(current[layout.accumulator0], delta0)))
  constraints.push(F.sub(next[layout.accumulator1], F.add(current[layout.accumulator1], delta1)))
  constraints.push(F.sub(
    next[layout.requestCount],
    F.add(current[layout.requestCount], F.mul(request, BigInt(REQUESTS_PER_CHUNK)))
  ))
  constraints.push(F.sub(
    next[layout.supplyCount],
    F.add(current[layout.supplyCount], F.mul(supply, current[layout.multiplicity]))
  ))
  return constraints
}

export function method2LookupBatchedHmacSha256Metrics (
  trace: Method2LookupBatchedHmacSha256Trace,
  proof?: StarkProof
): Method2LookupBatchedHmacSha256Metrics {
  return {
    invoiceLength: trace.publicInput.invoice.length,
    innerBlocks: trace.publicInput.innerBlocks,
    outerBlocks: trace.publicInput.outerBlocks,
    totalBlocks: trace.publicInput.totalBlocks,
    activeRows: trace.publicInput.activeRows,
    paddedRows: trace.publicInput.traceLength,
    traceWidth: trace.layout.width,
    compactWidth: METHOD2_NARROW_HMAC_CORE_LAYOUT.width,
    lookupRequests: trace.publicInput.expectedLookupRequests,
    lookupTableRows: trace.publicInput.lookupTableRows,
    committedCells: trace.publicInput.traceLength * trace.layout.width,
    proofBytes: proof === undefined ? undefined : serializeStarkProof(proof).length
  }
}

export function method2LookupBatchedHmacSha256KeyForLink (
  trace: Method2LookupBatchedHmacSha256Trace
): number[] {
  validateMethod2LookupBatchedHmacSha256Trace(trace)
  return method2CompactHmacSha256KeyForLink(trace.compact)
}

export function method2LookupBatchedHmacSha256PublicInputDigest (
  publicInput: Method2LookupBatchedHmacSha256PublicInput
): number[] {
  validateMethod2LookupBatchedHmacSha256PublicInput(publicInput)
  const writer = new Writer()
  writer.write(toArray(METHOD2_LOOKUP_BATCHED_HMAC_SHA256_PUBLIC_INPUT_ID, 'utf8'))
  writer.writeVarIntNum(publicInput.invoice.length)
  writer.write(publicInput.invoice)
  writer.writeVarIntNum(publicInput.linkage.length)
  writer.write(publicInput.linkage)
  writer.writeVarIntNum(publicInput.innerBlocks)
  writer.writeVarIntNum(publicInput.outerBlocks)
  writer.writeVarIntNum(publicInput.totalBlocks)
  writer.writeVarIntNum(publicInput.compactActiveRows)
  writer.writeVarIntNum(publicInput.compactTraceLength)
  writer.writeVarIntNum(publicInput.activeRows)
  writer.writeVarIntNum(publicInput.traceLength)
  writer.writeVarIntNum(publicInput.expectedLookupRequests)
  writer.writeVarIntNum(publicInput.lookupTableRows)
  writer.writeVarIntNum(publicInput.tableDigest.length)
  writer.write(publicInput.tableDigest)
  writer.writeVarIntNum(REQUESTS_PER_CHUNK)
  writer.writeVarIntNum(LOOKUP_CHUNKS_PER_COMPACT_ROW)
  writer.writeVarIntNum(METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.width)
  return sha256(writer.toArray())
}

export function validateMethod2LookupBatchedHmacSha256Trace (
  trace: Method2LookupBatchedHmacSha256Trace
): void {
  validateMethod2LookupBatchedHmacSha256PublicInput(trace.publicInput)
  const key = method2CompactHmacSha256KeyForLink(trace.compact)
  try {
    if (!bytesEqual(hmacSha256(key, trace.publicInput.invoice), trace.publicInput.linkage)) {
      throw new Error('Lookup-batched HMAC-SHA256 trace linkage mismatch')
    }
  } finally {
    key.fill(0)
  }
  if (trace.layout.width !== METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.width) {
    throw new Error('Lookup-batched HMAC-SHA256 layout mismatch')
  }
  if (trace.rows.length !== trace.publicInput.traceLength) {
    throw new Error('Lookup-batched HMAC-SHA256 trace length mismatch')
  }
  for (const row of trace.rows) {
    if (row.length !== trace.layout.width) {
      throw new Error('Lookup-batched HMAC-SHA256 trace row width mismatch')
    }
  }
}

export function validateMethod2LookupBatchedHmacSha256PublicInput (
  publicInput: Method2LookupBatchedHmacSha256PublicInput
): void {
  if (publicInput.relation !== 'lookup-batched-hmac-sha256') {
    throw new Error('Lookup-batched HMAC-SHA256 relation mismatch')
  }
  assertBytes(publicInput.invoice, undefined, 'invoice')
  assertBytes(publicInput.linkage, METHOD2_SHA256_DIGEST_SIZE, 'linkage')
  const expected = method2LookupBatchedHmacSha256PublicInput(
    publicInput.invoice,
    publicInput.linkage
  )
  if (
    publicInput.innerBlocks !== expected.innerBlocks ||
    publicInput.outerBlocks !== expected.outerBlocks ||
    publicInput.totalBlocks !== expected.totalBlocks ||
    publicInput.compactActiveRows !== expected.compactActiveRows ||
    publicInput.compactTraceLength !== expected.compactTraceLength ||
    publicInput.activeRows !== expected.activeRows ||
    publicInput.expectedLookupRequests !== expected.expectedLookupRequests ||
    publicInput.lookupTableRows !== expected.lookupTableRows
  ) {
    throw new Error('Lookup-batched HMAC-SHA256 public input shape mismatch')
  }
  if (
    !isPowerOfTwo(publicInput.traceLength) ||
    publicInput.traceLength < expected.traceLength
  ) {
    throw new Error('Lookup-batched HMAC-SHA256 trace length mismatch')
  }
  if (!bytesEqual(publicInput.tableDigest, expected.tableDigest)) {
    throw new Error('Lookup-batched HMAC-SHA256 table digest mismatch')
  }
}

function lookupBoundaryConstraints (
  publicInput: Method2LookupBatchedHmacSha256PublicInput
): AirDefinition['boundaryConstraints'] {
  const layout = METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT
  const lastRow = publicInput.activeRows
  return [
    { column: layout.accumulator0, row: 0, value: 0n },
    { column: layout.accumulator1, row: 0, value: 0n },
    { column: layout.requestCount, row: 0, value: 0n },
    { column: layout.supplyCount, row: 0, value: 0n },
    { column: layout.accumulator0, row: lastRow, value: 0n },
    { column: layout.accumulator1, row: lastRow, value: 0n },
    {
      column: layout.requestCount,
      row: lastRow,
      value: BigInt(publicInput.expectedLookupRequests)
    },
    {
      column: layout.supplyCount,
      row: lastRow,
      value: BigInt(publicInput.expectedLookupRequests)
    }
  ]
}

function lookupFullBoundaryColumns (
  publicInput: Method2LookupBatchedHmacSha256PublicInput
): NonNullable<AirDefinition['fullBoundaryColumns']> {
  const layout = METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT
  const table = buildMethod2LookupShaHmacTable()
  const kind = new Array<FieldElement>(publicInput.traceLength).fill(0n)
  const tag = new Array<FieldElement>(publicInput.traceLength).fill(0n)
  const compactTransitionActive = new Array<FieldElement>(
    publicInput.traceLength
  ).fill(0n)
  const compactRepeatActive = new Array<FieldElement>(
    publicInput.traceLength
  ).fill(0n)
  const groupSelectors = Array.from(
    { length: LOOKUP_CHUNKS_PER_COMPACT_ROW },
    () => new Array<FieldElement>(publicInput.traceLength).fill(0n)
  )
  const publicTuples = Array.from(
    { length: LOG_LOOKUP_TUPLE_ARITY },
    () => new Array<FieldElement>(publicInput.traceLength).fill(0n)
  )
  for (let compactRow = 0; compactRow < publicInput.compactActiveRows; compactRow++) {
    const requestRow = isCompactRequestRow(
      compactRow,
      publicInput.compactActiveRows
    )
    for (let chunk = 0; chunk < LOOKUP_CHUNKS_PER_COMPACT_ROW; chunk++) {
      const row = compactChunkRow(compactRow, chunk)
      kind[row] = requestRow
        ? LOG_LOOKUP_ROW_KIND.request
        : LOG_LOOKUP_ROW_KIND.inactive
      compactRepeatActive[row] =
        chunk + 1 < LOOKUP_CHUNKS_PER_COMPACT_ROW ? 1n : 0n
      compactTransitionActive[row] =
        chunk + 1 === LOOKUP_CHUNKS_PER_COMPACT_ROW &&
        compactRow + 1 < publicInput.compactActiveRows
          ? 1n
          : 0n
      if (requestRow) groupSelectors[chunk][row] = 1n
    }
  }
  table.forEach((tableRow, index) => {
    const row = compactChunkRows(publicInput) + index
    kind[row] = LOG_LOOKUP_ROW_KIND.supply
    tag[row] = tableRow.tag
    for (let i = 0; i < LOG_LOOKUP_TUPLE_ARITY; i++) {
      publicTuples[i][row] = tableRow.values[i]
    }
  })
  return [
    { column: layout.kind, values: kind },
    { column: layout.tag, values: tag },
    { column: layout.compactTransitionActive, values: compactTransitionActive },
    { column: layout.compactRepeatActive, values: compactRepeatActive },
    ...groupSelectors.map((values, index) => ({
      column: layout.groupSelector + index,
      values
    })),
    ...publicTuples.map((values, index) => ({
      column: layout.publicTuple + index,
      values
    }))
  ]
}

function remapCompactBoundaryConstraints (
  constraints: AirDefinition['boundaryConstraints'],
  publicInput: Method2LookupBatchedHmacSha256PublicInput
): AirDefinition['boundaryConstraints'] {
  return constraints.flatMap(constraint => {
    const mappedColumn = mapCompactColumnToNarrow(constraint.column)
    if (mappedColumn === undefined) return []
    const row = compactChunkRow(constraint.row, 0)
    if (row >= compactChunkRows(publicInput)) return []
    return [{
      column: METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.compact +
        mappedColumn,
      row,
      value: constraint.value
    }]
  })
}

function remapCompactFullBoundaryColumns (
  columns: NonNullable<AirDefinition['fullBoundaryColumns']>,
  publicInput: Method2LookupBatchedHmacSha256PublicInput
): NonNullable<AirDefinition['fullBoundaryColumns']> {
  return columns.map(column => {
    const mappedColumn = mapCompactColumnToNarrow(column.column)
    if (mappedColumn === undefined) return undefined
    const values = new Array<FieldElement>(publicInput.traceLength).fill(0n)
    for (let compactRow = 0; compactRow < publicInput.compactActiveRows; compactRow++) {
      for (let chunk = 0; chunk < LOOKUP_CHUNKS_PER_COMPACT_ROW; chunk++) {
        values[compactChunkRow(compactRow, chunk)] =
          F.normalize(column.values[compactRow] ?? 0n)
      }
    }
    return {
      column: METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.compact + mappedColumn,
      values
    }
  }).filter(column => column !== undefined)
}

function compactPublicInputFromBatched (
  publicInput: Method2LookupBatchedHmacSha256PublicInput
): Method2CompactHmacSha256PublicInput {
  const compact = method2CompactHmacSha256PublicInput(
    publicInput.invoice,
    publicInput.linkage
  )
  validateMethod2CompactHmacSha256PublicInput(compact)
  return compact
}

function copyCompactCoreIntoNarrow (
  target: FieldElement[],
  offset: number,
  compactRow: FieldElement[]
): void {
  for (let column = 0; column < METHOD2_COMPACT_HMAC_SHA256_LAYOUT.width; column++) {
    const mappedColumn = mapCompactColumnToNarrow(column)
    if (mappedColumn !== undefined) {
      target[offset + mappedColumn] = compactRow[column]
    }
  }
}

function mapCompactColumnToNarrow (column: number): number | undefined {
  const compact = METHOD2_COMPACT_HMAC_SHA256_LAYOUT
  const narrow = METHOD2_NARROW_HMAC_CORE_LAYOUT
  if (column < compact.aBits) return column
  if (inRange(column, compact.keyBytes, METHOD2_HMAC_KEY_SIZE)) {
    return narrow.keyBytes + column - compact.keyBytes
  }
  if (inRange(column, compact.innerKeyBytes, METHOD2_HMAC_KEY_SIZE)) {
    return narrow.innerKeyBytes + column - compact.innerKeyBytes
  }
  if (inRange(column, compact.outerKeyBytes, METHOD2_HMAC_KEY_SIZE)) {
    return narrow.outerKeyBytes + column - compact.outerKeyBytes
  }
  if (inRange(column, compact.keyCheckBits, 24)) {
    return narrow.keyCheckBits + column - compact.keyCheckBits
  }
  if (inRange(column, compact.keyCheckSelectors, METHOD2_HMAC_KEY_SIZE)) {
    return narrow.keyCheckSelectors + column - compact.keyCheckSelectors
  }
  if (inRange(column, compact.innerDigestChunks, STATE_WORDS * WORD_CHUNKS)) {
    return narrow.innerDigestChunks + column - compact.innerDigestChunks
  }
  return undefined
}

function inRange (value: number, start: number, length: number): boolean {
  return value >= start && value < start + length
}

function writeBitLanesForLookupChunk (
  row: FieldElement[],
  offset: number,
  compactRow: FieldElement[],
  chunk: number
): void {
  const descriptors = roundLinkDescriptors()
  const descriptor = descriptors[chunk * REQUESTS_PER_CHUNK]
  const bits = compactBits(compactRow)
  const sourceLanes = bitLanesForDescriptor(bits, descriptor.code)
  const lanes = [
    sourceLanes[0] ?? ZERO_BITS,
    sourceLanes[1] ?? ZERO_BITS,
    sourceLanes[2] ?? ZERO_BITS,
    helperBitsForDescriptor(compactRow, descriptor.code)
  ]
  for (let lane = 0; lane < BIT_LANE_WORDS; lane++) {
    const source = lanes[lane] ?? ZERO_BITS
    for (let bit = 0; bit < WORD_BITS; bit++) {
      row[offset + lane * WORD_BITS + bit] = source[bit]
    }
  }
}

const ZERO_BITS = new Array<FieldElement>(WORD_BITS).fill(0n)

function bitLanesForDescriptor (
  bits: ReturnType<typeof compactBits>,
  code: number
): FieldElement[][] {
  switch (code) {
    case LINK_XOR_SIGMA0_FIRST:
    case LINK_XOR_SIGMA0_SECOND:
      return [bits.a]
    case LINK_XOR_SIGMA1_FIRST:
    case LINK_XOR_SIGMA1_SECOND:
    case LINK_CH_AND_EF:
    case LINK_CH_AND_NOT_E_G:
    case LINK_CH_XOR:
      return [bits.e, bits.f, bits.g]
    case LINK_MAJ_AND_AB:
    case LINK_MAJ_AND_AC:
    case LINK_MAJ_AND_BC:
    case LINK_MAJ_XOR_AB_AC:
    case LINK_MAJ_XOR_TEMP_BC:
      return [bits.a, bits.b, bits.c]
    case LINK_XOR_SMALL0_FIRST:
    case LINK_XOR_SMALL0_SECOND:
      return [bits.schedule1]
    case LINK_XOR_SMALL1_FIRST:
    case LINK_XOR_SMALL1_SECOND:
      return [bits.schedule14]
    default:
      return []
  }
}

function helperBitsForDescriptor (
  compactRow: FieldElement[],
  code: number
): FieldElement[] {
  const layout = METHOD2_COMPACT_HMAC_SHA256_LAYOUT
  switch (code) {
    case LINK_XOR_SIGMA0_FIRST:
    case LINK_XOR_SIGMA0_SECOND:
      return wordBitsFromCompactRow(compactRow, layout.sigma0)
    case LINK_XOR_SIGMA1_FIRST:
    case LINK_XOR_SIGMA1_SECOND:
      return wordBitsFromCompactRow(compactRow, layout.sigma1)
    case LINK_CH_AND_EF:
    case LINK_CH_AND_NOT_E_G:
    case LINK_CH_XOR:
      return wordBitsFromCompactRow(compactRow, layout.ch)
    case LINK_MAJ_AND_AB:
    case LINK_MAJ_AND_AC:
    case LINK_MAJ_AND_BC:
    case LINK_MAJ_XOR_AB_AC:
    case LINK_MAJ_XOR_TEMP_BC:
      return wordBitsFromCompactRow(compactRow, layout.maj)
    case LINK_XOR_SMALL0_FIRST:
    case LINK_XOR_SMALL0_SECOND:
      return wordBitsFromCompactRow(compactRow, layout.smallSigma0)
    case LINK_XOR_SMALL1_FIRST:
    case LINK_XOR_SMALL1_SECOND:
      return wordBitsFromCompactRow(compactRow, layout.smallSigma1)
    default:
      return ZERO_BITS
  }
}

function wordBitsFromCompactRow (
  row: FieldElement[],
  offset: number
): FieldElement[] {
  const lo = Number(row[offset])
  const hi = Number(row[offset + 1])
  const out = new Array<FieldElement>(WORD_BITS)
  for (let bit = 0; bit < CHUNK_BITS; bit++) {
    out[bit] = BigInt((lo >>> bit) & 1)
    out[bit + CHUNK_BITS] = BigInt((hi >>> bit) & 1)
  }
  return out
}

function roundLinkDescriptors (): LinkDescriptor[] {
  const out: LinkDescriptor[] = []
  appendXor3Descriptors(out, LINK_XOR_SIGMA0_FIRST, LINK_XOR_SIGMA0_SECOND)
  appendXor3Descriptors(out, LINK_XOR_SIGMA1_FIRST, LINK_XOR_SIGMA1_SECOND)
  appendChDescriptors(out)
  appendMajDescriptors(out)
  appendXor3Descriptors(out, LINK_XOR_SMALL0_FIRST, LINK_XOR_SMALL0_SECOND)
  appendXor3Descriptors(out, LINK_XOR_SMALL1_FIRST, LINK_XOR_SMALL1_SECOND)
  return out
}

function appendXor3Descriptors (
  out: LinkDescriptor[],
  first: number,
  second: number
): void {
  for (let nibble = 0; nibble < NIBBLES_PER_WORD; nibble++) {
    out.push({ code: first, nibble, tag: METHOD2_LOOKUP_SHA_TAG_XOR4 })
    out.push({ code: second, nibble, tag: METHOD2_LOOKUP_SHA_TAG_XOR4 })
  }
}

function appendChDescriptors (out: LinkDescriptor[]): void {
  for (let nibble = 0; nibble < NIBBLES_PER_WORD; nibble++) {
    out.push({ code: LINK_CH_AND_EF, nibble, tag: METHOD2_LOOKUP_SHA_TAG_AND4 })
    out.push({ code: LINK_CH_AND_NOT_E_G, nibble, tag: METHOD2_LOOKUP_SHA_TAG_AND4 })
    out.push({ code: LINK_CH_XOR, nibble, tag: METHOD2_LOOKUP_SHA_TAG_XOR4 })
  }
}

function appendMajDescriptors (out: LinkDescriptor[]): void {
  for (let nibble = 0; nibble < NIBBLES_PER_WORD; nibble++) {
    out.push({ code: LINK_MAJ_AND_AB, nibble, tag: METHOD2_LOOKUP_SHA_TAG_AND4 })
    out.push({ code: LINK_MAJ_AND_AC, nibble, tag: METHOD2_LOOKUP_SHA_TAG_AND4 })
    out.push({ code: LINK_MAJ_AND_BC, nibble, tag: METHOD2_LOOKUP_SHA_TAG_AND4 })
    out.push({ code: LINK_MAJ_XOR_AB_AC, nibble, tag: METHOD2_LOOKUP_SHA_TAG_XOR4 })
    out.push({ code: LINK_MAJ_XOR_TEMP_BC, nibble, tag: METHOD2_LOOKUP_SHA_TAG_XOR4 })
  }
}

function expectedLookupTupleFromCompactRow (
  compactRow: FieldElement[],
  code: number,
  nibble: number
): FieldElement[] {
  const bits = compactBits(compactRow)
  switch (code) {
    case LINK_XOR_SIGMA0_FIRST:
      return xorFirstTuple(rotrBits(bits.a, 2), rotrBits(bits.a, 13), nibble)
    case LINK_XOR_SIGMA0_SECOND:
      return xorSecondTuple(rotrBits(bits.a, 2), rotrBits(bits.a, 13), rotrBits(bits.a, 22), nibble)
    case LINK_XOR_SIGMA1_FIRST:
      return xorFirstTuple(rotrBits(bits.e, 6), rotrBits(bits.e, 11), nibble)
    case LINK_XOR_SIGMA1_SECOND:
      return xorSecondTuple(rotrBits(bits.e, 6), rotrBits(bits.e, 11), rotrBits(bits.e, 25), nibble)
    case LINK_CH_AND_EF:
      return andTuple(bits.e, bits.f, nibble)
    case LINK_CH_AND_NOT_E_G:
      return andTuple(notBits(bits.e), bits.g, nibble)
    case LINK_CH_XOR:
      return xorFirstTuple(andBits(bits.e, bits.f), andBits(notBits(bits.e), bits.g), nibble)
    case LINK_MAJ_AND_AB:
      return andTuple(bits.a, bits.b, nibble)
    case LINK_MAJ_AND_AC:
      return andTuple(bits.a, bits.c, nibble)
    case LINK_MAJ_AND_BC:
      return andTuple(bits.b, bits.c, nibble)
    case LINK_MAJ_XOR_AB_AC:
      return xorFirstTuple(andBits(bits.a, bits.b), andBits(bits.a, bits.c), nibble)
    case LINK_MAJ_XOR_TEMP_BC:
      return xorFirstTuple(
        xorBits(andBits(bits.a, bits.b), andBits(bits.a, bits.c)),
        andBits(bits.b, bits.c),
        nibble
      )
    case LINK_XOR_SMALL0_FIRST:
      return xorFirstTuple(rotrBits(bits.schedule1, 7), rotrBits(bits.schedule1, 18), nibble)
    case LINK_XOR_SMALL0_SECOND:
      return xorSecondTuple(rotrBits(bits.schedule1, 7), rotrBits(bits.schedule1, 18), shrBits(bits.schedule1, 3), nibble)
    case LINK_XOR_SMALL1_FIRST:
      return xorFirstTuple(rotrBits(bits.schedule14, 17), rotrBits(bits.schedule14, 19), nibble)
    case LINK_XOR_SMALL1_SECOND:
      return xorSecondTuple(rotrBits(bits.schedule14, 17), rotrBits(bits.schedule14, 19), shrBits(bits.schedule14, 10), nibble)
    default:
      return zeroTuple()
  }
}

function expectedLookupTuple (
  compactRow: FieldElement[],
  bitLane: FieldElement[],
  code: number,
  nibble: number
): FieldElement[] {
  const bits = bitLaneBits(bitLane)
  switch (code) {
    case LINK_XOR_SIGMA0_FIRST:
      return xorFirstTuple(rotrBits(bits.left, 2), rotrBits(bits.left, 13), nibble)
    case LINK_XOR_SIGMA0_SECOND:
      return xorSecondTuple(rotrBits(bits.left, 2), rotrBits(bits.left, 13), rotrBits(bits.left, 22), nibble)
    case LINK_XOR_SIGMA1_FIRST:
      return xorFirstTuple(rotrBits(bits.left, 6), rotrBits(bits.left, 11), nibble)
    case LINK_XOR_SIGMA1_SECOND:
      return xorSecondTuple(rotrBits(bits.left, 6), rotrBits(bits.left, 11), rotrBits(bits.left, 25), nibble)
    case LINK_CH_AND_EF:
      return andTuple(bits.left, bits.middle, nibble)
    case LINK_CH_AND_NOT_E_G:
      return andTuple(notBits(bits.left), bits.right, nibble)
    case LINK_CH_XOR:
      return xorFirstTuple(andBits(bits.left, bits.middle), andBits(notBits(bits.left), bits.right), nibble)
    case LINK_MAJ_AND_AB:
      return andTuple(bits.left, bits.middle, nibble)
    case LINK_MAJ_AND_AC:
      return andTuple(bits.left, bits.right, nibble)
    case LINK_MAJ_AND_BC:
      return andTuple(bits.middle, bits.right, nibble)
    case LINK_MAJ_XOR_AB_AC:
      return xorFirstTuple(andBits(bits.left, bits.middle), andBits(bits.left, bits.right), nibble)
    case LINK_MAJ_XOR_TEMP_BC:
      return xorFirstTuple(
        xorBits(andBits(bits.left, bits.middle), andBits(bits.left, bits.right)),
        andBits(bits.middle, bits.right),
        nibble
      )
    case LINK_XOR_SMALL0_FIRST:
      return xorFirstTuple(rotrBits(bits.left, 7), rotrBits(bits.left, 18), nibble)
    case LINK_XOR_SMALL0_SECOND:
      return xorSecondTuple(rotrBits(bits.left, 7), rotrBits(bits.left, 18), shrBits(bits.left, 3), nibble)
    case LINK_XOR_SMALL1_FIRST:
      return xorFirstTuple(rotrBits(bits.left, 17), rotrBits(bits.left, 19), nibble)
    case LINK_XOR_SMALL1_SECOND:
      return xorSecondTuple(rotrBits(bits.left, 17), rotrBits(bits.left, 19), shrBits(bits.left, 10), nibble)
    default:
      return zeroTuple()
  }
}

function bitLaneBits (
  bitLane: FieldElement[]
): {
    left: FieldElement[]
    middle: FieldElement[]
    right: FieldElement[]
    output: FieldElement[]
  } {
  return {
    left: bitLane.slice(0, WORD_BITS),
    middle: bitLane.slice(WORD_BITS, WORD_BITS * 2),
    right: bitLane.slice(WORD_BITS * 2, WORD_BITS * 3),
    output: bitLane.slice(WORD_BITS * 3, WORD_BITS * 4)
  }
}

function bitLaneBindingConstraints (
  compactRow: FieldElement[],
  bitLane: FieldElement[],
  groupSelectors: FieldElement[]
): FieldElement[] {
  const bits = bitLaneBits(bitLane)
  const constraints: FieldElement[] = []
  for (const selector of groupSelectors) {
    constraints.push(...gated(selector, bitBooleanConstraintsForBits(bits.left)))
    constraints.push(...gated(selector, bitBooleanConstraintsForBits(bits.middle)))
    constraints.push(...gated(selector, bitBooleanConstraintsForBits(bits.right)))
    constraints.push(...gated(selector, bitBooleanConstraintsForBits(bits.output)))
  }
  const descriptors = roundLinkDescriptors()
  for (let group = 0; group < LOOKUP_CHUNKS_PER_COMPACT_ROW; group++) {
    constraints.push(...gated(
      groupSelectors[group],
      bitLaneWordBindingConstraints(
        compactRow,
        bitLane,
        descriptors[group * REQUESTS_PER_CHUNK].code
      )
    ))
  }
  return constraints
}

function bitLaneWordBindingConstraints (
  compactRow: FieldElement[],
  bitLane: FieldElement[],
  code: number
): FieldElement[] {
  const layout = METHOD2_NARROW_HMAC_CORE_LAYOUT
  const bits = bitLaneBits(bitLane)
  const state = readWords(compactRow, layout.state, STATE_WORDS)
  const schedule = readWords(compactRow, layout.schedule, SCHEDULE_WINDOW)
  switch (code) {
    case LINK_XOR_SIGMA0_FIRST:
    case LINK_XOR_SIGMA0_SECOND:
      return [
        ...wordEqualsBits(state[0], bits.left),
        ...wordEqualsBits(readWord(compactRow, layout.sigma0), bits.output)
      ]
    case LINK_XOR_SIGMA1_FIRST:
    case LINK_XOR_SIGMA1_SECOND:
      return [
        ...wordEqualsBits(state[4], bits.left),
        ...wordEqualsBits(readWord(compactRow, layout.sigma1), bits.output)
      ]
    case LINK_CH_AND_EF:
    case LINK_CH_AND_NOT_E_G:
    case LINK_CH_XOR:
      return [
        ...wordEqualsBits(state[4], bits.left),
        ...wordEqualsBits(state[5], bits.middle),
        ...wordEqualsBits(state[6], bits.right),
        ...wordEqualsBits(readWord(compactRow, layout.ch), bits.output)
      ]
    case LINK_MAJ_AND_AB:
    case LINK_MAJ_AND_AC:
    case LINK_MAJ_AND_BC:
    case LINK_MAJ_XOR_AB_AC:
    case LINK_MAJ_XOR_TEMP_BC:
      return [
        ...wordEqualsBits(state[0], bits.left),
        ...wordEqualsBits(state[1], bits.middle),
        ...wordEqualsBits(state[2], bits.right),
        ...wordEqualsBits(readWord(compactRow, layout.maj), bits.output)
      ]
    case LINK_XOR_SMALL0_FIRST:
    case LINK_XOR_SMALL0_SECOND:
      return [
        ...wordEqualsBits(schedule[1], bits.left),
        ...wordEqualsBits(readWord(compactRow, layout.smallSigma0), bits.output)
      ]
    case LINK_XOR_SMALL1_FIRST:
    case LINK_XOR_SMALL1_SECOND:
      return [
        ...wordEqualsBits(schedule[14], bits.left),
        ...wordEqualsBits(readWord(compactRow, layout.smallSigma1), bits.output)
      ]
    default:
      return []
  }
}

function helperOutputBindingConstraints (
  compactRow: FieldElement[],
  bitLane: FieldElement[],
  tuple: FieldElement[],
  descriptor: LinkDescriptor
): FieldElement[] {
  const outputNibble = tuple[2]
  const expected = nibbleFromBits(bitLaneBits(bitLane).output, descriptor.nibble)
  switch (descriptor.code) {
    case LINK_XOR_SIGMA0_SECOND:
    case LINK_XOR_SIGMA1_SECOND:
    case LINK_CH_XOR:
    case LINK_MAJ_XOR_TEMP_BC:
    case LINK_XOR_SMALL0_SECOND:
    case LINK_XOR_SMALL1_SECOND:
      return [F.sub(outputNibble, expected)]
    default:
      return []
  }
}

function evaluateMethod2NarrowHmacCoreTransition (
  current: FieldElement[],
  next: FieldElement[],
  layout: Method2NarrowHmacCoreLayout
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
  constraints.push(...narrowHmacLinkConstraints(current, next, layout))
  return constraints
}

function narrowHmacLinkConstraints (
  current: FieldElement[],
  next: FieldElement[],
  layout: Method2NarrowHmacCoreLayout
): FieldElement[] {
  const constraints: FieldElement[] = []
  for (let byteIndex = 0; byteIndex < METHOD2_HMAC_KEY_SIZE; byteIndex++) {
    constraints.push(F.mul(
      current[layout.keyCarry],
      F.sub(next[layout.keyBytes + byteIndex], current[layout.keyBytes + byteIndex])
    ))
    constraints.push(F.mul(
      current[layout.keyCarry],
      F.sub(next[layout.innerKeyBytes + byteIndex], current[layout.innerKeyBytes + byteIndex])
    ))
    constraints.push(F.mul(
      current[layout.keyCarry],
      F.sub(next[layout.outerKeyBytes + byteIndex], current[layout.outerKeyBytes + byteIndex])
    ))
  }
  constraints.push(...keyByteCheckConstraints(current, layout))
  for (let chunk = 0; chunk < STATE_WORDS * WORD_CHUNKS; chunk++) {
    constraints.push(F.mul(
      current[layout.digestCarry],
      F.sub(next[layout.innerDigestChunks + chunk], current[layout.innerDigestChunks + chunk])
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
  layout: Method2NarrowHmacCoreLayout,
  selector: FieldElement,
  byteOffset: number,
  pad: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  for (let word = 0; word < SCHEDULE_WINDOW; word++) {
    const bytes: FieldElement[] = []
    for (let byte = 0; byte < 4; byte++) {
      const byteIndex = word * 4 + byte
      bytes.push(byteIndex < METHOD2_HMAC_KEY_SIZE
        ? row[byteOffset + byteIndex]
        : BigInt(pad))
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
  layout: Method2NarrowHmacCoreLayout
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

function smallRangeConstraint (
  value: FieldElement,
  maxInclusive: number
): FieldElement {
  let out = 1n
  for (let item = 0; item <= maxInclusive; item++) {
    out = F.mul(out, F.sub(value, BigInt(item)))
  }
  return out
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

function wordEquality (
  left: FieldElement[],
  right: FieldElement[]
): FieldElement[] {
  return [
    F.sub(left[0], right[0]),
    F.sub(left[1], right[1])
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

function compactBits (
  row: FieldElement[]
): Record<string, FieldElement[]> {
  const layout = METHOD2_COMPACT_HMAC_SHA256_LAYOUT
  return {
    a: row.slice(layout.aBits, layout.aBits + WORD_BITS),
    b: row.slice(layout.bBits, layout.bBits + WORD_BITS),
    c: row.slice(layout.cBits, layout.cBits + WORD_BITS),
    e: row.slice(layout.eBits, layout.eBits + WORD_BITS),
    f: row.slice(layout.fBits, layout.fBits + WORD_BITS),
    g: row.slice(layout.gBits, layout.gBits + WORD_BITS),
    schedule1: row.slice(layout.schedule1Bits, layout.schedule1Bits + WORD_BITS),
    schedule14: row.slice(layout.schedule14Bits, layout.schedule14Bits + WORD_BITS)
  }
}

function xorFirstTuple (
  left: FieldElement[],
  right: FieldElement[],
  nibble: number
): FieldElement[] {
  return padTuple([
    nibbleFromBits(left, nibble),
    nibbleFromBits(right, nibble),
    nibbleFromBits(xorBits(left, right), nibble)
  ])
}

function xorSecondTuple (
  left: FieldElement[],
  middle: FieldElement[],
  right: FieldElement[],
  nibble: number
): FieldElement[] {
  const temp = xorBits(left, middle)
  return padTuple([
    nibbleFromBits(temp, nibble),
    nibbleFromBits(right, nibble),
    nibbleFromBits(xorBits(temp, right), nibble)
  ])
}

function andTuple (
  left: FieldElement[],
  right: FieldElement[],
  nibble: number
): FieldElement[] {
  return padTuple([
    nibbleFromBits(left, nibble),
    nibbleFromBits(right, nibble),
    nibbleFromBits(andBits(left, right), nibble)
  ])
}

function rotrBits (bits: FieldElement[], amount: number): FieldElement[] {
  return bits.map((_, bit) => bits[(bit + amount) % WORD_BITS])
}

function shrBits (bits: FieldElement[], amount: number): FieldElement[] {
  return bits.map((_, bit) => bit + amount < WORD_BITS ? bits[bit + amount] : 0n)
}

function xorBits (
  left: FieldElement[],
  right: FieldElement[]
): FieldElement[] {
  return left.map((bit, index) => xorBit(bit, right[index]))
}

function andBits (
  left: FieldElement[],
  right: FieldElement[]
): FieldElement[] {
  return left.map((bit, index) => F.mul(bit, right[index]))
}

function notBits (bits: FieldElement[]): FieldElement[] {
  return bits.map(bit => F.sub(1n, bit))
}

function xorBit (left: FieldElement, right: FieldElement): FieldElement {
  return F.sub(F.add(left, right), F.mul(2n, F.mul(left, right)))
}

function nibbleFromBits (
  bits: FieldElement[],
  nibble: number
): FieldElement {
  let out = 0n
  for (let bit = 0; bit < 4; bit++) {
    out = F.add(out, F.mul(bits[nibble * 4 + bit], BigInt(1 << bit)))
  }
  return out
}

function padTuple (values: FieldElement[]): FieldElement[] {
  const out = zeroTuple()
  for (let i = 0; i < values.length; i++) out[i] = F.normalize(values[i])
  return out
}

function zeroTuple (): FieldElement[] {
  return new Array<FieldElement>(LOG_LOOKUP_TUPLE_ARITY).fill(0n)
}

function writeTuple (
  row: FieldElement[],
  offset: number,
  values: FieldElement[]
): void {
  for (let i = 0; i < LOG_LOOKUP_TUPLE_ARITY; i++) {
    row[offset + i] = F.normalize(values[i] ?? 0n)
  }
}

function deriveLookupBatchedChallenges (
  publicInputDigest: number[]
): LookupBatchedChallenges {
  const transcript = new FiatShamirTranscript(
    `${METHOD2_LOOKUP_BATCHED_HMAC_SHA256_TRANSCRIPT_DOMAIN}:lookup`
  )
  transcript.absorb('public-input', publicInputDigest)
  return {
    alphaPowers0: challengePowers(nonZeroChallenge(transcript, 'alpha-0')),
    alphaPowers1: challengePowers(nonZeroChallenge(transcript, 'alpha-1')),
    compactPowers0: challengePowersOfLength(
      nonZeroChallenge(transcript, 'compact-alpha-0'),
      METHOD2_NARROW_HMAC_CORE_LAYOUT.width
    ),
    compactPowers1: challengePowersOfLength(
      nonZeroChallenge(transcript, 'compact-alpha-1'),
      METHOD2_NARROW_HMAC_CORE_LAYOUT.width
    ),
    beta0: nonZeroChallenge(transcript, 'beta-0'),
    beta1: nonZeroChallenge(transcript, 'beta-1')
  }
}

function challengePowers (alpha: FieldElement): FieldElement[] {
  return challengePowersOfLength(alpha, LOG_LOOKUP_TUPLE_ARITY)
}

function challengePowersOfLength (
  alpha: FieldElement,
  length: number
): FieldElement[] {
  const powers = new Array<FieldElement>(length)
  let power = F.normalize(alpha)
  for (let i = 0; i < powers.length; i++) {
    powers[i] = power
    power = F.mul(power, alpha)
  }
  return powers
}

function nonZeroChallenge (
  transcript: FiatShamirTranscript,
  label: string
): FieldElement {
  for (let i = 0; i < 16; i++) {
    const value = transcript.challengeFieldElement(`${label}-${i}`)
    if (value !== 0n) return value
  }
  throw new Error('Lookup-batched HMAC-SHA256 could not derive non-zero challenge')
}

const KIND_VALUES = [
  LOG_LOOKUP_ROW_KIND.inactive,
  LOG_LOOKUP_ROW_KIND.request,
  LOG_LOOKUP_ROW_KIND.supply
]

function kindDomainConstraint (kind: FieldElement): FieldElement {
  let out = 1n
  for (const value of KIND_VALUES) out = F.mul(out, F.sub(kind, value))
  return out
}

function kindSelector (
  kind: FieldElement,
  target: FieldElement
): FieldElement {
  let numerator = 1n
  let denominator = 1n
  for (const value of KIND_VALUES) {
    if (value === target) continue
    numerator = F.mul(numerator, F.sub(kind, value))
    denominator = F.mul(denominator, F.sub(target, value))
  }
  return F.mul(numerator, F.inv(denominator))
}

function isCompactRoundRow (row: number): boolean {
  return row % BLOCK_STRIDE < SHA_ROUNDS
}

function isCompactRequestRow (
  row: number,
  compactActiveRows: number
): boolean {
  return row < compactActiveRows && isCompactRoundRow(row)
}

function compactChunkRow (
  compactRow: number,
  chunk: number
): number {
  return compactRow * LOOKUP_CHUNKS_PER_COMPACT_ROW + chunk
}

function compactChunkRows (
  publicInput: Method2LookupBatchedHmacSha256PublicInput
): number {
  return publicInput.compactActiveRows * LOOKUP_CHUNKS_PER_COMPACT_ROW
}

function compressedCompactDifference (
  current: FieldElement[],
  next: FieldElement[],
  powers: FieldElement[]
): FieldElement {
  let out = 0n
  for (let i = 0; i < METHOD2_NARROW_HMAC_CORE_LAYOUT.width; i++) {
    out = F.add(out, F.mul(F.sub(next[i], current[i]), powers[i]))
  }
  return out
}

function tupleKey (tag: FieldElement, values: FieldElement[]): string {
  return `${F.normalize(tag).toString()}:${
    values.map(value => F.normalize(value).toString()).join(',')
  }`
}

function gated (
  selector: FieldElement,
  constraints: FieldElement[]
): FieldElement[] {
  return constraints.map(constraint => F.mul(selector, constraint))
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
  if (left.length !== right.length) return false
  let diff = 0
  for (let i = 0; i < left.length; i++) diff |= left[i] ^ right[i]
  return diff === 0
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}

function isPowerOfTwo (value: number): boolean {
  return Number.isSafeInteger(value) && value > 0 && (value & (value - 1)) === 0
}
