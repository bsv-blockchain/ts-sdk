import { sha256 } from '../../../primitives/Hash.js'
import { Writer } from '../../../primitives/utils.js'
import { AirDefinition, assertAirTrace } from './Air.js'
import {
  F,
  FieldElement,
  assertPowerOfTwo,
  batchInvertFieldElements,
  getPowerOfTwoRootOfUnity
} from './Field.js'
import {
  FriProof,
  parseFriProof,
  proveFriTyped,
  serializeFriProof,
  verifyFri
} from './Fri.js'
import {
  MerkleHash,
  MerklePathItem,
  MerkleTree,
  buildMerkleTreeFromLeafFactory,
  openMerklePath
} from './Merkle.js'
import { FiatShamirTranscript } from './Transcript.js'
import {
  TraceCommitment,
  TraceRowOpening,
  commitTraceLde,
  openTraceRow,
  traceCommitmentLdeRow,
  verifyTraceRowOpening,
  writeTraceCommitmentLdeRow
} from './Trace.js'
import {
  TypedFieldColumn,
  typedFieldColumn,
  typedFieldElement,
  typedFieldColumnValue,
  typedFieldElementBytes
} from './TypedField.js'
import { typedCosetLowDegreeExtend } from './TypedPolynomial.js'
import {
  StarkProgressCallback,
  emitStarkProgress,
  shouldEmitProgress,
  withStarkProgressContext
} from './Progress.js'

export const STARK_TRANSCRIPT_DOMAIN = 'BRC69_STARK_CORE_V1_AIR'
export const STARK_DEFAULT_BLOWUP_FACTOR = 16
export const STARK_DEFAULT_NUM_QUERIES = 48
export const STARK_DEFAULT_MAX_REMAINDER_SIZE = 16
export const STARK_DEFAULT_MASK_DEGREE = 2
export const STARK_DEFAULT_COSET_OFFSET = 7n
export const STARK_MAX_TRACE_WIDTH = 65536

export interface StarkProverOptions {
  blowupFactor?: number
  numQueries?: number
  maxRemainderSize?: number
  maskDegree?: number
  cosetOffset?: FieldElement
  traceDegreeBound?: number
  compositionDegreeBound?: number
  publicInputDigest?: number[]
  transcriptDomain?: string
  transcriptContext?: number[]
  maskSeed?: number[]
  progress?: StarkProgressCallback
}

export interface StarkVerifierOptions {
  blowupFactor?: number
  numQueries?: number
  maxRemainderSize?: number
  maskDegree?: number
  cosetOffset?: FieldElement
  traceDegreeBound?: number
  compositionDegreeBound?: number
  publicInputDigest?: number[]
  transcriptDomain?: string
  transcriptContext?: number[]
}

export interface StarkProof {
  traceLength: number
  traceWidth: number
  blowupFactor: number
  numQueries: number
  maxRemainderSize: number
  maskDegree: number
  traceDegreeBound: number
  compositionDegreeBound: number
  cosetOffset: FieldElement
  publicInputDigest: number[]
  traceRoot: MerkleHash
  traceCombinationRoot: MerkleHash
  compositionRoot: MerkleHash
  traceLowDegreeOpenings: TraceRowOpening[]
  traceOpenings: TraceRowOpening[]
  nextTraceOpenings: TraceRowOpening[]
  compositionOpenings: TraceRowOpening[]
  traceFriProof: FriProof
  friProof: FriProof
}

export interface StarkProofDegreeBounds {
  traceDegreeBound: number
  compositionDegreeBound: number
}

export interface StarkDiagnostic {
  ok: boolean
  stage: string
  detail?: string
  query?: number
  error?: string
}

interface ResolvedStarkOptions {
  blowupFactor: number
  numQueries: number
  maxRemainderSize: number
  maskDegree: number
  cosetOffset: FieldElement
  traceDegreeBound: number
  compositionDegreeBound: number
  publicInputDigest: number[]
  transcriptDomain: string
  transcriptContext?: number[]
}

export interface MultiTraceStarkSegmentInput {
  name: string
  air: AirDefinition
  traceRows: FieldElement[][]
  options?: StarkProverOptions
}

export interface MultiTraceStarkSegmentVerifierInput {
  name: string
  air: AirDefinition
  options?: StarkVerifierOptions
}

export interface MultiTraceStarkSegmentProof {
  name: string
  proof: StarkProof
}

export interface MultiTraceStarkProof {
  transcriptDomain: string
  contextDigest: number[]
  segments: MultiTraceStarkSegmentProof[]
  crossProofs?: MultiTraceStarkCrossProof[]
  constantColumnProofs?: MultiTraceStarkConstantColumnProof[]
}

export interface MultiTraceStarkDiagnostic {
  ok: boolean
  stage: string
  detail?: string
  segment?: string
  constraint?: string
  link?: string
  error?: string
}

export interface MultiTraceCrossTraceRef {
  alias: string
  segment: string
  shift?: number
}

export interface MultiTraceCrossConstraintInput {
  name: string
  refs: MultiTraceCrossTraceRef[]
  degreeBound?: number
  evaluate: (input: {
    rows: Record<string, FieldElement[]>
    x: FieldElement
    ldeIndex: number
    traceLength: number
    blowupFactor: number
  }) => FieldElement[]
}

export interface MultiTraceConstantColumnRef {
  segment: string
  column: number
}

export interface MultiTraceConstantColumnLinkInput {
  name: string
  left: MultiTraceConstantColumnRef
  right: MultiTraceConstantColumnRef
  numQueries?: number
}

export interface MultiTraceStarkCrossOpening {
  alias: string
  opening: TraceRowOpening
}

export interface MultiTraceStarkCrossQueryOpenings {
  composition: TraceRowOpening
  traces: MultiTraceStarkCrossOpening[]
}

export interface MultiTraceStarkCrossProof {
  name: string
  compositionRoot: MerkleHash
  friProof: FriProof
  openings: MultiTraceStarkCrossQueryOpenings[]
}

export interface MultiTraceStarkConstantColumnQuery {
  left: TraceRowOpening
  right: TraceRowOpening
}

export interface MultiTraceStarkConstantColumnProof {
  name: string
  queries: MultiTraceStarkConstantColumnQuery[]
}

interface CompositionOracle {
  values?: FieldElement[]
  typedValues?: TypedFieldColumn
  tree: MerkleTree
}

interface TraceCombinationOracle {
  values?: FieldElement[]
  typedValues?: TypedFieldColumn
  tree: MerkleTree
}

interface CompositionContext {
  boundaryColumns: Array<{
    column: number
    maskLdeValues: TypedFieldColumn
    valueLdeValues: TypedFieldColumn
  }>
}

const COMPOSITION_CONTEXT_CACHE_LIMIT = 32
const COMPOSITION_CONTEXT_CACHE = new Map<string, CompositionContext>()

export function proveStark (
  air: AirDefinition,
  traceRows: FieldElement[][],
  options: StarkProverOptions = {}
): StarkProof {
  const start = Date.now()
  emitStarkProgress(options.progress, {
    phase: 'stark.prove',
    status: 'start',
    traceLength: traceRows.length,
    traceWidth: air.traceWidth
  })
  assertAirTrace(air, traceRows)
  const resolved = resolveProverOptions(air, traceRows.length, options)
  validateStarkParameters(traceRows.length, air.traceWidth, resolved)
  assertCosetDisjoint(traceRows.length, resolved.cosetOffset)

  const traceCommitment = commitTraceLde(traceRows, {
    blowupFactor: resolved.blowupFactor,
    cosetOffset: resolved.cosetOffset,
    maskCoefficients: makeTraceMasks(
      air.traceWidth,
      resolved.maskDegree,
      options.maskSeed,
      publicBoundaryColumnSet(air)
    ),
    progress: options.progress
  })
  const proof = proveCommittedStark(air, traceCommitment, resolved, options.progress)
  emitStarkProgress(options.progress, {
    phase: 'stark.prove',
    status: 'end',
    traceLength: traceRows.length,
    traceWidth: air.traceWidth,
    elapsedMs: Date.now() - start
  })
  return proof
}

function proveCommittedStark (
  air: AirDefinition,
  traceCommitment: TraceCommitment,
  resolved: ResolvedStarkOptions,
  progress?: StarkProgressCallback
): StarkProof {
  const start = Date.now()
  emitStarkProgress(progress, {
    phase: 'stark.committed-prove',
    status: 'start',
    traceLength: traceCommitment.traceLength,
    traceWidth: air.traceWidth,
    ldeSize: traceCommitment.ldeSize
  })
  const transcript = createStarkTranscript(
    traceCommitment.traceLength,
    air.traceWidth,
    resolved,
    traceCommitment.tree.root
  )
  const traceCombinationAlpha = transcript.challengeFieldElement('stark-trace-combination-alpha')
  const traceCombinationStart = Date.now()
  emitStarkProgress(progress, {
    phase: 'stark.trace-combination',
    status: 'start',
    ldeSize: traceCommitment.ldeSize
  })
  const traceCombination = commitTraceCombinationOracle(
    traceCommitment,
    traceCombinationAlpha,
    progress
  )
  emitStarkProgress(progress, {
    phase: 'stark.trace-combination',
    status: 'end',
    ldeSize: traceCommitment.ldeSize,
    elapsedMs: Date.now() - traceCombinationStart
  })
  transcript.absorb('stark-trace-combination-root', traceCombination.tree.root)
  const compositionAlpha = transcript.challengeFieldElement('stark-composition-alpha')
  const contextStart = Date.now()
  emitStarkProgress(progress, {
    phase: 'stark.composition-context',
    status: 'start',
    traceLength: traceCommitment.traceLength,
    ldeSize: traceCommitment.ldeSize
  })
  const compositionContext = buildCompositionContext(
    air,
    traceCommitment.traceLength,
    traceCommitment.ldeSize,
    resolved.cosetOffset,
    progress,
    traceCommitment
  )
  emitStarkProgress(progress, {
    phase: 'stark.composition-context',
    status: 'end',
    traceLength: traceCommitment.traceLength,
    ldeSize: traceCommitment.ldeSize,
    elapsedMs: Date.now() - contextStart
  })
  const compositionStart = Date.now()
  emitStarkProgress(progress, {
    phase: 'stark.composition-oracle',
    status: 'start',
    ldeSize: traceCommitment.ldeSize
  })
  const composition = commitCompositionOracle(
    air,
    traceCommitment,
    compositionAlpha,
    compositionContext,
    progress
  )
  emitStarkProgress(progress, {
    phase: 'stark.composition-oracle',
    status: 'end',
    ldeSize: traceCommitment.ldeSize,
    elapsedMs: Date.now() - compositionStart
  })

  emitStarkProgress(progress, {
    phase: 'stark.trace-fri',
    status: 'start',
    ldeSize: oracleLength(traceCombination)
  })
  const traceFriProof = proveFriTyped(oracleTypedValues(traceCombination), {
    degreeBound: resolved.traceDegreeBound,
    numQueries: resolved.numQueries,
    maxRemainderSize: resolved.maxRemainderSize,
    domainOffset: resolved.cosetOffset,
    transcriptDomain: `${resolved.transcriptDomain}:trace-fri`,
    transcriptContext: resolved.transcriptContext,
    progress
  })
  emitStarkProgress(progress, {
    phase: 'stark.trace-fri',
    status: 'end',
    ldeSize: oracleLength(traceCombination)
  })

  emitStarkProgress(progress, {
    phase: 'stark.composition-fri',
    status: 'start',
    ldeSize: oracleLength(composition)
  })
  const friProof = proveFriTyped(oracleTypedValues(composition), {
    degreeBound: resolved.compositionDegreeBound,
    numQueries: resolved.numQueries,
    maxRemainderSize: resolved.maxRemainderSize,
    domainOffset: resolved.cosetOffset,
    transcriptDomain: `${resolved.transcriptDomain}:fri`,
    transcriptContext: resolved.transcriptContext,
    progress
  })
  emitStarkProgress(progress, {
    phase: 'stark.composition-fri',
    status: 'end',
    ldeSize: oracleLength(composition)
  })

  const openingsStart = Date.now()
  emitStarkProgress(progress, {
    phase: 'stark.openings',
    status: 'start',
    count: traceFriProof.queries.length + friProof.queries.length,
    total: traceFriProof.queries.length + friProof.queries.length
  })
  const traceOpenings: TraceRowOpening[] = []
  const nextTraceOpenings: TraceRowOpening[] = []
  const compositionOpenings: TraceRowOpening[] = []
  const traceLowDegreeOpenings: TraceRowOpening[] = []
  for (const query of traceFriProof.queries) {
    const firstLayer = query.layers[0]
    if (firstLayer === undefined) {
      throw new Error('Trace FRI query is missing its first layer')
    }
    traceLowDegreeOpenings.push(openTraceRow(
      traceCommitment,
      firstLayer.leftIndex
    ))
    traceLowDegreeOpenings.push(openTraceRow(
      traceCommitment,
      firstLayer.rightIndex
    ))
  }
  for (const query of friProof.queries) {
    const index = query.initialIndex
    traceOpenings.push(openTraceRow(traceCommitment, index))
    nextTraceOpenings.push(openTraceRow(
      traceCommitment,
      (index + resolved.blowupFactor) % traceCommitment.ldeSize
    ))
    compositionOpenings.push(openCompositionRow(composition, index))
  }
  emitStarkProgress(progress, {
    phase: 'stark.openings',
    status: 'end',
    count: traceLowDegreeOpenings.length +
      traceOpenings.length +
      nextTraceOpenings.length +
      compositionOpenings.length,
    elapsedMs: Date.now() - openingsStart
  })

  const proof = {
    traceLength: traceCommitment.traceLength,
    traceWidth: air.traceWidth,
    blowupFactor: resolved.blowupFactor,
    numQueries: resolved.numQueries,
    maxRemainderSize: resolved.maxRemainderSize,
    maskDegree: resolved.maskDegree,
    traceDegreeBound: resolved.traceDegreeBound,
    compositionDegreeBound: resolved.compositionDegreeBound,
    cosetOffset: resolved.cosetOffset,
    publicInputDigest: resolved.publicInputDigest,
    traceRoot: traceCommitment.tree.root,
    traceCombinationRoot: traceCombination.tree.root,
    compositionRoot: composition.tree.root,
    traceLowDegreeOpenings,
    traceOpenings,
    nextTraceOpenings,
    compositionOpenings,
    traceFriProof,
    friProof
  }
  emitStarkProgress(progress, {
    phase: 'stark.committed-prove',
    status: 'end',
    traceLength: traceCommitment.traceLength,
    traceWidth: air.traceWidth,
    ldeSize: traceCommitment.ldeSize,
    elapsedMs: Date.now() - start
  })
  return proof
}

export function proveMultiTraceStark (
  segments: MultiTraceStarkSegmentInput[],
  options: StarkProverOptions = {},
  crossConstraints: MultiTraceCrossConstraintInput[] = [],
  constantLinks: MultiTraceConstantColumnLinkInput[] = []
): MultiTraceStarkProof {
  const start = Date.now()
  validateMultiTraceSegmentNames(segments.map(segment => segment.name))
  validateMultiTraceCrossConstraints(crossConstraints)
  validateMultiTraceConstantLinks(constantLinks)
  const transcriptDomain = options.transcriptDomain ?? STARK_TRANSCRIPT_DOMAIN
  emitStarkProgress(options.progress, {
    phase: 'multi-trace.prove',
    status: 'start',
    count: segments.length,
    total: segments.length
  })
  const prepared: Array<{
    name: string
    air: AirDefinition
    traceRows: FieldElement[][]
    segmentOptions: StarkProverOptions
    prepareStart: number
    commitment: TraceCommitment
    resolved: ResolvedStarkOptions
  }> = []
  for (const segment of segments) {
    const segmentProgress = withStarkProgressContext(options.progress, {
      segment: segment.name
    })
    const prepareStart = Date.now()
    emitStarkProgress(segmentProgress, {
      phase: 'multi-trace.segment-prepare',
      status: 'start',
      traceLength: segment.traceRows.length,
      traceWidth: segment.air.traceWidth
    })
    assertAirTrace(segment.air, segment.traceRows)
    const segmentOptions = multiTraceSegmentProverOptions(
      transcriptDomain,
      segment,
      options
    )
    const resolved = resolveProverOptions(
      segment.air,
      segment.traceRows.length,
      segmentOptions
    )
    validateStarkParameters(segment.traceRows.length, segment.air.traceWidth, resolved)
    assertCosetDisjoint(segment.traceRows.length, resolved.cosetOffset)
    prepared.push({
      name: segment.name,
      air: segment.air,
      traceRows: segment.traceRows,
      segmentOptions,
      prepareStart,
      commitment: undefined as unknown as TraceCommitment,
      resolved
    })
  }
  const sharedMasks = makeMultiTraceMasks(
    prepared,
    constantLinks,
    options.maskSeed
  )
  for (const segment of prepared) {
    const segmentProgress = withStarkProgressContext(options.progress, {
      segment: segment.name
    })
    const commitment = commitTraceLde(segment.traceRows, {
      blowupFactor: segment.resolved.blowupFactor,
      cosetOffset: segment.resolved.cosetOffset,
      maskCoefficients: sharedMasks.get(segment.name),
      progress: segmentProgress
    })
    segment.commitment = commitment
    emitStarkProgress(segmentProgress, {
      phase: 'multi-trace.segment-prepare',
      status: 'end',
      traceLength: segment.traceRows.length,
      traceWidth: segment.air.traceWidth,
      elapsedMs: Date.now() - segment.prepareStart
    })
  }
  emitStarkProgress(options.progress, {
    phase: 'multi-trace.context-digest',
    status: 'start',
    count: prepared.length,
    total: prepared.length
  })
  const contextDigest = multiTraceContextDigest(transcriptDomain, prepared)
  emitStarkProgress(options.progress, {
    phase: 'multi-trace.context-digest',
    status: 'end',
    count: prepared.length,
    total: prepared.length
  })
  const crossProofs = crossConstraints.map(constraint => {
    const crossProgress = withStarkProgressContext(options.progress, {
      crossConstraint: constraint.name
    })
    return proveMultiTraceCrossConstraint(
      constraint,
      prepared,
      transcriptDomain,
      contextDigest,
      crossProgress
    )
  })
  const constantColumnProofs = constantLinks.map(link =>
    proveMultiTraceConstantColumnLink(
      link,
      prepared,
      transcriptDomain,
      contextDigest
    )
  )
  const proofSegments: MultiTraceStarkSegmentProof[] = prepared.map(segment => {
    const segmentProgress = withStarkProgressContext(options.progress, {
      segment: segment.name
    })
    return {
      name: segment.name,
      proof: proveCommittedStark(segment.air, segment.commitment, {
        ...segment.resolved,
        transcriptContext: contextDigest
      }, segmentProgress)
    }
  })
  const proof = {
    transcriptDomain,
    contextDigest,
    segments: proofSegments,
    crossProofs,
    constantColumnProofs
  }
  emitStarkProgress(options.progress, {
    phase: 'multi-trace.prove',
    status: 'end',
    count: segments.length,
    total: segments.length,
    elapsedMs: Date.now() - start
  })
  return proof
}

export function verifyMultiTraceStark (
  segments: MultiTraceStarkSegmentVerifierInput[],
  proof: MultiTraceStarkProof,
  options: StarkVerifierOptions = {},
  crossConstraints: MultiTraceCrossConstraintInput[] = [],
  constantLinks: MultiTraceConstantColumnLinkInput[] = []
): boolean {
  try {
    validateMultiTraceSegmentNames(segments.map(segment => segment.name))
    validateMultiTraceSegmentNames(proof.segments.map(segment => segment.name))
    validateMultiTraceCrossConstraints(crossConstraints)
    validateMultiTraceConstantLinks(constantLinks)
    const transcriptDomain = options.transcriptDomain ?? proof.transcriptDomain
    if (proof.transcriptDomain !== transcriptDomain) return false
    const prepared = segments.map(segment => {
      const segmentProof = proof.segments.find(item => item.name === segment.name)
      if (segmentProof === undefined) {
        throw new Error('multi-trace STARK proof segment missing')
      }
      const resolved = resolveVerifierOptions(
        segment.air,
        segmentProof.proof.traceLength,
        multiTraceSegmentVerifierOptions(
          transcriptDomain,
          segment,
          options,
          segmentProof.proof
        )
      )
      return {
        name: segment.name,
        air: segment.air,
        proof: segmentProof.proof,
        resolved
      }
    })
    const contextDigest = multiTraceContextDigest(transcriptDomain, prepared.map(segment => ({
      name: segment.name,
      air: segment.air,
      commitment: {
        traceLength: segment.proof.traceLength,
        traceWidth: segment.proof.traceWidth,
        ldeSize: segment.proof.traceLength * segment.proof.blowupFactor,
        blowupFactor: segment.proof.blowupFactor,
        cosetOffset: segment.proof.cosetOffset,
        columnCoefficients: [],
        ldeColumns: [],
        tree: {
          root: segment.proof.traceRoot,
          levels: [[segment.proof.traceRoot]]
        }
      },
      resolved: segment.resolved
    })))
    if (!hashesEqual(contextDigest, proof.contextDigest)) return false
    const crossProofs = proof.crossProofs ?? []
    if (crossProofs.length !== crossConstraints.length) return false
    for (const constraint of crossConstraints) {
      const crossProof = crossProofs.find(item => item.name === constraint.name)
      if (crossProof === undefined) return false
      if (!verifyMultiTraceCrossConstraint(
        constraint,
        prepared,
        crossProof,
        transcriptDomain,
        contextDigest
      )) {
        return false
      }
    }
    const constantColumnProofs = proof.constantColumnProofs ?? []
    if (constantColumnProofs.length !== constantLinks.length) return false
    for (const link of constantLinks) {
      const linkProof = constantColumnProofs.find(item => item.name === link.name)
      if (linkProof === undefined) return false
      if (!verifyMultiTraceConstantColumnLink(
        link,
        prepared,
        linkProof,
        transcriptDomain,
        contextDigest
      )) {
        return false
      }
    }
    for (const segment of prepared) {
      if (!verifyStark(segment.air, segment.proof, {
        ...segment.resolved,
        transcriptContext: contextDigest
      })) {
        return false
      }
    }
    return true
  } catch {
    return false
  }
}

export function diagnoseMultiTraceStark (
  segments: MultiTraceStarkSegmentVerifierInput[],
  proof: MultiTraceStarkProof,
  options: StarkVerifierOptions = {},
  crossConstraints: MultiTraceCrossConstraintInput[] = [],
  constantLinks: MultiTraceConstantColumnLinkInput[] = []
): MultiTraceStarkDiagnostic {
  try {
    validateMultiTraceSegmentNames(segments.map(segment => segment.name))
    validateMultiTraceSegmentNames(proof.segments.map(segment => segment.name))
    validateMultiTraceCrossConstraints(crossConstraints)
    validateMultiTraceConstantLinks(constantLinks)
    const transcriptDomain = options.transcriptDomain ?? proof.transcriptDomain
    if (proof.transcriptDomain !== transcriptDomain) {
      return {
        ok: false,
        stage: 'transcript-domain',
        detail: `proof=${proof.transcriptDomain} expected=${transcriptDomain}`
      }
    }
    const prepared = segments.map(segment => {
      const segmentProof = proof.segments.find(item => item.name === segment.name)
      if (segmentProof === undefined) {
        throw new Error(`multi-trace STARK proof segment missing: ${segment.name}`)
      }
      const resolved = resolveVerifierOptions(
        segment.air,
        segmentProof.proof.traceLength,
        multiTraceSegmentVerifierOptions(
          transcriptDomain,
          segment,
          options,
          segmentProof.proof
        )
      )
      return {
        name: segment.name,
        air: segment.air,
        proof: segmentProof.proof,
        resolved
      }
    })
    const contextDigest = multiTraceContextDigest(transcriptDomain, prepared.map(segment => ({
      name: segment.name,
      air: segment.air,
      commitment: {
        traceLength: segment.proof.traceLength,
        traceWidth: segment.proof.traceWidth,
        ldeSize: segment.proof.traceLength * segment.proof.blowupFactor,
        blowupFactor: segment.proof.blowupFactor,
        cosetOffset: segment.proof.cosetOffset,
        columnCoefficients: [],
        ldeColumns: [],
        tree: {
          root: segment.proof.traceRoot,
          levels: [[segment.proof.traceRoot]]
        }
      },
      resolved: segment.resolved
    })))
    if (!hashesEqual(contextDigest, proof.contextDigest)) {
      return {
        ok: false,
        stage: 'context-digest',
        detail: 'recomputed multi-trace context digest does not match proof'
      }
    }
    const crossProofs = proof.crossProofs ?? []
    if (crossProofs.length !== crossConstraints.length) {
      return {
        ok: false,
        stage: 'cross-proof-count',
        detail: `proof=${crossProofs.length} expected=${crossConstraints.length}`
      }
    }
    for (const constraint of crossConstraints) {
      const crossProof = crossProofs.find(item => item.name === constraint.name)
      if (crossProof === undefined) {
        return {
          ok: false,
          stage: 'cross-proof-missing',
          constraint: constraint.name
        }
      }
      if (!verifyMultiTraceCrossConstraint(
        constraint,
        prepared,
        crossProof,
        transcriptDomain,
        contextDigest
      )) {
        return {
          ok: false,
          stage: 'cross-proof',
          constraint: constraint.name
        }
      }
    }
    const constantColumnProofs = proof.constantColumnProofs ?? []
    if (constantColumnProofs.length !== constantLinks.length) {
      return {
        ok: false,
        stage: 'constant-link-count',
        detail: `proof=${constantColumnProofs.length} expected=${constantLinks.length}`
      }
    }
    for (const link of constantLinks) {
      const linkProof = constantColumnProofs.find(item => item.name === link.name)
      if (linkProof === undefined) {
        return {
          ok: false,
          stage: 'constant-link-missing',
          link: link.name
        }
      }
      if (!verifyMultiTraceConstantColumnLink(
        link,
        prepared,
        linkProof,
        transcriptDomain,
        contextDigest
      )) {
        return {
          ok: false,
          stage: 'constant-link',
          link: link.name
        }
      }
    }
    for (const segment of prepared) {
      const segmentDiagnostic = diagnoseStark(segment.air, segment.proof, {
        ...segment.resolved,
        transcriptContext: contextDigest
      })
      if (!segmentDiagnostic.ok) {
        return {
          ok: false,
          stage: 'segment-proof',
          segment: segment.name,
          detail: segmentDiagnostic.stage
        }
      }
    }
    return { ok: true, stage: 'ok' }
  } catch (err) {
    return {
      ok: false,
      stage: 'exception',
      error: err instanceof Error ? err.message : String(err)
    }
  }
}

export function verifyStark (
  air: AirDefinition,
  proof: StarkProof,
  options: StarkVerifierOptions = {}
): boolean {
  try {
    validateStarkProofShape(proof)
    const resolved = resolveVerifierOptions(air, proof.traceLength, options)
    validateStarkParameters(proof.traceLength, air.traceWidth, resolved)
    if (
      proof.traceWidth !== air.traceWidth ||
      proof.blowupFactor !== resolved.blowupFactor ||
      proof.numQueries !== resolved.numQueries ||
      proof.maxRemainderSize !== resolved.maxRemainderSize ||
      proof.maskDegree !== resolved.maskDegree ||
      proof.traceDegreeBound !== resolved.traceDegreeBound ||
      proof.compositionDegreeBound !== resolved.compositionDegreeBound ||
      proof.cosetOffset !== resolved.cosetOffset ||
      !hashesEqual(proof.publicInputDigest, resolved.publicInputDigest)
    ) {
      return false
    }
    assertCosetDisjoint(proof.traceLength, proof.cosetOffset)

    const ldeSize = proof.traceLength * proof.blowupFactor
    const transcript = createStarkTranscript(
      proof.traceLength,
      proof.traceWidth,
      resolved,
      proof.traceRoot
    )
    const traceCombinationAlpha = transcript.challengeFieldElement('stark-trace-combination-alpha')
    transcript.absorb('stark-trace-combination-root', proof.traceCombinationRoot)
    const compositionAlpha = transcript.challengeFieldElement('stark-composition-alpha')

    if (!verifyFri(proof.traceFriProof, {
      expectedRoot: proof.traceCombinationRoot,
      domainSize: ldeSize,
      degreeBound: proof.traceDegreeBound,
      numQueries: proof.numQueries,
      maxRemainderSize: proof.maxRemainderSize,
      domainOffset: proof.cosetOffset,
      transcriptDomain: `${resolved.transcriptDomain}:trace-fri`,
      transcriptContext: resolved.transcriptContext
    })) {
      return false
    }

    if (!verifyFri(proof.friProof, {
      expectedRoot: proof.compositionRoot,
      domainSize: ldeSize,
      degreeBound: proof.compositionDegreeBound,
      numQueries: proof.numQueries,
      maxRemainderSize: proof.maxRemainderSize,
      domainOffset: proof.cosetOffset,
      transcriptDomain: `${resolved.transcriptDomain}:fri`,
      transcriptContext: resolved.transcriptContext
    })) {
      return false
    }

    if (
      proof.traceLowDegreeOpenings.length !== proof.traceFriProof.queries.length * 2
    ) {
      return false
    }
    for (let i = 0; i < proof.traceFriProof.queries.length; i++) {
      const firstLayer = proof.traceFriProof.queries[i].layers[0]
      if (firstLayer === undefined) return false
      const leftOpening = proof.traceLowDegreeOpenings[i * 2]
      const rightOpening = proof.traceLowDegreeOpenings[i * 2 + 1]
      if (
        leftOpening.rowIndex !== firstLayer.leftIndex ||
        rightOpening.rowIndex !== firstLayer.rightIndex ||
        leftOpening.row.length !== proof.traceWidth ||
        rightOpening.row.length !== proof.traceWidth
      ) {
        return false
      }
      if (!verifyTraceRowOpening(proof.traceRoot, leftOpening, ldeSize)) {
        return false
      }
      if (!verifyTraceRowOpening(proof.traceRoot, rightOpening, ldeSize)) {
        return false
      }
      if (
        linearCombination(leftOpening.row, traceCombinationAlpha) !== firstLayer.leftValue ||
        linearCombination(rightOpening.row, traceCombinationAlpha) !== firstLayer.rightValue
      ) {
        return false
      }
    }

    if (
      proof.traceOpenings.length !== proof.friProof.queries.length ||
      proof.nextTraceOpenings.length !== proof.friProof.queries.length ||
      proof.compositionOpenings.length !== proof.friProof.queries.length
    ) {
      return false
    }

    const compositionContext = buildCompositionContext(
      air,
      proof.traceLength,
      ldeSize,
      proof.cosetOffset
    )
    for (let i = 0; i < proof.friProof.queries.length; i++) {
      const queryIndex = proof.friProof.queries[i].initialIndex
      const nextIndex = (queryIndex + proof.blowupFactor) % ldeSize
      const traceOpening = proof.traceOpenings[i]
      const nextOpening = proof.nextTraceOpenings[i]
      const compositionOpening = proof.compositionOpenings[i]
      if (
        traceOpening.rowIndex !== queryIndex ||
        nextOpening.rowIndex !== nextIndex ||
        compositionOpening.rowIndex !== queryIndex ||
        traceOpening.row.length !== proof.traceWidth ||
        nextOpening.row.length !== proof.traceWidth ||
        compositionOpening.row.length !== 1
      ) {
        return false
      }
      if (!verifyTraceRowOpening(proof.traceRoot, traceOpening, ldeSize)) {
        return false
      }
      if (!verifyTraceRowOpening(proof.traceRoot, nextOpening, ldeSize)) {
        return false
      }
      if (!verifyTraceRowOpening(
        proof.compositionRoot,
        compositionOpening,
        ldeSize
      )) {
        return false
      }
      const x = getLdePoint(ldeSize, proof.cosetOffset, queryIndex)
      const expected = evaluateCompositionAtPoint(
        air,
        traceOpening.row,
        nextOpening.row,
        x,
        queryIndex,
        queryIndex,
        proof.traceLength,
        compositionAlpha,
        compositionContext
      )
      if (compositionOpening.row[0] !== expected) {
        return false
      }
    }

    return true
  } catch {
    return false
  }
}

export function diagnoseStark (
  air: AirDefinition,
  proof: StarkProof,
  options: StarkVerifierOptions = {}
): StarkDiagnostic {
  try {
    validateStarkProofShape(proof)
    const resolved = resolveVerifierOptions(air, proof.traceLength, options)
    validateStarkParameters(proof.traceLength, air.traceWidth, resolved)
    const metadataChecks: Array<[string, boolean]> = [
      ['traceWidth', proof.traceWidth === air.traceWidth],
      ['blowupFactor', proof.blowupFactor === resolved.blowupFactor],
      ['numQueries', proof.numQueries === resolved.numQueries],
      ['maxRemainderSize', proof.maxRemainderSize === resolved.maxRemainderSize],
      ['maskDegree', proof.maskDegree === resolved.maskDegree],
      ['traceDegreeBound', proof.traceDegreeBound === resolved.traceDegreeBound],
      [
        'compositionDegreeBound',
        proof.compositionDegreeBound === resolved.compositionDegreeBound
      ],
      ['cosetOffset', proof.cosetOffset === resolved.cosetOffset],
      [
        'publicInputDigest',
        hashesEqual(proof.publicInputDigest, resolved.publicInputDigest)
      ]
    ]
    const failedMetadata = metadataChecks.find(([, ok]) => !ok)
    if (failedMetadata !== undefined) {
      return {
        ok: false,
        stage: 'metadata',
        detail: failedMetadata[0]
      }
    }
    assertCosetDisjoint(proof.traceLength, proof.cosetOffset)

    const ldeSize = proof.traceLength * proof.blowupFactor
    const transcript = createStarkTranscript(
      proof.traceLength,
      proof.traceWidth,
      resolved,
      proof.traceRoot
    )
    const traceCombinationAlpha = transcript.challengeFieldElement('stark-trace-combination-alpha')
    transcript.absorb('stark-trace-combination-root', proof.traceCombinationRoot)
    const compositionAlpha = transcript.challengeFieldElement('stark-composition-alpha')

    if (!verifyFri(proof.traceFriProof, {
      expectedRoot: proof.traceCombinationRoot,
      domainSize: ldeSize,
      degreeBound: proof.traceDegreeBound,
      numQueries: proof.numQueries,
      maxRemainderSize: proof.maxRemainderSize,
      domainOffset: proof.cosetOffset,
      transcriptDomain: `${resolved.transcriptDomain}:trace-fri`,
      transcriptContext: resolved.transcriptContext
    })) {
      return { ok: false, stage: 'trace-fri' }
    }

    if (!verifyFri(proof.friProof, {
      expectedRoot: proof.compositionRoot,
      domainSize: ldeSize,
      degreeBound: proof.compositionDegreeBound,
      numQueries: proof.numQueries,
      maxRemainderSize: proof.maxRemainderSize,
      domainOffset: proof.cosetOffset,
      transcriptDomain: `${resolved.transcriptDomain}:fri`,
      transcriptContext: resolved.transcriptContext
    })) {
      return { ok: false, stage: 'composition-fri' }
    }

    if (
      proof.traceLowDegreeOpenings.length !== proof.traceFriProof.queries.length * 2
    ) {
      return { ok: false, stage: 'trace-low-degree-opening-count' }
    }
    for (let i = 0; i < proof.traceFriProof.queries.length; i++) {
      const firstLayer = proof.traceFriProof.queries[i].layers[0]
      if (firstLayer === undefined) {
        return { ok: false, stage: 'trace-fri-query-layer', query: i }
      }
      const leftOpening = proof.traceLowDegreeOpenings[i * 2]
      const rightOpening = proof.traceLowDegreeOpenings[i * 2 + 1]
      if (
        leftOpening.rowIndex !== firstLayer.leftIndex ||
        rightOpening.rowIndex !== firstLayer.rightIndex ||
        leftOpening.row.length !== proof.traceWidth ||
        rightOpening.row.length !== proof.traceWidth
      ) {
        return { ok: false, stage: 'trace-low-degree-opening-shape', query: i }
      }
      if (!verifyTraceRowOpening(proof.traceRoot, leftOpening, ldeSize)) {
        return { ok: false, stage: 'trace-low-degree-left-opening', query: i }
      }
      if (!verifyTraceRowOpening(proof.traceRoot, rightOpening, ldeSize)) {
        return { ok: false, stage: 'trace-low-degree-right-opening', query: i }
      }
      if (
        linearCombination(leftOpening.row, traceCombinationAlpha) !== firstLayer.leftValue ||
        linearCombination(rightOpening.row, traceCombinationAlpha) !== firstLayer.rightValue
      ) {
        return { ok: false, stage: 'trace-combination-opening', query: i }
      }
    }

    if (
      proof.traceOpenings.length !== proof.friProof.queries.length ||
      proof.nextTraceOpenings.length !== proof.friProof.queries.length ||
      proof.compositionOpenings.length !== proof.friProof.queries.length
    ) {
      return { ok: false, stage: 'composition-opening-count' }
    }

    const compositionContext = buildCompositionContext(
      air,
      proof.traceLength,
      ldeSize,
      proof.cosetOffset
    )
    for (let i = 0; i < proof.friProof.queries.length; i++) {
      const queryIndex = proof.friProof.queries[i].initialIndex
      const nextIndex = (queryIndex + proof.blowupFactor) % ldeSize
      const traceOpening = proof.traceOpenings[i]
      const nextOpening = proof.nextTraceOpenings[i]
      const compositionOpening = proof.compositionOpenings[i]
      if (
        traceOpening.rowIndex !== queryIndex ||
        nextOpening.rowIndex !== nextIndex ||
        compositionOpening.rowIndex !== queryIndex ||
        traceOpening.row.length !== proof.traceWidth ||
        nextOpening.row.length !== proof.traceWidth ||
        compositionOpening.row.length !== 1
      ) {
        return { ok: false, stage: 'composition-opening-shape', query: i }
      }
      if (!verifyTraceRowOpening(proof.traceRoot, traceOpening, ldeSize)) {
        return { ok: false, stage: 'composition-trace-opening', query: i }
      }
      if (!verifyTraceRowOpening(proof.traceRoot, nextOpening, ldeSize)) {
        return { ok: false, stage: 'composition-next-trace-opening', query: i }
      }
      if (!verifyTraceRowOpening(
        proof.compositionRoot,
        compositionOpening,
        ldeSize
      )) {
        return { ok: false, stage: 'composition-oracle-opening', query: i }
      }
      const x = getLdePoint(ldeSize, proof.cosetOffset, queryIndex)
      const expected = evaluateCompositionAtPoint(
        air,
        traceOpening.row,
        nextOpening.row,
        x,
        queryIndex,
        queryIndex,
        proof.traceLength,
        compositionAlpha,
        compositionContext
      )
      if (compositionOpening.row[0] !== expected) {
        return {
          ok: false,
          stage: 'composition-evaluation',
          query: i
        }
      }
    }

    return { ok: true, stage: 'ok' }
  } catch (err) {
    return {
      ok: false,
      stage: 'exception',
      error: err instanceof Error ? err.message : String(err)
    }
  }
}

export function serializeStarkProof (proof: StarkProof): number[] {
  return serializeStarkProofInternal(proof, true)
}

export function serializeStarkProofWithoutDegreeBounds (
  proof: StarkProof
): number[] {
  return serializeStarkProofInternal(proof, false)
}

function serializeStarkProofInternal (
  proof: StarkProof,
  includeDegreeBounds: boolean
): number[] {
  validateStarkProofShape(proof)
  const writer = new Writer()
  const merkleHashes = starkMerklePathDictionary(proof)
  const merkleHashIndex = new Map(
    merkleHashes.map((hash, index) => [bytesKey(hash), index])
  )
  writer.writeVarIntNum(proof.traceLength)
  writer.writeVarIntNum(proof.traceWidth)
  writer.writeVarIntNum(proof.blowupFactor)
  writer.writeVarIntNum(proof.numQueries)
  writer.writeVarIntNum(proof.maxRemainderSize)
  writer.writeVarIntNum(proof.maskDegree)
  if (includeDegreeBounds) {
    writer.writeVarIntNum(proof.traceDegreeBound)
    writer.writeVarIntNum(proof.compositionDegreeBound)
  }
  writeField(writer, proof.cosetOffset)
  writeBytes(writer, proof.publicInputDigest)
  writeHash(writer, proof.traceRoot)
  writeHash(writer, proof.traceCombinationRoot)
  writeHash(writer, proof.compositionRoot)
  writeHashDictionary(writer, merkleHashes)
  writeCompactTraceOpenings(writer, proof.traceLowDegreeOpenings, merkleHashIndex)
  writeCompactTraceOpenings(writer, proof.traceOpenings, merkleHashIndex)
  writeCompactTraceOpenings(writer, proof.nextTraceOpenings, merkleHashIndex)
  writeCompactTraceOpenings(writer, proof.compositionOpenings, merkleHashIndex)
  const traceFriBytes = serializeFriProof(proof.traceFriProof)
  writer.writeVarIntNum(traceFriBytes.length)
  writer.write(traceFriBytes)
  const friBytes = serializeFriProof(proof.friProof)
  writer.writeVarIntNum(friBytes.length)
  writer.write(friBytes)
  return writer.toArray()
}

export function serializeMultiTraceStarkProof (
  proof: MultiTraceStarkProof
): number[] {
  const writer = new Writer()
  writeString(writer, proof.transcriptDomain)
  writeBytes(writer, proof.contextDigest)
  writer.writeVarIntNum(proof.segments.length)
  for (const segment of proof.segments) {
    writeString(writer, segment.name)
    const bytes = serializeStarkProof(segment.proof)
    writer.writeVarIntNum(bytes.length)
    writer.write(bytes)
  }
  writer.writeVarIntNum(proof.crossProofs?.length ?? 0)
  for (const crossProof of proof.crossProofs ?? []) {
    writeString(writer, crossProof.name)
    writeHash(writer, crossProof.compositionRoot)
    const friBytes = serializeFriProof(crossProof.friProof)
    writer.writeVarIntNum(friBytes.length)
    writer.write(friBytes)
    writer.writeVarIntNum(crossProof.openings.length)
    for (const opening of crossProof.openings) {
      writeTraceOpening(writer, opening.composition)
      writer.writeVarIntNum(opening.traces.length)
      for (const trace of opening.traces) {
        writeString(writer, trace.alias)
        writeTraceOpening(writer, trace.opening)
      }
    }
  }
  writer.writeVarIntNum(proof.constantColumnProofs?.length ?? 0)
  for (const constantProof of proof.constantColumnProofs ?? []) {
    writeString(writer, constantProof.name)
    writer.writeVarIntNum(constantProof.queries.length)
    for (const query of constantProof.queries) {
      writeTraceOpening(writer, query.left)
      writeTraceOpening(writer, query.right)
    }
  }
  return writer.toArray()
}

export function parseMultiTraceStarkProof (
  bytes: number[]
): MultiTraceStarkProof {
  const reader = new StarkBinaryReader(bytes)
  const transcriptDomain = readString(reader)
  const contextDigest = readBytes(reader)
  if (contextDigest.length !== 32) {
    throw new Error('multi-trace STARK context digest must be 32 bytes')
  }
  const segmentCount = reader.readVarIntNum()
  if (segmentCount > 64) throw new Error('Too many multi-trace STARK segments')
  const segments: MultiTraceStarkSegmentProof[] = []
  for (let i = 0; i < segmentCount; i++) {
    const name = readString(reader)
    const proofLength = reader.readVarIntNum()
    if (proofLength > 1024 * 1024 * 1024) {
      throw new Error('multi-trace STARK segment proof is too large')
    }
    segments.push({
      name,
      proof: parseStarkProof(reader.read(proofLength))
    })
  }
  const crossProofCount = reader.readVarIntNum()
  if (crossProofCount > 64) {
    throw new Error('Too many multi-trace STARK cross proofs')
  }
  const crossProofs: MultiTraceStarkCrossProof[] = []
  for (let i = 0; i < crossProofCount; i++) {
    const name = readString(reader)
    const compositionRoot = readHash(reader)
    const friLength = reader.readVarIntNum()
    if (friLength > 1024 * 1024 * 1024) {
      throw new Error('multi-trace STARK cross FRI proof is too large')
    }
    const friProof = parseFriProof(reader.read(friLength))
    const openingCount = reader.readVarIntNum()
    if (openingCount > 1048576) {
      throw new Error('Too many multi-trace STARK cross openings')
    }
    const openings: MultiTraceStarkCrossQueryOpenings[] = []
    for (let query = 0; query < openingCount; query++) {
      const composition = readTraceOpening(reader)
      const traceCount = reader.readVarIntNum()
      if (traceCount > 64) {
        throw new Error('Too many multi-trace STARK cross traces')
      }
      const traces: MultiTraceStarkCrossOpening[] = []
      for (let trace = 0; trace < traceCount; trace++) {
        traces.push({
          alias: readString(reader),
          opening: readTraceOpening(reader)
        })
      }
      openings.push({ composition, traces })
    }
    crossProofs.push({ name, compositionRoot, friProof, openings })
  }
  const constantColumnProofCount = reader.readVarIntNum()
  if (constantColumnProofCount > 64) {
    throw new Error('Too many multi-trace STARK constant-column proofs')
  }
  const constantColumnProofs: MultiTraceStarkConstantColumnProof[] = []
  for (let i = 0; i < constantColumnProofCount; i++) {
    const name = readString(reader)
    const queryCount = reader.readVarIntNum()
    if (queryCount > 1048576) {
      throw new Error('Too many multi-trace STARK constant-column queries')
    }
    const queries: MultiTraceStarkConstantColumnQuery[] = []
    for (let query = 0; query < queryCount; query++) {
      queries.push({
        left: readTraceOpening(reader),
        right: readTraceOpening(reader)
      })
    }
    constantColumnProofs.push({ name, queries })
  }
  if (!reader.eof()) {
    throw new Error('Unexpected trailing bytes in multi-trace STARK proof')
  }
  validateMultiTraceSegmentNames(segments.map(segment => segment.name))
  validateMultiTraceSegmentNames(crossProofs.map(proof => proof.name))
  validateMultiTraceSegmentNames(
    constantColumnProofs.map(proof => proof.name)
  )
  return {
    transcriptDomain,
    contextDigest,
    segments,
    crossProofs,
    constantColumnProofs
  }
}

export function parseStarkProof (bytes: number[]): StarkProof {
  return parseStarkProofInternal(bytes)
}

export function parseStarkProofWithDegreeBounds (
  bytes: number[],
  degreeBounds: StarkProofDegreeBounds
): StarkProof {
  return parseStarkProofInternal(bytes, degreeBounds)
}

function parseStarkProofInternal (
  bytes: number[],
  degreeBounds?: StarkProofDegreeBounds
): StarkProof {
  const reader = new StarkBinaryReader(bytes)
  const traceLength = reader.readVarIntNum()
  const traceWidth = reader.readVarIntNum()
  const blowupFactor = reader.readVarIntNum()
  const numQueries = reader.readVarIntNum()
  const maxRemainderSize = reader.readVarIntNum()
  const maskDegree = reader.readVarIntNum()
  const traceDegreeBound = degreeBounds === undefined
    ? reader.readVarIntNum()
    : degreeBounds.traceDegreeBound
  const compositionDegreeBound = degreeBounds === undefined
    ? reader.readVarIntNum()
    : degreeBounds.compositionDegreeBound
  const cosetOffset = readField(reader)
  const publicInputDigest = readBytes(reader)
  const traceRoot = readHash(reader)
  const traceCombinationRoot = readHash(reader)
  const compositionRoot = readHash(reader)
  const merkleHashes = readHashDictionary(reader)
  const traceLowDegreeOpenings = readCompactTraceOpenings(reader, merkleHashes)
  const traceOpenings = readCompactTraceOpenings(reader, merkleHashes)
  const nextTraceOpenings = readCompactTraceOpenings(reader, merkleHashes)
  const compositionOpenings = readCompactTraceOpenings(reader, merkleHashes)
  const traceFriLength = reader.readVarIntNum()
  const traceFriProof = parseFriProof(reader.read(traceFriLength))
  const friLength = reader.readVarIntNum()
  const friProof = parseFriProof(reader.read(friLength))
  if (!reader.eof()) {
    throw new Error('Unexpected trailing bytes in STARK proof')
  }
  const proof = {
    traceLength,
    traceWidth,
    blowupFactor,
    numQueries,
    maxRemainderSize,
    maskDegree,
    traceDegreeBound,
    compositionDegreeBound,
    cosetOffset,
    publicInputDigest,
    traceRoot,
    traceCombinationRoot,
    compositionRoot,
    traceLowDegreeOpenings,
    traceOpenings,
    nextTraceOpenings,
    compositionOpenings,
    traceFriProof,
    friProof
  }
  validateStarkProofShape(proof)
  return proof
}

function commitTraceCombinationOracle (
  traceCommitment: TraceCommitment,
  alpha: FieldElement,
  progress?: StarkProgressCallback
): TraceCombinationOracle {
  const typedValues = emptyTypedColumn(traceCommitment.ldeSize)
  for (let row = 0; row < traceCommitment.ldeSize; row++) {
    const value = traceCommitment.ldeRows === undefined
      ? linearCombinationTraceCommitmentRow(traceCommitment, row, alpha)
      : linearCombination(traceCommitment.ldeRows[row], alpha)
    writeTypedColumnValue(typedValues, row, value)
    if (shouldEmitProgress(row, traceCommitment.ldeSize)) {
      emitStarkProgress(progress, {
        phase: 'stark.trace-combination.rows',
        status: 'progress',
        row,
        count: row + 1,
        total: traceCommitment.ldeSize
      })
    }
  }
  const tree = buildMerkleTreeFromLeafFactory(
    traceCommitment.ldeSize,
    row => typedFieldElementBytes({
      lo: typedValues.lo[row],
      hi: typedValues.hi[row]
    }),
    { progress, phase: 'stark.trace-combination.merkle' }
  )
  return { typedValues, tree }
}

function commitCompositionOracle (
  air: AirDefinition,
  traceCommitment: TraceCommitment,
  alpha: FieldElement,
  context: CompositionContext,
  progress?: StarkProgressCallback
): CompositionOracle {
  const typedValues = emptyTypedColumn(traceCommitment.ldeSize)
  const denominators = new Array<FieldElement>(traceCommitment.ldeSize)
  const transitionNumerators = new Array<FieldElement>(traceCommitment.ldeSize)
  const ldeRoot = getPowerOfTwoRootOfUnity(traceCommitment.ldeSize)
  const traceRoot = getPowerOfTwoRootOfUnity(traceCommitment.traceLength)
  const lastPoint = F.inv(traceRoot)
  const xNStride = F.pow(ldeRoot, BigInt(traceCommitment.traceLength))
  let x = traceCommitment.cosetOffset
  let xN = F.pow(traceCommitment.cosetOffset, BigInt(traceCommitment.traceLength))
  for (let i = 0; i < traceCommitment.ldeSize; i++) {
    denominators[i] = F.sub(xN, 1n)
    transitionNumerators[i] = F.sub(x, lastPoint)
    x = F.mul(x, ldeRoot)
    xN = F.mul(xN, xNStride)
  }
  const denominatorInverses = batchInvertFieldElements(denominators)
  const currentScratch = traceCommitment.ldeRows === undefined
    ? new Array<FieldElement>(traceCommitment.traceWidth)
    : undefined
  const nextScratch = traceCommitment.ldeRows === undefined
    ? new Array<FieldElement>(traceCommitment.traceWidth)
    : undefined
  for (let i = 0; i < traceCommitment.ldeSize; i++) {
    const current = traceCommitment.ldeRows?.[i] ??
      writeTraceCommitmentLdeRow(
        traceCommitment,
        i,
        currentScratch as FieldElement[]
      )
    const nextIndex = (i + traceCommitment.blowupFactor) % traceCommitment.ldeSize
    const next = traceCommitment.ldeRows?.[nextIndex] ??
      writeTraceCommitmentLdeRow(
        traceCommitment,
        nextIndex,
        nextScratch as FieldElement[]
      )
    const value = evaluateCompositionAtPointWithInverses(
      air,
      current,
      next,
      i,
      i,
      alpha,
      context,
      F.mul(transitionNumerators[i], denominatorInverses[i]),
      denominatorInverses[i]
    )
    writeTypedColumnValue(typedValues, i, value)
    if (shouldEmitProgress(i, traceCommitment.ldeSize)) {
      emitStarkProgress(progress, {
        phase: 'stark.composition-oracle.rows',
        status: 'progress',
        row: i,
        count: i + 1,
        total: traceCommitment.ldeSize
      })
    }
  }
  const tree = buildMerkleTreeFromLeafFactory(
    traceCommitment.ldeSize,
    row => typedFieldElementBytes({
      lo: typedValues.lo[row],
      hi: typedValues.hi[row]
    }),
    { progress, phase: 'stark.composition-oracle.merkle' }
  )
  return { typedValues, tree }
}

function openCompositionRow (
  oracle: CompositionOracle,
  rowIndex: number
): TraceRowOpening {
  if (!Number.isSafeInteger(rowIndex) || rowIndex < 0 || rowIndex >= oracleLength(oracle)) {
    throw new Error('Composition row index out of bounds')
  }
  return {
    rowIndex,
    row: [oracleValue(oracle, rowIndex)],
    path: openMerklePath(oracle.tree, rowIndex)
  }
}

function evaluateCompositionAtPoint (
  air: AirDefinition,
  current: FieldElement[],
  next: FieldElement[],
  x: FieldElement,
  ldeIndex: number,
  step: number,
  traceLength: number,
  alpha: FieldElement,
  context: CompositionContext
): FieldElement {
  const transitionDenominator = transitionZerofierExceptLast(x, traceLength)
  const transitionDenominatorInv = F.inv(transitionDenominator)
  const boundaryDenominator = F.sub(F.pow(x, BigInt(traceLength)), 1n)
  if (boundaryDenominator === 0n) {
    throw new Error('Boundary denominator vanished on LDE domain')
  }
  return evaluateCompositionAtPointWithInverses(
    air,
    current,
    next,
    ldeIndex,
    step,
    alpha,
    context,
    transitionDenominatorInv,
    F.inv(boundaryDenominator)
  )
}

function evaluateCompositionAtPointWithInverses (
  air: AirDefinition,
  current: FieldElement[],
  next: FieldElement[],
  ldeIndex: number,
  step: number,
  alpha: FieldElement,
  context: CompositionContext,
  transitionDenominatorInv: FieldElement,
  boundaryDenominatorInv: FieldElement
): FieldElement {
  const transitionValues = air.evaluateTransition(current, next, step)
  let accumulator = 0n
  let alphaPower = 1n
  for (const value of transitionValues) {
    accumulator = F.add(
      accumulator,
      F.mul(
        alphaPower,
        F.mul(F.normalize(value), transitionDenominatorInv)
      )
    )
    alphaPower = F.mul(alphaPower, alpha)
  }

  if (context.boundaryColumns.length > 0) {
    for (const column of context.boundaryColumns) {
      const numerator = F.mul(
        typedFieldColumnValue(column.maskLdeValues, ldeIndex),
        F.sub(
          F.normalize(current[column.column]),
          typedFieldColumnValue(column.valueLdeValues, ldeIndex)
        )
      )
      accumulator = F.add(
        accumulator,
        F.mul(alphaPower, F.mul(numerator, boundaryDenominatorInv))
      )
      alphaPower = F.mul(alphaPower, alpha)
    }
  }

  return accumulator
}

function buildCompositionContext (
  air: AirDefinition,
  traceLength: number,
  ldeSize: number,
  cosetOffset: FieldElement,
  progress?: StarkProgressCallback,
  traceCommitment?: TraceCommitment
): CompositionContext {
  const cacheKey = compositionContextCacheKey(
    air,
    traceLength,
    ldeSize,
    cosetOffset
  )
  const cached = cacheKey === undefined
    ? undefined
    : COMPOSITION_CONTEXT_CACHE.get(cacheKey)
  if (cached !== undefined) return cached

  const blowupFactor = ldeSize / traceLength
  if (!Number.isSafeInteger(blowupFactor) || blowupFactor < 1) {
    throw new Error('Invalid LDE blowup factor')
  }
  const columns = new Map<number, {
    maskValues: FieldElement[]
    valueValues: FieldElement[]
    full: boolean
  }>()
  const getColumn = (column: number): {
    maskValues: FieldElement[]
    valueValues: FieldElement[]
    full: boolean
  } => {
    if (
      !Number.isSafeInteger(column) ||
      column < 0 ||
      column >= air.traceWidth
    ) {
      throw new Error('AIR boundary column out of bounds')
    }
    const existing = columns.get(column)
    if (existing !== undefined) return existing
    const created = {
      maskValues: new Array<FieldElement>(traceLength).fill(0n),
      valueValues: new Array<FieldElement>(traceLength).fill(0n),
      full: false
    }
    columns.set(column, created)
    return created
  }
  const setBoundary = (
    column: number,
    row: number,
    value: FieldElement
  ): void => {
    if (!Number.isSafeInteger(row) || row < 0 || row >= traceLength) {
      throw new Error('AIR boundary row out of bounds')
    }
    const boundaryColumn = getColumn(column)
    const normalized = F.normalize(value)
    if (
      boundaryColumn.maskValues[row] === 1n &&
      boundaryColumn.valueValues[row] !== normalized
    ) {
      throw new Error('AIR boundary constraint conflict')
    }
    boundaryColumn.maskValues[row] = 1n
    boundaryColumn.valueValues[row] = normalized
  }

  for (const column of air.fullBoundaryColumns ?? []) {
    if (column.values.length !== traceLength) {
      throw new Error('AIR full boundary column length mismatch')
    }
    const boundaryColumn = getColumn(column.column)
    for (let row = 0; row < traceLength; row++) {
      const normalized = F.normalize(column.values[row])
      if (
        boundaryColumn.maskValues[row] === 1n &&
        boundaryColumn.valueValues[row] !== normalized
      ) {
        throw new Error('AIR boundary constraint conflict')
      }
      boundaryColumn.maskValues[row] = 1n
      boundaryColumn.valueValues[row] = normalized
    }
    boundaryColumn.full = true
  }
  for (const constraint of air.boundaryConstraints) {
    setBoundary(constraint.column, constraint.row, constraint.value)
  }

  const entries = Array.from(columns.entries())
  const boundaryColumns = entries.map(([column, values], index) => {
    const committedFullBoundaryLde =
      values.full &&
      traceCommitment?.traceLength === traceLength &&
      traceCommitment.ldeSize === ldeSize &&
      traceCommitment.cosetOffset === F.normalize(cosetOffset)
        ? traceCommitment.typedLdeColumns?.[column]
        : undefined
    const result = {
      column,
      maskLdeValues: values.full
        ? constantTypedColumn(ldeSize, 1n)
        : typedCosetLowDegreeExtend(
          typedFieldColumn(values.maskValues),
          blowupFactor,
          cosetOffset
        ),
      valueLdeValues: committedFullBoundaryLde ?? typedCosetLowDegreeExtend(
        typedFieldColumn(values.valueValues),
        blowupFactor,
        cosetOffset
      )
    }
    if (shouldEmitProgress(index, entries.length)) {
      emitStarkProgress(progress, {
        phase: 'stark.composition-context.boundary-columns',
        status: 'progress',
        column,
        count: index + 1,
        total: entries.length
      })
    }
    return result
  })
  const context = { boundaryColumns }
  if (cacheKey !== undefined) {
    if (COMPOSITION_CONTEXT_CACHE.size >= COMPOSITION_CONTEXT_CACHE_LIMIT) {
      const oldest = COMPOSITION_CONTEXT_CACHE.keys().next().value
      if (oldest !== undefined) COMPOSITION_CONTEXT_CACHE.delete(oldest)
    }
    COMPOSITION_CONTEXT_CACHE.set(cacheKey, context)
  }
  return context
}

function compositionContextCacheKey (
  air: AirDefinition,
  traceLength: number,
  ldeSize: number,
  cosetOffset: FieldElement
): string | undefined {
  if (
    air.publicInputDigest === undefined ||
    (
      air.boundaryConstraints.length === 0 &&
      (air.fullBoundaryColumns?.length ?? 0) === 0
    )
  ) {
    return undefined
  }
  const writer = new Writer()
  writer.writeVarIntNum(traceLength)
  writer.writeVarIntNum(ldeSize)
  writer.writeVarIntNum(air.traceWidth)
  writer.write(F.toBytesLE(F.normalize(cosetOffset)))
  writer.write(air.publicInputDigest)
  writer.writeVarIntNum(air.boundaryConstraints.length)
  for (const constraint of air.boundaryConstraints) {
    writer.writeVarIntNum(constraint.column)
    writer.writeVarIntNum(constraint.row)
    writer.write(F.toBytesLE(F.normalize(constraint.value)))
  }
  writer.writeVarIntNum(air.fullBoundaryColumns?.length ?? 0)
  for (const column of air.fullBoundaryColumns ?? []) {
    writer.writeVarIntNum(column.column)
    writer.writeVarIntNum(column.values.length)
  }
  return bytesKey(sha256(writer.toArray()))
}

function transitionZerofierExceptLast (
  x: FieldElement,
  traceLength: number
): FieldElement {
  const traceRoot = getPowerOfTwoRootOfUnity(traceLength)
  const lastPoint = F.pow(traceRoot, BigInt(traceLength - 1))
  const numerator = F.sub(F.pow(x, BigInt(traceLength)), 1n)
  const denominator = F.sub(x, lastPoint)
  if (denominator === 0n) {
    throw new Error('Transition denominator vanished on LDE domain')
  }
  return F.div(numerator, denominator)
}

function getLdePoint (
  domainSize: number,
  cosetOffset: FieldElement,
  index: number
): FieldElement {
  return F.mul(
    cosetOffset,
    F.pow(getPowerOfTwoRootOfUnity(domainSize), BigInt(index))
  )
}

function linearCombination (
  values: FieldElement[],
  alpha: FieldElement
): FieldElement {
  let accumulator = 0n
  let power = 1n
  for (const value of values) {
    accumulator = F.add(accumulator, F.mul(power, value))
    power = F.mul(power, alpha)
  }
  return accumulator
}

function oracleLength (
  oracle: CompositionOracle | TraceCombinationOracle
): number {
  if (oracle.typedValues !== undefined) return oracle.typedValues.lo.length
  if (oracle.values !== undefined) return oracle.values.length
  throw new Error('Oracle has no values')
}

function oracleTypedValues (
  oracle: CompositionOracle | TraceCombinationOracle
): TypedFieldColumn {
  if (oracle.typedValues !== undefined) return oracle.typedValues
  if (oracle.values !== undefined) return typedFieldColumn(oracle.values)
  throw new Error('Oracle has no values')
}

function oracleValue (
  oracle: CompositionOracle | TraceCombinationOracle,
  index: number
): FieldElement {
  if (oracle.typedValues !== undefined) {
    return typedFieldColumnValue(oracle.typedValues, index)
  }
  if (oracle.values !== undefined) return F.normalize(oracle.values[index])
  throw new Error('Oracle has no values')
}

function emptyTypedColumn (length: number): TypedFieldColumn {
  return {
    lo: new Uint32Array(length),
    hi: new Uint32Array(length)
  }
}

function writeTypedColumnValue (
  column: TypedFieldColumn,
  index: number,
  value: FieldElement
): void {
  const typed = typedFieldElement(value)
  column.lo[index] = typed.lo
  column.hi[index] = typed.hi
}

function linearCombinationTraceCommitmentRow (
  commitment: TraceCommitment,
  row: number,
  alpha: FieldElement
): FieldElement {
  let accumulator = 0n
  let power = 1n
  if (commitment.typedLdeColumns !== undefined) {
    for (const column of commitment.typedLdeColumns) {
      accumulator = F.add(
        accumulator,
        F.mul(power, typedFieldColumnValue(column, row))
      )
      power = F.mul(power, alpha)
    }
    return accumulator
  }
  for (const column of commitment.ldeColumns) {
    accumulator = F.add(accumulator, F.mul(power, column[row]))
    power = F.mul(power, alpha)
  }
  return accumulator
}

function constantTypedColumn (
  length: number,
  value: FieldElement
): TypedFieldColumn {
  const normalized = F.normalize(value)
  const lo = Number(normalized & 0xffffffffn) >>> 0
  const hi = Number((normalized >> 32n) & 0xffffffffn) >>> 0
  return {
    lo: new Uint32Array(length).fill(lo),
    hi: new Uint32Array(length).fill(hi)
  }
}

function resolveProverOptions (
  air: AirDefinition,
  traceLength: number,
  options: StarkProverOptions
): ResolvedStarkOptions {
  const blowupFactor = options.blowupFactor ?? air.blowupFactor ?? STARK_DEFAULT_BLOWUP_FACTOR
  const maskDegree = options.maskDegree ?? air.maskDegree ?? STARK_DEFAULT_MASK_DEGREE
  const ldeSize = traceLength * blowupFactor
  const traceDegreeBound = options.traceDegreeBound ?? traceLength + maskDegree
  return {
    blowupFactor,
    numQueries: options.numQueries ?? air.numQueries ?? STARK_DEFAULT_NUM_QUERIES,
    maxRemainderSize: options.maxRemainderSize ?? air.maxRemainderSize ?? STARK_DEFAULT_MAX_REMAINDER_SIZE,
    maskDegree,
    cosetOffset: F.normalize(options.cosetOffset ?? air.cosetOffset ?? STARK_DEFAULT_COSET_OFFSET),
    traceDegreeBound,
    compositionDegreeBound: options.compositionDegreeBound ?? deriveCompositionDegreeBound(
      air,
      traceLength,
      ldeSize,
      traceDegreeBound
    ),
    publicInputDigest: normalizePublicInputDigest(
      options.publicInputDigest ?? air.publicInputDigest
    ),
    transcriptDomain: options.transcriptDomain ?? STARK_TRANSCRIPT_DOMAIN,
    transcriptContext: normalizeOptionalDigest(options.transcriptContext)
  }
}

function resolveVerifierOptions (
  air: AirDefinition,
  traceLength: number,
  options: StarkVerifierOptions
): ResolvedStarkOptions {
  const blowupFactor = options.blowupFactor ?? air.blowupFactor ?? STARK_DEFAULT_BLOWUP_FACTOR
  const maskDegree = options.maskDegree ?? air.maskDegree ?? STARK_DEFAULT_MASK_DEGREE
  const ldeSize = traceLength * blowupFactor
  const traceDegreeBound = options.traceDegreeBound ?? traceLength + maskDegree
  return {
    blowupFactor,
    numQueries: options.numQueries ?? air.numQueries ?? STARK_DEFAULT_NUM_QUERIES,
    maxRemainderSize: options.maxRemainderSize ?? air.maxRemainderSize ?? STARK_DEFAULT_MAX_REMAINDER_SIZE,
    maskDegree,
    cosetOffset: F.normalize(options.cosetOffset ?? air.cosetOffset ?? STARK_DEFAULT_COSET_OFFSET),
    traceDegreeBound,
    compositionDegreeBound: options.compositionDegreeBound ?? deriveCompositionDegreeBound(
      air,
      traceLength,
      ldeSize,
      traceDegreeBound
    ),
    publicInputDigest: normalizePublicInputDigest(
      options.publicInputDigest ?? air.publicInputDigest
    ),
    transcriptDomain: options.transcriptDomain ?? STARK_TRANSCRIPT_DOMAIN,
    transcriptContext: normalizeOptionalDigest(options.transcriptContext)
  }
}

function deriveCompositionDegreeBound (
  air: AirDefinition,
  traceLength: number,
  ldeSize: number,
  traceDegreeBound: number
): number {
  const transitionDegree = air.transitionDegree ?? 2
  if (!Number.isSafeInteger(transitionDegree) || transitionDegree < 1) {
    throw new Error('AIR transitionDegree must be positive')
  }
  const transitionNumeratorBound = Math.max(
    1,
    transitionDegree * traceDegreeBound
  )
  const transitionQuotientBound = Math.max(
    1,
    transitionNumeratorBound - traceLength + 1
  )
  const boundaryBound = (
    air.boundaryConstraints.length > 0 ||
    (air.fullBoundaryColumns?.length ?? 0) > 0
  )
    ? traceDegreeBound
    : 1
  return Math.min(
    ldeSize - 1,
    Math.max(transitionQuotientBound, boundaryBound) + 8
  )
}

function validateStarkParameters (
  traceLength: number,
  traceWidth: number,
  options: ResolvedStarkOptions
): void {
  assertPowerOfTwo(traceLength)
  if (
    !Number.isSafeInteger(traceWidth) ||
    traceWidth < 1 ||
    traceWidth > STARK_MAX_TRACE_WIDTH
  ) {
    throw new Error('STARK trace width must be positive')
  }
  assertPowerOfTwo(options.blowupFactor)
  const ldeSize = traceLength * options.blowupFactor
  assertPowerOfTwo(ldeSize)
  if (!Number.isSafeInteger(options.numQueries) || options.numQueries < 1 || options.numQueries > ldeSize) {
    throw new Error('STARK numQueries must be in [1, LDE size]')
  }
  if (!Number.isSafeInteger(options.maxRemainderSize) || options.maxRemainderSize < 1 || options.maxRemainderSize >= ldeSize) {
    throw new Error('STARK maxRemainderSize must be in [1, LDE size)')
  }
  if (!Number.isSafeInteger(options.maskDegree) || options.maskDegree < 0) {
    throw new Error('STARK maskDegree must be non-negative')
  }
  if (!Number.isSafeInteger(options.traceDegreeBound) || options.traceDegreeBound < 1 || options.traceDegreeBound >= ldeSize) {
    throw new Error('STARK traceDegreeBound must be in [1, LDE size)')
  }
  if (!Number.isSafeInteger(options.compositionDegreeBound) || options.compositionDegreeBound < 1 || options.compositionDegreeBound >= ldeSize) {
    throw new Error('STARK compositionDegreeBound must be in [1, LDE size)')
  }
  if (options.cosetOffset === 0n) {
    throw new Error('STARK cosetOffset must be non-zero')
  }
  assertBytes(options.publicInputDigest)
  if (options.publicInputDigest.length !== 32) {
    throw new Error('STARK publicInputDigest must be 32 bytes')
  }
}

function validateStarkProofShape (proof: StarkProof): void {
  const options: ResolvedStarkOptions = {
    blowupFactor: proof.blowupFactor,
    numQueries: proof.numQueries,
    maxRemainderSize: proof.maxRemainderSize,
    maskDegree: proof.maskDegree,
    cosetOffset: proof.cosetOffset,
    traceDegreeBound: proof.traceDegreeBound,
    compositionDegreeBound: proof.compositionDegreeBound,
    publicInputDigest: proof.publicInputDigest,
    transcriptDomain: STARK_TRANSCRIPT_DOMAIN
  }
  validateStarkParameters(proof.traceLength, proof.traceWidth, options)
  writeHash(new Writer(), proof.traceRoot)
  writeHash(new Writer(), proof.traceCombinationRoot)
  writeHash(new Writer(), proof.compositionRoot)
  for (const opening of [
    ...proof.traceLowDegreeOpenings,
    ...proof.traceOpenings,
    ...proof.nextTraceOpenings,
    ...proof.compositionOpenings
  ]) {
    if (!Number.isSafeInteger(opening.rowIndex) || opening.rowIndex < 0) {
      throw new Error('Invalid STARK opening index')
    }
    for (const value of opening.row) F.assertCanonical(value)
    assertMerklePath(opening.path)
  }
}

function createStarkTranscript (
  traceLength: number,
  traceWidth: number,
  options: ResolvedStarkOptions,
  traceRoot: MerkleHash
): FiatShamirTranscript {
  const transcript = new FiatShamirTranscript(options.transcriptDomain)
  if (options.transcriptContext !== undefined) {
    transcript.absorb('stark-transcript-context', options.transcriptContext)
  }
  transcript.absorb('stark-params', [
    ...u32(traceLength),
    ...u32(traceWidth),
    ...u32(options.blowupFactor),
    ...u32(options.numQueries),
    ...u32(options.maxRemainderSize),
    ...u32(options.maskDegree),
    ...u32(options.traceDegreeBound),
    ...u32(options.compositionDegreeBound),
    ...F.toBytesLE(options.cosetOffset),
    ...options.publicInputDigest
  ])
  transcript.absorb('stark-trace-root', traceRoot)
  return transcript
}

function makeTraceMasks (
  traceWidth: number,
  maskDegree: number,
  seed?: number[],
  unmaskedColumns: Set<number> = new Set()
): FieldElement[][] {
  if (maskDegree === 0) {
    return new Array<FieldElement[]>(traceWidth).fill([])
  }
  if (seed !== undefined) assertBytes(seed)
  const transcript = seed !== undefined
    ? new FiatShamirTranscript(`${STARK_TRANSCRIPT_DOMAIN}:mask`)
    : undefined
  if (transcript !== undefined) transcript.absorb('mask-seed', seed ?? [])
  const masks: FieldElement[][] = []
  for (let column = 0; column < traceWidth; column++) {
    if (unmaskedColumns.has(column)) {
      masks.push([])
      continue
    }
    const columnMask: FieldElement[] = []
    for (let i = 0; i < maskDegree; i++) {
      columnMask.push(transcript !== undefined
        ? transcript.challengeFieldElement(`mask-${column}-${i}`)
        : randomFieldElement())
    }
    masks.push(columnMask)
  }
  return masks
}

function makeMultiTraceMasks (
  segments: Array<{
    name: string
    air: AirDefinition
    traceRows: FieldElement[][]
    resolved: ResolvedStarkOptions
  }>,
  constantLinks: MultiTraceConstantColumnLinkInput[],
  seed?: number[]
): Map<string, FieldElement[][]> {
  if (constantLinks.length === 0) {
    return new Map(segments.map(segment => [
      segment.name,
      makeTraceMasks(
        segment.air.traceWidth,
        segment.resolved.maskDegree,
        seed,
        publicBoundaryColumnSet(segment.air)
      )
    ]))
  }
  const segmentMap = new Map(segments.map(segment => [segment.name, segment]))
  const dsu = new SharedMaskDsu()
  for (const link of constantLinks) {
    const left = segmentMap.get(link.left.segment)
    const right = segmentMap.get(link.right.segment)
    if (left === undefined || right === undefined) {
      throw new Error('multi-trace constant link segment is missing')
    }
    validateSharedMaskCompatible(left, right, link.name)
    dsu.union(maskColumnKey(link.left), maskColumnKey(link.right))
  }
  const transcript = seed !== undefined
    ? new FiatShamirTranscript(`${STARK_TRANSCRIPT_DOMAIN}:multi-trace-mask`)
    : undefined
  if (transcript !== undefined) transcript.absorb('mask-seed', seed)
  const sharedMasks = new Map<string, FieldElement[]>()
  const out = new Map<string, FieldElement[][]>()
  for (const segment of segments) {
    const publicColumns = publicBoundaryColumnSet(segment.air)
    const masks: FieldElement[][] = []
    for (let column = 0; column < segment.air.traceWidth; column++) {
      if (publicColumns.has(column) || segment.resolved.maskDegree === 0) {
        masks.push([])
        continue
      }
      const key = maskColumnKey({ segment: segment.name, column })
      const isShared = dsu.has(key)
      const root = dsu.find(key)
      if (!isShared) {
        masks.push(makeMaskCoefficients(
          segment.resolved.maskDegree,
          transcript,
          `mask:${segment.name}:${column}`
        ))
        continue
      }
      const existing = sharedMasks.get(root)
      if (existing !== undefined) {
        masks.push(existing)
        continue
      }
      const created = makeMaskCoefficients(
        segment.resolved.maskDegree,
        transcript,
        `shared-mask:${root}`
      )
      sharedMasks.set(root, created)
      masks.push(created)
    }
    out.set(segment.name, masks)
  }
  return out
}

function makeMaskCoefficients (
  maskDegree: number,
  transcript: FiatShamirTranscript | undefined,
  label: string
): FieldElement[] {
  const mask: FieldElement[] = []
  for (let i = 0; i < maskDegree; i++) {
    mask.push(transcript !== undefined
      ? transcript.challengeFieldElement(`${label}:${i}`)
      : randomFieldElement())
  }
  return mask
}

function validateSharedMaskCompatible (
  left: {
    name: string
    traceRows: FieldElement[][]
    resolved: ResolvedStarkOptions
  },
  right: {
    name: string
    traceRows: FieldElement[][]
    resolved: ResolvedStarkOptions
  },
  linkName: string
): void {
  if (
    left.traceRows.length !== right.traceRows.length ||
    left.resolved.blowupFactor !== right.resolved.blowupFactor ||
    left.resolved.maskDegree !== right.resolved.maskDegree ||
    left.resolved.cosetOffset !== right.resolved.cosetOffset
  ) {
    throw new Error(
      `multi-trace constant link ${linkName} requires a shared equality domain`
    )
  }
}

function maskColumnKey (ref: MultiTraceConstantColumnRef): string {
  return `${ref.segment}:${ref.column}`
}

class SharedMaskDsu {
  private readonly parents = new Map<string, string>()

  has (key: string): boolean {
    return this.parents.has(key)
  }

  find (key: string): string {
    const parent = this.parents.get(key)
    if (parent === undefined) {
      this.parents.set(key, key)
      return key
    }
    if (parent === key) return key
    const root = this.find(parent)
    this.parents.set(key, root)
    return root
  }

  union (left: string, right: string): void {
    const leftRoot = this.find(left)
    const rightRoot = this.find(right)
    if (leftRoot === rightRoot) return
    const root = leftRoot < rightRoot ? leftRoot : rightRoot
    const child = root === leftRoot ? rightRoot : leftRoot
    this.parents.set(child, root)
  }
}

function publicBoundaryColumnSet (air: AirDefinition): Set<number> {
  const columns = new Set<number>()
  for (const column of air.fullBoundaryColumns ?? []) {
    columns.add(column.column)
  }
  for (const column of air.unmaskedColumns ?? []) {
    if (
      !Number.isSafeInteger(column) ||
      column < 0 ||
      column >= air.traceWidth
    ) {
      throw new Error('AIR unmasked column out of bounds')
    }
    columns.add(column)
  }
  return columns
}

function randomFieldElement (): FieldElement {
  for (;;) {
    try {
      return F.fromBytesLE(randomBytes(8))
    } catch {
      // Rejection probability is about 2^-32.
    }
  }
}

function randomBytes (length: number): number[] {
  const crypto = (globalThis as {
    crypto?: {
      getRandomValues?: (array: Uint8Array) => Uint8Array
    }
  }).crypto
  if (crypto?.getRandomValues === undefined) {
    throw new Error('No Web Crypto random source available')
  }
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return Array.from(bytes)
}

function normalizePublicInputDigest (digest?: number[]): number[] {
  if (digest === undefined) {
    return sha256([...'BRC69_STARK_CORE_EMPTY_PUBLIC_INPUT'].map(c => c.charCodeAt(0)))
  }
  assertBytes(digest)
  if (digest.length !== 32) {
    throw new Error('STARK publicInputDigest must be 32 bytes')
  }
  return digest.slice()
}

function normalizeOptionalDigest (digest?: number[]): number[] | undefined {
  if (digest === undefined) return undefined
  assertBytes(digest)
  if (digest.length !== 32) {
    throw new Error('STARK transcriptContext must be 32 bytes')
  }
  return digest.slice()
}

function multiTraceSegmentProverOptions (
  transcriptDomain: string,
  segment: MultiTraceStarkSegmentInput,
  options: StarkProverOptions
): StarkProverOptions {
  return {
    ...options,
    ...segment.options,
    transcriptDomain: multiTraceSegmentDomain(transcriptDomain, segment.name),
    transcriptContext: undefined
  }
}

function multiTraceSegmentVerifierOptions (
  transcriptDomain: string,
  segment: MultiTraceStarkSegmentVerifierInput,
  options: StarkVerifierOptions,
  proof: StarkProof
): StarkVerifierOptions {
  return {
    ...options,
    ...segment.options,
    transcriptDomain: multiTraceSegmentDomain(transcriptDomain, segment.name),
    traceDegreeBound: proof.traceDegreeBound,
    compositionDegreeBound: proof.compositionDegreeBound,
    publicInputDigest: proof.publicInputDigest,
    transcriptContext: undefined
  }
}

function multiTraceSegmentDomain (
  transcriptDomain: string,
  name: string
): string {
  return `${transcriptDomain}:segment:${name}`
}

function multiTraceContextDigest (
  transcriptDomain: string,
  segments: Array<{
    name: string
    air: AirDefinition
    commitment: {
      traceLength: number
      traceWidth: number
      tree: { root: MerkleHash }
    }
    resolved: ResolvedStarkOptions
  }>
): number[] {
  const writer = new Writer()
  writeString(writer, 'BRC69_MULTI_TRACE_STARK_CONTEXT_V1')
  writeString(writer, transcriptDomain)
  const sorted = segments.slice().sort((a, b) => a.name.localeCompare(b.name))
  writer.writeVarIntNum(sorted.length)
  for (const segment of sorted) {
    writeString(writer, segment.name)
    writer.writeVarIntNum(segment.commitment.traceLength)
    writer.writeVarIntNum(segment.air.traceWidth)
    writer.writeVarIntNum(segment.resolved.blowupFactor)
    writer.writeVarIntNum(segment.resolved.numQueries)
    writer.writeVarIntNum(segment.resolved.maxRemainderSize)
    writer.writeVarIntNum(segment.resolved.maskDegree)
    writer.writeVarIntNum(segment.resolved.traceDegreeBound)
    writer.writeVarIntNum(segment.resolved.compositionDegreeBound)
    writeField(writer, segment.resolved.cosetOffset)
    writeBytes(writer, segment.resolved.publicInputDigest)
    writeHash(writer, segment.commitment.tree.root)
  }
  return sha256(writer.toArray())
}

function proveMultiTraceCrossConstraint (
  constraint: MultiTraceCrossConstraintInput,
  segments: Array<{
    name: string
    air: AirDefinition
    commitment: TraceCommitment
    resolved: ResolvedStarkOptions
  }>,
  transcriptDomain: string,
  contextDigest: number[],
  progress?: StarkProgressCallback
): MultiTraceStarkCrossProof {
  const start = Date.now()
  emitStarkProgress(progress, {
    phase: 'multi-trace.cross.prove',
    status: 'start'
  })
  const parameters = multiTraceCrossParameters(constraint, segments)
  const transcript = createMultiTraceCrossTranscript(
    transcriptDomain,
    contextDigest,
    constraint,
    parameters.degreeBound
  )
  const alpha = transcript.challengeFieldElement('cross-composition-alpha')
  const compositionStart = Date.now()
  emitStarkProgress(progress, {
    phase: 'multi-trace.cross.composition',
    status: 'start',
    traceLength: parameters.traceLength,
    ldeSize: parameters.ldeSize
  })
  const composition = commitMultiTraceCrossComposition(
    constraint,
    segments,
    parameters,
    alpha,
    progress
  )
  emitStarkProgress(progress, {
    phase: 'multi-trace.cross.composition',
    status: 'end',
    traceLength: parameters.traceLength,
    ldeSize: parameters.ldeSize,
    elapsedMs: Date.now() - compositionStart
  })
  emitStarkProgress(progress, {
    phase: 'multi-trace.cross.fri',
    status: 'start',
    ldeSize: oracleLength(composition)
  })
  const friProof = proveFriTyped(oracleTypedValues(composition), {
    degreeBound: parameters.degreeBound,
    numQueries: parameters.numQueries,
    maxRemainderSize: parameters.maxRemainderSize,
    domainOffset: parameters.cosetOffset,
    transcriptDomain: `${transcriptDomain}:cross:${constraint.name}:fri`,
    transcriptContext: contextDigest,
    progress
  })
  emitStarkProgress(progress, {
    phase: 'multi-trace.cross.fri',
    status: 'end',
    ldeSize: oracleLength(composition)
  })
  emitStarkProgress(progress, {
    phase: 'multi-trace.cross.openings',
    status: 'start',
    count: friProof.queries.length,
    total: friProof.queries.length
  })
  const openings = friProof.queries.map(query => ({
    composition: openCompositionRow(composition, query.initialIndex),
    traces: constraint.refs.map(ref => ({
      alias: ref.alias,
      opening: openTraceRow(
        segmentByName(segments, ref.segment).commitment,
        shiftedLdeIndex(
          query.initialIndex,
          ref.shift ?? 0,
          parameters.blowupFactor,
          parameters.ldeSize
        )
      )
    }))
  }))
  emitStarkProgress(progress, {
    phase: 'multi-trace.cross.openings',
    status: 'end',
    count: openings.length,
    total: friProof.queries.length
  })
  emitStarkProgress(progress, {
    phase: 'multi-trace.cross.prove',
    status: 'end',
    elapsedMs: Date.now() - start
  })
  return {
    name: constraint.name,
    compositionRoot: composition.tree.root,
    friProof,
    openings
  }
}

function verifyMultiTraceCrossConstraint (
  constraint: MultiTraceCrossConstraintInput,
  segments: Array<{
    name: string
    air: AirDefinition
    proof: StarkProof
    resolved: ResolvedStarkOptions
  }>,
  proof: MultiTraceStarkCrossProof,
  transcriptDomain: string,
  contextDigest: number[]
): boolean {
  if (proof.name !== constraint.name) return false
  const parameters = multiTraceCrossParameters(constraint, segments)
  if (!verifyFri(proof.friProof, {
    expectedRoot: proof.compositionRoot,
    domainSize: parameters.ldeSize,
    degreeBound: parameters.degreeBound,
    numQueries: parameters.numQueries,
    maxRemainderSize: parameters.maxRemainderSize,
    domainOffset: parameters.cosetOffset,
    transcriptDomain: `${transcriptDomain}:cross:${constraint.name}:fri`,
    transcriptContext: contextDigest
  })) {
    return false
  }
  if (proof.openings.length !== proof.friProof.queries.length) return false
  const transcript = createMultiTraceCrossTranscript(
    transcriptDomain,
    contextDigest,
    constraint,
    parameters.degreeBound
  )
  const alpha = transcript.challengeFieldElement('cross-composition-alpha')
  for (let i = 0; i < proof.friProof.queries.length; i++) {
    const queryIndex = proof.friProof.queries[i].initialIndex
    const opening = proof.openings[i]
    if (
      opening.composition.rowIndex !== queryIndex ||
      opening.composition.row.length !== 1 ||
      !verifyTraceRowOpening(
        proof.compositionRoot,
        opening.composition,
        parameters.ldeSize
      )
    ) {
      return false
    }
    if (opening.traces.length !== constraint.refs.length) return false
    const rows: Record<string, FieldElement[]> = {}
    for (const ref of constraint.refs) {
      const item = opening.traces.find(candidate =>
        candidate.alias === ref.alias
      )
      if (item === undefined) return false
      const segment = segmentByName(segments, ref.segment)
      const expectedIndex = shiftedLdeIndex(
        queryIndex,
        ref.shift ?? 0,
        parameters.blowupFactor,
        parameters.ldeSize
      )
      if (
        item.opening.rowIndex !== expectedIndex ||
        item.opening.row.length !== segment.proof.traceWidth ||
        !verifyTraceRowOpening(
          segment.proof.traceRoot,
          item.opening,
          parameters.ldeSize
        )
      ) {
        return false
      }
      rows[ref.alias] = item.opening.row
    }
    const x = getLdePoint(parameters.ldeSize, parameters.cosetOffset, queryIndex)
    const expected = evaluateMultiTraceCrossCompositionAtPoint(
      constraint,
      rows,
      x,
      queryIndex,
      parameters.traceLength,
      parameters.blowupFactor,
      alpha
    )
    if (opening.composition.row[0] !== expected) return false
  }
  return true
}

function proveMultiTraceConstantColumnLink (
  link: MultiTraceConstantColumnLinkInput,
  segments: Array<{
    name: string
    commitment: TraceCommitment
  }>,
  transcriptDomain: string,
  contextDigest: number[]
): MultiTraceStarkConstantColumnProof {
  const left = segmentByName(segments, link.left.segment)
  const right = segmentByName(segments, link.right.segment)
  validateConstantColumnRef(link.left, left.commitment.traceWidth)
  validateConstantColumnRef(link.right, right.commitment.traceWidth)
  const transcript = createMultiTraceConstantColumnTranscript(
    transcriptDomain,
    contextDigest,
    link
  )
  const queries: MultiTraceStarkConstantColumnQuery[] = []
  const numQueries = link.numQueries ?? 4
  if (left.commitment.ldeSize !== right.commitment.ldeSize) {
    throw new Error('multi-trace constant link requires shared LDE domain')
  }
  for (let i = 0; i < numQueries; i++) {
    const index = transcript.challengeIndex(
      `constant-link:${link.name}:index:${i}`,
      left.commitment.ldeSize
    )
    queries.push({
      left: openTraceRow(left.commitment, index),
      right: openTraceRow(right.commitment, index)
    })
  }
  return { name: link.name, queries }
}

function verifyMultiTraceConstantColumnLink (
  link: MultiTraceConstantColumnLinkInput,
  segments: Array<{
    name: string
    proof: StarkProof
  }>,
  proof: MultiTraceStarkConstantColumnProof,
  transcriptDomain: string,
  contextDigest: number[]
): boolean {
  if (proof.name !== link.name) return false
  const left = segmentByName(segments, link.left.segment)
  const right = segmentByName(segments, link.right.segment)
  validateConstantColumnRef(link.left, left.proof.traceWidth)
  validateConstantColumnRef(link.right, right.proof.traceWidth)
  const numQueries = link.numQueries ?? 4
  if (proof.queries.length !== numQueries) return false
  const ldeSize = left.proof.traceLength * left.proof.blowupFactor
  if (ldeSize !== right.proof.traceLength * right.proof.blowupFactor) {
    return false
  }
  const transcript = createMultiTraceConstantColumnTranscript(
    transcriptDomain,
    contextDigest,
    link
  )
  for (let i = 0; i < numQueries; i++) {
    const query = proof.queries[i]
    const index = transcript.challengeIndex(
      `constant-link:${link.name}:index:${i}`,
      ldeSize
    )
    if (
      query.left.rowIndex !== index ||
      query.right.rowIndex !== index ||
      query.left.row.length !== left.proof.traceWidth ||
      query.right.row.length !== right.proof.traceWidth ||
      !verifyTraceRowOpening(
        left.proof.traceRoot,
        query.left,
        ldeSize
      ) ||
      !verifyTraceRowOpening(
        right.proof.traceRoot,
        query.right,
        ldeSize
      ) ||
      query.left.row[link.left.column] !== query.right.row[link.right.column]
    ) {
      return false
    }
  }
  return true
}

function createMultiTraceConstantColumnTranscript (
  transcriptDomain: string,
  contextDigest: number[],
  link: MultiTraceConstantColumnLinkInput
): FiatShamirTranscript {
  const transcript = new FiatShamirTranscript(
    `${transcriptDomain}:constant-column-link:${link.name}`
  )
  transcript.absorb('constant-link-context', contextDigest)
  const writer = new Writer()
  writeString(writer, link.name)
  writeString(writer, link.left.segment)
  writer.writeVarIntNum(link.left.column)
  writeString(writer, link.right.segment)
  writer.writeVarIntNum(link.right.column)
  writer.writeVarIntNum(link.numQueries ?? 4)
  transcript.absorb('constant-link-definition', writer.toArray())
  return transcript
}

function validateConstantColumnRef (
  ref: MultiTraceConstantColumnRef,
  width: number
): void {
  if (!/^[A-Za-z0-9._-]+$/.test(ref.segment)) {
    throw new Error('multi-trace constant link segment name is invalid')
  }
  if (
    !Number.isSafeInteger(ref.column) ||
    ref.column < 0 ||
    ref.column >= width
  ) {
    throw new Error('multi-trace constant link column is out of bounds')
  }
}

function commitMultiTraceCrossComposition (
  constraint: MultiTraceCrossConstraintInput,
  segments: Array<{
    name: string
    commitment: TraceCommitment
  }>,
  parameters: {
    traceLength: number
    ldeSize: number
    blowupFactor: number
    cosetOffset: FieldElement
  },
  alpha: FieldElement,
  progress?: StarkProgressCallback
): CompositionOracle {
  const typedValues = emptyTypedColumn(parameters.ldeSize)
  for (let index = 0; index < parameters.ldeSize; index++) {
    const rows: Record<string, FieldElement[]> = {}
    for (const ref of constraint.refs) {
      rows[ref.alias] = traceCommitmentLdeRow(
        segmentByName(segments, ref.segment).commitment,
        shiftedLdeIndex(
          index,
          ref.shift ?? 0,
          parameters.blowupFactor,
          parameters.ldeSize
        )
      )
    }
    const x = getLdePoint(parameters.ldeSize, parameters.cosetOffset, index)
    const value = evaluateMultiTraceCrossCompositionAtPoint(
      constraint,
      rows,
      x,
      index,
      parameters.traceLength,
      parameters.blowupFactor,
      alpha
    )
    writeTypedColumnValue(typedValues, index, value)
    if (shouldEmitProgress(index, parameters.ldeSize)) {
      emitStarkProgress(progress, {
        phase: 'multi-trace.cross.composition.rows',
        status: 'progress',
        row: index,
        count: index + 1,
        total: parameters.ldeSize
      })
    }
  }
  return {
    typedValues,
    tree: buildMerkleTreeFromLeafFactory(
      parameters.ldeSize,
      row => typedFieldElementBytes({
        lo: typedValues.lo[row],
        hi: typedValues.hi[row]
      }),
      { progress, phase: 'multi-trace.cross.composition.merkle' }
    )
  }
}

function evaluateMultiTraceCrossCompositionAtPoint (
  constraint: MultiTraceCrossConstraintInput,
  rows: Record<string, FieldElement[]>,
  x: FieldElement,
  ldeIndex: number,
  traceLength: number,
  blowupFactor: number,
  alpha: FieldElement
): FieldElement {
  const denominator = F.sub(F.pow(x, BigInt(traceLength)), 1n)
  if (denominator === 0n) {
    throw new Error('Cross-trace denominator vanished on LDE domain')
  }
  const values = constraint.evaluate({
    rows,
    x,
    ldeIndex,
    traceLength,
    blowupFactor
  })
  let accumulator = 0n
  let alphaPower = 1n
  const denominatorInv = F.inv(denominator)
  for (const value of values) {
    accumulator = F.add(
      accumulator,
      F.mul(alphaPower, F.mul(F.normalize(value), denominatorInv))
    )
    alphaPower = F.mul(alphaPower, alpha)
  }
  return accumulator
}

function multiTraceCrossParameters (
  constraint: MultiTraceCrossConstraintInput,
  segments: Array<{
    name: string
    proof?: StarkProof
    commitment?: TraceCommitment
    resolved: ResolvedStarkOptions
  }>
): {
    traceLength: number
    ldeSize: number
    blowupFactor: number
    numQueries: number
    maxRemainderSize: number
    cosetOffset: FieldElement
    degreeBound: number
  } {
  if (constraint.refs.length === 0) {
    throw new Error('multi-trace cross constraint must reference traces')
  }
  const first = segmentByName(segments, constraint.refs[0].segment)
  const traceLength = first.commitment?.traceLength ?? first.proof?.traceLength
  const blowupFactor = first.resolved.blowupFactor
  const cosetOffset = first.resolved.cosetOffset
  if (traceLength === undefined) {
    throw new Error('multi-trace cross constraint segment is missing trace length')
  }
  for (const ref of constraint.refs) {
    const segment = segmentByName(segments, ref.segment)
    const segmentTraceLength = segment.commitment?.traceLength ??
      segment.proof?.traceLength
    if (
      segmentTraceLength !== traceLength ||
      segment.resolved.blowupFactor !== blowupFactor ||
      segment.resolved.cosetOffset !== cosetOffset
    ) {
      throw new Error(
        'multi-trace cross constraints require a common trace domain'
      )
    }
  }
  const ldeSize = traceLength * blowupFactor
  const degreeBound = constraint.degreeBound ?? Math.min(
    ldeSize - 1,
    traceLength * 8
  )
  return {
    traceLength,
    ldeSize,
    blowupFactor,
    numQueries: first.resolved.numQueries,
    maxRemainderSize: first.resolved.maxRemainderSize,
    cosetOffset,
    degreeBound
  }
}

function createMultiTraceCrossTranscript (
  transcriptDomain: string,
  contextDigest: number[],
  constraint: MultiTraceCrossConstraintInput,
  degreeBound: number
): FiatShamirTranscript {
  const transcript = new FiatShamirTranscript(
    `${transcriptDomain}:cross:${constraint.name}`
  )
  transcript.absorb('cross-context', contextDigest)
  const writer = new Writer()
  writeString(writer, constraint.name)
  writer.writeVarIntNum(degreeBound)
  writer.writeVarIntNum(constraint.refs.length)
  for (const ref of constraint.refs) {
    writeString(writer, ref.alias)
    writeString(writer, ref.segment)
    writer.writeVarIntNum(encodeSignedVarInt(ref.shift ?? 0))
  }
  transcript.absorb('cross-definition', writer.toArray())
  return transcript
}

function shiftedLdeIndex (
  index: number,
  rowShift: number,
  blowupFactor: number,
  ldeSize: number
): number {
  const shifted = index + rowShift * blowupFactor
  return ((shifted % ldeSize) + ldeSize) % ldeSize
}

function validateMultiTraceCrossConstraints (
  constraints: MultiTraceCrossConstraintInput[]
): void {
  validateMultiTraceSegmentNames(constraints.map(constraint => constraint.name))
  for (const constraint of constraints) {
    validateMultiTraceSegmentNames(constraint.refs.map(ref => ref.alias))
    for (const ref of constraint.refs) {
      if (!/^[A-Za-z0-9._-]+$/.test(ref.segment)) {
        throw new Error('multi-trace cross constraint segment name is invalid')
      }
      if (
        ref.shift !== undefined &&
        !Number.isSafeInteger(ref.shift)
      ) {
        throw new Error('multi-trace cross constraint shift is invalid')
      }
    }
  }
}

function validateMultiTraceConstantLinks (
  links: MultiTraceConstantColumnLinkInput[]
): void {
  validateMultiTraceSegmentNames(links.map(link => link.name))
  for (const link of links) {
    for (const ref of [link.left, link.right]) {
      if (!/^[A-Za-z0-9._-]+$/.test(ref.segment)) {
        throw new Error('multi-trace constant link segment name is invalid')
      }
      if (!Number.isSafeInteger(ref.column) || ref.column < 0) {
        throw new Error('multi-trace constant link column is invalid')
      }
    }
    if (
      link.numQueries !== undefined &&
      (!Number.isSafeInteger(link.numQueries) || link.numQueries < 1)
    ) {
      throw new Error('multi-trace constant link query count is invalid')
    }
  }
}

function segmentByName<T extends { name: string }> (
  segments: T[],
  name: string
): T {
  const segment = segments.find(item => item.name === name)
  if (segment === undefined) {
    throw new Error(`multi-trace segment ${name} is missing`)
  }
  return segment
}

function encodeSignedVarInt (value: number): number {
  if (!Number.isSafeInteger(value)) {
    throw new Error('signed varint value is invalid')
  }
  return value >= 0 ? value * 2 : -value * 2 - 1
}

function validateMultiTraceSegmentNames (names: string[]): void {
  const seen = new Set<string>()
  for (const name of names) {
    if (!/^[A-Za-z0-9._-]+$/.test(name)) {
      throw new Error('multi-trace STARK segment name is invalid')
    }
    if (seen.has(name)) {
      throw new Error('multi-trace STARK segment names must be unique')
    }
    seen.add(name)
  }
}

function assertCosetDisjoint (
  traceLength: number,
  cosetOffset: FieldElement
): void {
  if (F.pow(cosetOffset, BigInt(traceLength)) === 1n) {
    throw new Error('STARK coset domain must be disjoint from trace domain')
  }
}

function writeTraceOpenings (
  writer: Writer,
  openings: TraceRowOpening[]
): void {
  writer.writeVarIntNum(openings.length)
  for (const opening of openings) writeTraceOpening(writer, opening)
}

function writeTraceOpening (
  writer: Writer,
  opening: TraceRowOpening
): void {
  writer.writeVarIntNum(opening.rowIndex)
  writer.writeVarIntNum(opening.row.length)
  for (const value of opening.row) writeField(writer, value)
  writeMerklePath(writer, opening.path)
}

function readTraceOpenings (reader: StarkBinaryReader): TraceRowOpening[] {
  const length = reader.readVarIntNum()
  if (length > 1048576) throw new Error('Too many STARK openings')
  const openings: TraceRowOpening[] = []
  for (let i = 0; i < length; i++) openings.push(readTraceOpening(reader))
  return openings
}

function readTraceOpening (reader: StarkBinaryReader): TraceRowOpening {
  const rowIndex = reader.readVarIntNum()
  const rowLength = reader.readVarIntNum()
  if (rowLength > STARK_MAX_TRACE_WIDTH) {
    throw new Error('STARK opening row too wide')
  }
  const row: FieldElement[] = []
  for (let i = 0; i < rowLength; i++) row.push(readField(reader))
  return {
    rowIndex,
    row,
    path: readMerklePath(reader)
  }
}

function writeMerklePath (
  writer: Writer,
  path: MerklePathItem[]
): void {
  assertMerklePath(path)
  writer.writeVarIntNum(path.length)
  for (const item of path) {
    writer.writeUInt8(item.siblingOnLeft ? 1 : 0)
    writeHash(writer, item.sibling)
  }
}

function readMerklePath (reader: StarkBinaryReader): MerklePathItem[] {
  const length = reader.readVarIntNum()
  if (length > 64) throw new Error('Merkle path too long')
  const path: MerklePathItem[] = []
  for (let i = 0; i < length; i++) {
    const direction = reader.readUInt8()
    if (direction !== 0 && direction !== 1) {
      throw new Error('Invalid Merkle path direction')
    }
    path.push({
      siblingOnLeft: direction === 1,
      sibling: readHash(reader)
    })
  }
  return path
}

function starkMerklePathDictionary (proof: StarkProof): MerkleHash[] {
  const hashes: MerkleHash[] = []
  const seen = new Set<string>()
  const addPath = (path: MerklePathItem[]): void => {
    for (const item of path) {
      const key = bytesKey(item.sibling)
      if (!seen.has(key)) {
        seen.add(key)
        hashes.push(item.sibling)
      }
    }
  }
  const addOpenings = (openings: TraceRowOpening[]): void => {
    for (const opening of openings) addPath(opening.path)
  }
  addOpenings(proof.traceLowDegreeOpenings)
  addOpenings(proof.traceOpenings)
  addOpenings(proof.nextTraceOpenings)
  addOpenings(proof.compositionOpenings)
  return hashes
}

function writeHashDictionary (
  writer: Writer,
  hashes: MerkleHash[]
): void {
  writer.writeVarIntNum(hashes.length)
  for (const hash of hashes) writeHash(writer, hash)
}

function readHashDictionary (reader: StarkBinaryReader): MerkleHash[] {
  const length = reader.readVarIntNum()
  if (length > 1048576) throw new Error('Merkle hash dictionary too large')
  const hashes: MerkleHash[] = []
  for (let i = 0; i < length; i++) hashes.push(readHash(reader))
  return hashes
}

function writeCompactTraceOpenings (
  writer: Writer,
  openings: TraceRowOpening[],
  merkleHashIndex: Map<string, number>
): void {
  writer.writeVarIntNum(openings.length)
  for (const opening of openings) {
    writer.writeVarIntNum(opening.rowIndex)
    writer.writeVarIntNum(opening.row.length)
    for (const value of opening.row) writeField(writer, value)
    writeCompactMerklePath(writer, opening.path, merkleHashIndex)
  }
}

function readCompactTraceOpenings (
  reader: StarkBinaryReader,
  merkleHashes: MerkleHash[]
): TraceRowOpening[] {
  const length = reader.readVarIntNum()
  if (length > 1048576) throw new Error('Too many STARK openings')
  const openings: TraceRowOpening[] = []
  for (let i = 0; i < length; i++) {
    const rowIndex = reader.readVarIntNum()
    const rowLength = reader.readVarIntNum()
    if (rowLength > STARK_MAX_TRACE_WIDTH) {
      throw new Error('STARK opening row too wide')
    }
    const row: FieldElement[] = []
    for (let column = 0; column < rowLength; column++) {
      row.push(readField(reader))
    }
    openings.push({
      rowIndex,
      row,
      path: readCompactMerklePath(reader, merkleHashes)
    })
  }
  return openings
}

function writeCompactMerklePath (
  writer: Writer,
  path: MerklePathItem[],
  merkleHashIndex: Map<string, number>
): void {
  assertMerklePath(path)
  writer.writeVarIntNum(path.length)
  for (const item of path) {
    const index = merkleHashIndex.get(bytesKey(item.sibling))
    if (index === undefined) throw new Error('Missing Merkle hash dictionary entry')
    writer.writeUInt8(item.siblingOnLeft ? 1 : 0)
    writer.writeVarIntNum(index)
  }
}

function readCompactMerklePath (
  reader: StarkBinaryReader,
  merkleHashes: MerkleHash[]
): MerklePathItem[] {
  const length = reader.readVarIntNum()
  if (length > 64) throw new Error('Merkle path too long')
  const path: MerklePathItem[] = []
  for (let i = 0; i < length; i++) {
    const direction = reader.readUInt8()
    if (direction !== 0 && direction !== 1) {
      throw new Error('Invalid Merkle path direction')
    }
    const hashIndex = reader.readVarIntNum()
    const sibling = merkleHashes[hashIndex]
    if (sibling === undefined) {
      throw new Error('Invalid Merkle hash dictionary index')
    }
    path.push({
      siblingOnLeft: direction === 1,
      sibling
    })
  }
  return path
}

function assertMerklePath (path: MerklePathItem[]): void {
  if (path.length > 64) throw new Error('Merkle path too long')
  for (const item of path) {
    if (typeof item.siblingOnLeft !== 'boolean') {
      throw new Error('Invalid Merkle path direction')
    }
    assertHash(item.sibling)
  }
}

function writeField (writer: Writer, value: FieldElement): void {
  F.assertCanonical(value)
  writer.write(F.toBytesLE(value))
}

function readField (reader: StarkBinaryReader): FieldElement {
  return F.fromBytesLE(reader.read(8))
}

function writeHash (writer: Writer, hash: number[]): void {
  assertHash(hash)
  writer.write(hash)
}

function readHash (reader: StarkBinaryReader): MerkleHash {
  const hash = reader.read(32)
  assertHash(hash)
  return hash
}

function assertHash (hash: number[]): void {
  if (hash.length !== 32) throw new Error('Merkle hashes must be 32 bytes')
  assertBytes(hash)
}

function writeBytes (writer: Writer, bytes: number[]): void {
  assertBytes(bytes)
  writer.writeVarIntNum(bytes.length)
  writer.write(bytes)
}

function writeString (writer: Writer, value: string): void {
  const bytes = Array.from(value).map(char => char.charCodeAt(0))
  writeBytes(writer, bytes)
}

function readBytes (reader: StarkBinaryReader): number[] {
  const length = reader.readVarIntNum()
  if (length > 1048576) throw new Error('Byte field too long')
  const bytes = reader.read(length)
  assertBytes(bytes)
  return bytes
}

function readString (reader: StarkBinaryReader): string {
  return String.fromCharCode(...readBytes(reader))
}

function assertBytes (bytes: number[]): void {
  for (const byte of bytes) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error('Invalid byte value')
    }
  }
}

function hashesEqual (a: number[], b: number[]): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

function bytesKey (bytes: number[]): string {
  return bytes.map(byte => byte.toString(16).padStart(2, '0')).join('')
}

function u32 (value: number): number[] {
  return [
    value & 0xff,
    (value >>> 8) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 24) & 0xff
  ]
}

class StarkBinaryReader {
  private readonly bytes: number[]
  private offset = 0

  constructor (bytes: number[]) {
    assertBytes(bytes)
    this.bytes = bytes
  }

  eof (): boolean {
    return this.offset === this.bytes.length
  }

  read (length: number): number[] {
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new Error('Invalid read length')
    }
    if (this.offset + length > this.bytes.length) {
      throw new Error('Unexpected end of STARK proof')
    }
    const out = this.bytes.slice(this.offset, this.offset + length)
    this.offset += length
    return out
  }

  readUInt8 (): number {
    return this.read(1)[0]
  }

  readVarIntNum (): number {
    const first = this.readUInt8()
    if (first < 0xfd) return first
    if (first === 0xfd) {
      const value = this.readUIntLE(2)
      if (value < 0xfd) throw new Error('Non-canonical varint')
      return Number(value)
    }
    if (first === 0xfe) {
      const value = this.readUIntLE(4)
      if (value < 0x10000n) throw new Error('Non-canonical varint')
      return Number(value)
    }
    const value = this.readUIntLE(8)
    if (value < 0x100000000n) throw new Error('Non-canonical varint')
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('Varint exceeds safe integer range')
    }
    return Number(value)
  }

  private readUIntLE (length: number): bigint {
    const bytes = this.read(length)
    let value = 0n
    for (let i = 0; i < bytes.length; i++) {
      value |= BigInt(bytes[i]) << BigInt(i * 8)
    }
    return value
  }
}
