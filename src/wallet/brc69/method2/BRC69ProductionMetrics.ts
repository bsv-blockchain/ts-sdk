import { toArray, toHex } from '../../../primitives/utils.js'
import {
  SECP256K1_N,
  compressPoint,
  scalarMultiply
} from '../circuit/Secp256k1.js'
import { hmacSha256 } from '../circuit/Sha256.js'
import { buildLookupBusAir } from '../stark/LookupBus.js'
import {
  BRC69_RADIX11_TABLE_ROWS,
  buildProductionRadix11LookupPrototype,
  productionRadix11TableRoot,
  productionRadix11LookupMetrics,
  proveProductionRadix11Lookup,
  verifyProductionRadix11Lookup
} from '../stark/DualBaseRadix11Metrics.js'
import {
  buildProductionRadix11EcTrace,
  productionRadix11EcMetrics
} from '../stark/ProductionRadix11Ec.js'
import {
  buildProductionEcTrace,
  productionEcMetrics,
  productionEcTracePrivateS,
  proveProductionEc,
  verifyProductionEc
} from '../stark/ProductionEcAir.js'
import {
  TypedStarkBackendBenchmarkMetrics,
  benchmarkTypedStarkBackendShape,
  estimateStarkProofBytes
} from '../stark/TypedStark.js'
import {
  MultiTraceStarkProof,
  StarkProof,
  StarkProverOptions,
  serializeMultiTraceStarkProof,
  serializeStarkProof,
  verifyStark
} from '../stark/Stark.js'
import {
  StarkProgressCallback,
  emitStarkProgress,
  withStarkProgressContext
} from '../stark/Progress.js'
import { computeInvoiceNumber } from '../../keyLinkage.js'
import {
  METHOD2_COMPACT_HMAC_SHA256_TRANSCRIPT_DOMAIN,
  buildMethod2CompactHmacSha256Air,
  buildMethod2CompactHmacSha256Trace,
  method2CompactHmacSha256Metrics,
  proveMethod2CompactHmacSha256
} from './Method2CompactHmacSha256.js'
import {
  brc69ProductionScalarMetrics,
  buildBRC69ProductionScalarTrace,
  proveBRC69ProductionScalar,
  verifyBRC69ProductionScalar
} from './BRC69ProductionScalar.js'
import {
  brc69ProductionCompressionBytes,
  brc69ProductionCompressionMetrics,
  buildBRC69ProductionCompressionTrace,
  proveBRC69ProductionCompression,
  verifyBRC69ProductionCompression
} from './BRC69ProductionCompression.js'
import {
  brc69Method2WholeStatementMetrics,
  buildBRC69Method2WholeStatement,
  diagnoseBRC69Method2WholeStatement,
  proveBRC69Method2WholeStatement,
  verifyBRC69Method2WholeStatement
} from './BRC69Method2WholeStatement.js'

export const BRC69_PRODUCTION_METRICS_PROFILE = {
  blowupFactor: 16,
  numQueries: 48,
  maxRemainderSize: 16,
  maskDegree: 192,
  cosetOffset: 7n,
  transcriptDomain: 'BRC69_METHOD2_PRODUCTION_METRICS_V1'
} as const
export const BRC69_PRODUCTION_MAX_PROOF_BYTES = 1500000

export interface BRC69ProductionMetricsOptions {
  mode?: 'full' | 'fast'
  prove?: boolean
  proveSegments?: boolean
  proveEc?: boolean
  proveWhole?: boolean
  now?: () => number
  progress?: StarkProgressCallback
  sampleColumns?: number
  maxSampleTraceLength?: number
  gitCommit?: string
  cpuCount?: number
  onWholeStatementProof?: (artifact: {
    publicInput: unknown
    proof: unknown
    diagnostic: unknown
    verified: boolean | undefined
  }) => void
}

export interface BRC69ProductionMetricsReport {
  environment: BRC69ProductionMetricsEnvironment
  profile: typeof BRC69_PRODUCTION_METRICS_PROFILE
  inputs: BRC69ProductionMetricsInputs
  segments: Record<BRC69ProductionSegmentName, BRC69ProductionSegmentMetrics>
}

export type BRC69ProductionSegmentName =
  'scalarDigits' |
  'radix11PointLookup' |
  'ecArithmetic' |
  'compressionAndKeyBinding' |
  'maxInvoiceCompactHmac' |
  'lookupEqualityBus' |
  'wholeStatement'

export interface BRC69ProductionMetricsEnvironment {
  timestamp: string
  node?: string
  platform?: string
  arch?: string
  cpuCount?: number
  gitCommit?: string
}

export interface BRC69ProductionMetricsInputs {
  invoiceLength: number
  invoicePreview: string
  innerBlocks: number
  outerBlocks: number
  totalBlocks: number
  scalarProfile: string
  baseBCompressed: string
  linkageHex: string
  radixWindowBits: number
  radixWindowCount: number
}

export interface BRC69ProductionSegmentMetrics {
  status: 'actual' | 'projection' | 'mixed'
  activeRows: number
  paddedRows: number
  committedWidth: number
  committedCells: number
  ldeRows: number
  ldeCells: number
  fixedPreprocessedRows: number
  lookupRequestsByTag: Record<string, number>
  proofBytes?: number
  estimatedProofBytes?: number
  buildMs?: number
  proveMs?: number
  verifyMs?: number
  tableGenerationMs?: number
  tableRootMs?: number
  verified?: boolean
  diagnostic?: unknown
  memory?: BRC69ProductionMemoryDelta
  backend?: TypedStarkBackendBenchmarkMetrics
  notes?: string[]
}

export interface BRC69ProductionMemoryDelta {
  beforeHeapUsed: number
  afterHeapUsed: number
  deltaHeapUsed: number
  beforeRss: number
  afterRss: number
  deltaRss: number
}

interface TimedResult<T> {
  value: T
  ms: number
  memory: BRC69ProductionMemoryDelta
}

export function collectBRC69ProductionMetrics (
  options: BRC69ProductionMetricsOptions = {}
): BRC69ProductionMetricsReport {
  const mode = options.mode ?? 'full'
  const prove = options.prove ?? mode === 'full'
  const proveSegments = options.proveSegments ?? false
  const proveSegmentProofs = prove && proveSegments
  const proveEc = options.proveEc ?? proveSegmentProofs
  const proveWhole = options.proveWhole ?? prove
  const now = options.now ?? (() => Date.now())
  const progress = options.progress
  const step = <T>(
    phase: string,
    fn: () => T,
    metricSegment?: BRC69ProductionSegmentName
  ): TimedResult<T> => timed(now, fn, progress, phase, metricSegment)
  const sampleColumns = options.sampleColumns ?? (mode === 'fast' ? 1 : 4)
  const maxSampleTraceLength = options.maxSampleTraceLength ??
    (mode === 'fast' ? 256 : 4096)
  const inputs = deterministicInputs()
  const proofOptions = (
    metricSegment: BRC69ProductionSegmentName
  ): StarkProverOptions => ({
    ...BRC69_PRODUCTION_METRICS_PROFILE,
    maskSeed: toArray('brc69-production-metrics-mask', 'utf8'),
    progress: withStarkProgressContext(progress, { metricSegment })
  })

  emitStarkProgress(progress, {
    phase: 'brc69.metrics.collect',
    status: 'start'
  })
  const radixTableBuild = step(
    'brc69.metrics.radix11PointLookup.table-build',
    () => buildProductionRadix11LookupPrototype(inputs.scalar, inputs.baseB),
    'radix11PointLookup'
  )
  const radixRoot = step(
    'brc69.metrics.radix11PointLookup.table-root',
    () => productionRadix11TableRoot(radixTableBuild.value.table),
    'radix11PointLookup'
  )
  const radixAir = buildLookupBusAir(radixTableBuild.value.trace.publicInput)
  const radixProof = proveSegmentProofs
    ? step('brc69.metrics.radix11PointLookup.prove', () => proveProductionRadix11Lookup(
      radixTableBuild.value,
      proofOptions('radix11PointLookup')
    ), 'radix11PointLookup')
    : undefined
  const radixVerify = radixProof === undefined
    ? undefined
    : step('brc69.metrics.radix11PointLookup.verify', () =>
      verifyProductionRadix11Lookup(radixTableBuild.value, radixProof.value),
    'radix11PointLookup')
  const radixMetrics = productionRadix11LookupMetrics(
    radixTableBuild.value,
    radixProof?.value,
    BRC69_PRODUCTION_METRICS_PROFILE.blowupFactor
  )
  const scalarBuild = step(
    'brc69.metrics.scalarDigits.build',
    () => buildBRC69ProductionScalarTrace(radixTableBuild.value),
    'scalarDigits'
  )
  const scalarProof = proveSegmentProofs
    ? step('brc69.metrics.scalarDigits.prove', () => proveBRC69ProductionScalar(
      scalarBuild.value,
      proofOptions('scalarDigits')
    ), 'scalarDigits')
    : undefined
  const scalarVerify = scalarProof === undefined
    ? undefined
    : step('brc69.metrics.scalarDigits.verify', () => verifyBRC69ProductionScalar(
      scalarBuild.value.publicInput,
      scalarProof.value
    ), 'scalarDigits')
  const scalarBaseMetrics = brc69ProductionScalarMetrics(
    scalarBuild.value,
    scalarProof?.value,
    BRC69_PRODUCTION_METRICS_PROFILE.blowupFactor
  )
  const ecBuild = step(
    'brc69.metrics.ecArithmetic.radix-trace-build',
    () => buildProductionRadix11EcTrace(radixTableBuild.value),
    'ecArithmetic'
  )
  const productionEcBuild = step(
    'brc69.metrics.ecArithmetic.production-trace-build',
    () => buildProductionEcTrace(ecBuild.value),
    'ecArithmetic'
  )
  const ecProof = proveEc
    ? step(
      'brc69.metrics.ecArithmetic.prove',
      () => proveProductionEc(productionEcBuild.value, proofOptions('ecArithmetic')),
      'ecArithmetic'
    )
    : undefined
  const ecVerify = ecProof === undefined
    ? undefined
    : step('brc69.metrics.ecArithmetic.verify', () => verifyProductionEc(
      productionEcBuild.value.publicInput,
      ecProof.value,
      BRC69_PRODUCTION_METRICS_PROFILE
    ), 'ecArithmetic')
  const ecRadixMetrics = productionRadix11EcMetrics(
    ecBuild.value,
    BRC69_PRODUCTION_METRICS_PROFILE.blowupFactor
  )
  const ecBaseMetrics = productionEcMetrics(
    productionEcBuild.value,
    ecProof?.value,
    BRC69_PRODUCTION_METRICS_PROFILE.blowupFactor
  )
  const airPrivateS = productionEcTracePrivateS(productionEcBuild.value)
  const airCompressedS = compressPoint(airPrivateS)
  if (!bytesEqual(airCompressedS, inputs.key)) {
    throw new Error('BRC69 production metrics EC/HMAC key mismatch')
  }
  const compressionBuild = step(
    'brc69.metrics.compressionAndKeyBinding.build',
    () => buildBRC69ProductionCompressionTrace(airPrivateS),
    'compressionAndKeyBinding'
  )
  if (!bytesEqual(brc69ProductionCompressionBytes(compressionBuild.value), inputs.key)) {
    throw new Error('BRC69 production metrics compression/HMAC key mismatch')
  }
  const compressionProof = proveSegmentProofs
    ? step('brc69.metrics.compressionAndKeyBinding.prove', () => proveBRC69ProductionCompression(
      compressionBuild.value,
      proofOptions('compressionAndKeyBinding')
    ), 'compressionAndKeyBinding')
    : undefined
  const compressionVerify = compressionProof === undefined
    ? undefined
    : step('brc69.metrics.compressionAndKeyBinding.verify', () => verifyBRC69ProductionCompression(
      compressionBuild.value.publicInput,
      compressionProof.value
    ), 'compressionAndKeyBinding')
  const compressionBaseMetrics = brc69ProductionCompressionMetrics(
    compressionBuild.value,
    compressionProof?.value,
    BRC69_PRODUCTION_METRICS_PROFILE.blowupFactor
  )
  const hmacBuild = step(
    'brc69.metrics.maxInvoiceCompactHmac.build',
    () => buildMethod2CompactHmacSha256Trace(
      brc69ProductionCompressionBytes(compressionBuild.value),
      inputs.invoice,
      inputs.linkage
    ),
    'maxInvoiceCompactHmac'
  )
  const hmacAir = buildMethod2CompactHmacSha256Air(hmacBuild.value.publicInput)
  const hmacProof = proveSegmentProofs
    ? step('brc69.metrics.maxInvoiceCompactHmac.prove', () => proveMethod2CompactHmacSha256(
      hmacBuild.value,
      proofOptions('maxInvoiceCompactHmac')
    ), 'maxInvoiceCompactHmac')
    : undefined
  const hmacVerify = hmacProof === undefined
    ? undefined
    : step('brc69.metrics.maxInvoiceCompactHmac.verify', () => verifyStark(hmacAir, hmacProof.value, {
      ...BRC69_PRODUCTION_METRICS_PROFILE,
      publicInputDigest: hmacAir.publicInputDigest,
      transcriptDomain: METHOD2_COMPACT_HMAC_SHA256_TRANSCRIPT_DOMAIN
    }), 'maxInvoiceCompactHmac')
  const hmacBaseMetrics = method2CompactHmacSha256Metrics(
    hmacBuild.value,
    hmacProof?.value
  )
  const wholeBuild = step(
    'brc69.metrics.wholeStatement.build',
    () => buildBRC69Method2WholeStatement({
      scalar: inputs.scalar,
      baseB: inputs.baseB,
      invoice: inputs.invoice,
      linkage: inputs.linkage
    }),
    'wholeStatement'
  )
  const wholeProof = proveWhole
    ? step('brc69.metrics.wholeStatement.prove', () => proveBRC69Method2WholeStatement(
      wholeBuild.value,
      proofOptions('wholeStatement')
    ), 'wholeStatement')
    : undefined
  const wholeVerify = wholeProof === undefined
    ? undefined
    : step('brc69.metrics.wholeStatement.verify', () => verifyBRC69Method2WholeStatement(
      wholeBuild.value.publicInput,
      wholeProof.value
    ), 'wholeStatement')
  const wholeDiagnostic = wholeProof === undefined
    ? undefined
    : diagnoseBRC69Method2WholeStatement(
      wholeBuild.value.publicInput,
      wholeProof.value
    )
  if (wholeProof !== undefined) {
    options.onWholeStatementProof?.({
      publicInput: wholeBuild.value.publicInput,
      proof: wholeProof.value,
      diagnostic: wholeDiagnostic,
      verified: wholeVerify?.value
    })
  }
  const wholeBaseMetrics = brc69Method2WholeStatementMetrics(
    wholeBuild.value,
    wholeProof?.value
  )

  const scalarDigits = actualSegment({
    activeRows: scalarBaseMetrics.activeRows,
    paddedRows: scalarBaseMetrics.paddedRows,
    width: scalarBaseMetrics.traceWidth,
    fixedRows: 0,
    tagCounts: {
      scalarDigit: scalarBaseMetrics.digitRows,
      scalarRangeBit: scalarBaseMetrics.bitRows
    },
    proof: scalarProof?.value,
    build: scalarBuild,
    prove: scalarProof,
    verify: scalarVerify,
    backend: backendMetrics(
      scalarBaseMetrics.paddedRows,
      scalarBaseMetrics.traceWidth,
      sampleColumns,
      maxSampleTraceLength,
      now
    ),
    verified: scalarVerify?.value,
    notes: [
      proveSegmentProofs
        ? 'Actual scalar digit AIR proved canonical signed radix-11 digits, unsigned scalar reconstruction, non-zero scalar, and scalar <= n - 1.'
        : 'Actual scalar digit AIR shape measured; proof skipped by metrics options.'
    ]
  })
  const ecArithmetic = actualSegment({
    activeRows: ecBaseMetrics.activeRows,
    paddedRows: ecBaseMetrics.paddedRows,
    width: ecBaseMetrics.traceWidth,
    fixedRows: 0,
    tagCounts: {
      pointPairOutput: ecRadixMetrics.selectedRows,
      signedPointNegation: ecRadixMetrics.signedPointNegations,
      affineDistinctAdd: ecRadixMetrics.distinctAddBranches,
      affineDoubling: ecRadixMetrics.doublingBranches,
      affineOpposite: ecRadixMetrics.oppositeBranches,
      scheduledAffineLaneAddition: ecBaseMetrics.scheduledAdditions,
      limbRange: ecBaseMetrics.linearOps * 3 * 5 +
        ecBaseMetrics.mulOps * 4 * 10
    },
    build: productionEcBuild,
    prove: ecProof,
    verify: ecVerify,
    proof: ecProof?.value,
    verified: ecVerify?.value,
    notes: [
      proveEc
        ? 'Actual hardened production radix-11 EC accumulator AIR proved the fixed 48-lane schedule, branch-gated accumulator transitions, selected 52/26-bit field limbs, canonical field encodings, signed carries, final public A boundary, and private S output consumed by compression; doubling/opposite branches are rejected fail-closed by this slice.'
        : 'Actual hardened production radix-11 EC accumulator AIR shape measured; proof skipped by metrics options; selected 52/26-bit field limbs, canonical field encodings, and signed carries are constrained; doubling/opposite branches are rejected fail-closed by this slice.'
    ]
  })
  const compression = actualSegment({
    activeRows: compressionBaseMetrics.activeRows,
    paddedRows: compressionBaseMetrics.paddedRows,
    width: compressionBaseMetrics.traceWidth,
    fixedRows: 0,
    tagCounts: {
      compressedByte: compressionBaseMetrics.compressedBytes,
      compressedXBit: compressionBaseMetrics.xBitRows
    },
    proof: compressionProof?.value,
    build: compressionBuild,
    prove: compressionProof,
    verify: compressionVerify,
    backend: backendMetrics(
      compressionBaseMetrics.paddedRows,
      compressionBaseMetrics.traceWidth,
      sampleColumns,
      maxSampleTraceLength,
      now
    ),
    verified: compressionVerify?.value,
    notes: [
      proveSegmentProofs
        ? 'Actual compression/key-binding AIR proved non-infinity S encoding, x-byte reconstruction, y-parity prefix, and bus-linked HMAC key bytes.'
        : 'Actual compression/key-binding AIR shape measured; proof skipped by metrics options.'
    ]
  })
  const lookupBus = actualSegment({
    activeRows: Object.values(wholeBuild.value.publicInput.bus.segments)
      .reduce((total, segment) => total + segment.emissionCount, 0),
    paddedRows: wholeBaseMetrics.segments.bus.rows,
    width: wholeBaseMetrics.segments.bus.width,
    fixedRows: 0,
    tagCounts: {
      scalarDigit: scalarBaseMetrics.digitRows * 2,
      pointPairOutput: radixMetrics.selectedRows * 2,
      ecSelectedGPoint: radixMetrics.selectedRows * 2,
      ecSelectedBPoint: radixMetrics.selectedRows * 2,
      ecPrivateSPoint: 2,
      compressedSKeyByte: compressionBaseMetrics.compressedBytes * 2
    },
    build: wholeBuild,
    prove: undefined,
    verify: wholeVerify,
    backend: backendMetrics(
      wholeBaseMetrics.segments.bus.rows,
      wholeBaseMetrics.segments.bus.width,
      sampleColumns,
      maxSampleTraceLength,
      now
    ),
    verified: wholeVerify?.value,
    notes: [
      prove
        ? 'Production lookup/equality bus is committed as the second phased bus trace after deriving challenges from the base trace root; per-segment bus totals are not public.'
        : 'Production lookup/equality bus phase shape measured from challenge-dependent accumulator columns; proof skipped by metrics options.'
    ]
  })

  const hmacSegment = actualSegment({
    activeRows: hmacBaseMetrics.activeRows,
    paddedRows: hmacBaseMetrics.paddedRows,
    width: hmacBaseMetrics.traceWidth,
    fixedRows: 0,
    tagCounts: hmacCompactTagCounts(hmacBaseMetrics.totalBlocks),
    proof: hmacProof?.value,
    build: hmacBuild,
    prove: hmacProof,
    verify: hmacVerify,
    backend: backendMetrics(
      hmacBaseMetrics.paddedRows,
      hmacBaseMetrics.traceWidth,
      sampleColumns,
      maxSampleTraceLength,
      now
    ),
    verified: hmacVerify?.value,
    notes: [
      proveSegmentProofs
        ? 'Actual compact HMAC AIR proved SHA-256/HMAC arithmetic directly under the production profile.'
        : 'Actual compact HMAC AIR shape measured; proof skipped by metrics options.'
    ]
  })

  const radixSegment = actualSegment({
    activeRows: radixMetrics.activeRows,
    paddedRows: radixMetrics.paddedRows,
    width: radixMetrics.traceWidth,
    fixedRows: radixMetrics.tableRows,
    tagCounts: { dualBasePointPair: radixMetrics.selectedRows },
    proof: radixProof?.value,
    build: radixTableBuild,
    prove: radixProof,
    verify: radixVerify,
    tableGenerationMs: radixTableBuild.ms,
    tableRootMs: radixRoot.ms,
    backend: backendMetrics(
      radixMetrics.paddedRows,
      radixMetrics.traceWidth,
      sampleColumns,
      maxSampleTraceLength,
      now
    ),
    verified: radixVerify?.value ?? (
      radixProof === undefined
        ? undefined
        : verifyProductionRadix11Lookup(radixTableBuild.value, radixProof.value)
    )
  })

  const wholePaddedRows = Math.max(
    ...Object.values(wholeBaseMetrics.segments).map(segment => segment.rows)
  )
  const wholeWidth = Object.values(wholeBaseMetrics.segments)
    .reduce((total, segment) => total + segment.width, 0)
  const wholeActiveRows = scalarBaseMetrics.activeRows +
    radixMetrics.activeRows +
    ecBaseMetrics.activeRows +
    compressionBaseMetrics.activeRows +
    hmacBaseMetrics.activeRows +
    24
  const wholeStatement = actualSegment({
    activeRows: wholeActiveRows,
    paddedRows: wholePaddedRows,
    width: wholeWidth,
    fixedRows: BRC69_RADIX11_TABLE_ROWS,
    tagCounts: {
      scalarDigit: scalarBaseMetrics.digitRows,
      pointPairOutput: radixMetrics.selectedRows,
      ecSelectedGPoint: radixMetrics.selectedRows,
      ecSelectedBPoint: radixMetrics.selectedRows,
      ecPrivateSPoint: 1,
      compressedSKeyByte: compressionBaseMetrics.compressedBytes,
      scalarRangeBit: scalarBaseMetrics.bitRows,
      dualBasePointPair: radixMetrics.selectedRows,
      signedPointNegation: ecRadixMetrics.signedPointNegations,
      affineDistinctAdd: ecRadixMetrics.distinctAddBranches,
      affineDoubling: ecRadixMetrics.doublingBranches,
      affineOpposite: ecRadixMetrics.oppositeBranches,
      scheduledAffineLaneAddition: ecBaseMetrics.scheduledAdditions,
      limbRange: ecBaseMetrics.linearOps * 3 * 5 +
        ecBaseMetrics.mulOps * 4 * 10,
      compressedByte: compressionBaseMetrics.compressedBytes,
      compressedXBit: compressionBaseMetrics.xBitRows,
      ...hmacCompactTagCounts(hmacBaseMetrics.totalBlocks)
    },
    proofBytes: wholeBaseMetrics.proofBytes,
    committedCells: wholeBaseMetrics.totalCommittedCells,
    ldeCells: wholeBaseMetrics.totalCommittedCells *
      BRC69_PRODUCTION_METRICS_PROFILE.blowupFactor,
    build: wholeBuild,
    prove: wholeProof,
    verify: wholeVerify,
    backend: backendMetrics(
      wholePaddedRows,
      wholeWidth,
      sampleColumns,
      maxSampleTraceLength,
      now
    ),
    verified: wholeVerify?.value,
    diagnostic: wholeDiagnostic,
    notes: [
      proveWhole
        ? 'Actual phased whole-statement proof binds the base witness trace to post-commitment lookup and segment-bus accumulator traces in one Fiat-Shamir context.'
        : 'Actual phased whole-statement shape measured; proof skipped by metrics options.'
    ]
  })

  const segments: Record<BRC69ProductionSegmentName, BRC69ProductionSegmentMetrics> = {
    scalarDigits,
    radix11PointLookup: radixSegment,
    ecArithmetic,
    compressionAndKeyBinding: compression,
    maxInvoiceCompactHmac: hmacSegment,
    lookupEqualityBus: lookupBus,
    wholeStatement
  }

  const report = {
    environment: environment(options),
    profile: BRC69_PRODUCTION_METRICS_PROFILE,
    inputs: {
      invoiceLength: inputs.invoice.length,
      invoicePreview: inputs.invoiceString.slice(0, 48),
      innerBlocks: hmacBuild.value.publicInput.innerBlocks,
      outerBlocks: hmacBuild.value.publicInput.outerBlocks,
      totalBlocks: hmacBuild.value.publicInput.totalBlocks,
      scalarProfile: 'SECP256K1_N - 123456789',
      baseBCompressed: toHex(compressPoint(inputs.baseB)),
      linkageHex: toHex(inputs.linkage),
      radixWindowBits: 11,
      radixWindowCount: 24
    },
    segments
  }
  emitStarkProgress(progress, {
    phase: 'brc69.metrics.collect',
    status: 'end'
  })
  return report
}

export function formatBRC69ProductionMetrics (
  report: BRC69ProductionMetricsReport
): string {
  const rows = Object.entries(report.segments).map(([name, segment]) => {
    const proofBytes = segment.proofBytes ?? segment.estimatedProofBytes
    const verified = segment.verified === undefined
      ? 'n/a'
      : String(segment.verified)
    return `| ${name} | ${segment.status} | ${segment.activeRows} | ` +
      `${segment.paddedRows} | ${segment.committedWidth} | ` +
      `${segment.committedCells} | ${proofBytes ?? 'n/a'} | ` +
      `${formatMs(segment.proveMs)} | ${formatMs(segment.verifyMs)} | ` +
      `${verified} |`
  })
  return [
    '# BRC69 Production Metrics',
    '',
    `- invoice length: ${report.inputs.invoiceLength}`,
    `- SHA/HMAC blocks: ${report.inputs.totalBlocks}`,
    `- radix-11 table rows: ${BRC69_RADIX11_TABLE_ROWS}`,
    `- profile: blowup ${report.profile.blowupFactor}, ` +
      `${report.profile.numQueries} queries`,
    '',
    '| segment | status | active rows | padded rows | width | cells | ' +
      'proof bytes | prove | verify | verified |',
    '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
    ...rows
  ].join('\n')
}

export function unverifiedBRC69ActualSegments (
  report: BRC69ProductionMetricsReport
): string[] {
  return Object.entries(report.segments)
    .filter(([, segment]) => (
      segment.status === 'actual' &&
      actualSegmentAttemptedProof(segment) &&
      segment.verified !== true
    ))
    .map(([name]) => name)
}

export function assertBRC69ActualSegmentsVerified (
  report: BRC69ProductionMetricsReport
): void {
  const failed = unverifiedBRC69ActualSegments(report)
  if (failed.length > 0) {
    throw new Error(
      'BRC69 production metrics has unverified actual segment(s): ' +
      failed.join(', ')
    )
  }
}

export function brc69ProductionAcceptanceIssues (
  report: BRC69ProductionMetricsReport
): string[] {
  const issues: string[] = []
  const projected = Object.entries(report.segments)
    .filter(([name, segment]) =>
      name !== 'wholeStatement' && segment.status === 'projection'
    )
    .map(([name]) => name)
  if (projected.length > 0) {
    issues.push(`projected segment(s): ${projected.join(', ')}`)
  }
  const unverified = Object.entries(report.segments)
    .filter(([, segment]) =>
      segment.status === 'actual' &&
      (segment.verified !== undefined || actualSegmentAttemptedProof(segment)) &&
      segment.verified !== true
    )
    .map(([name]) => name)
  if (unverified.length > 0) {
    issues.push(`unverified actual segment(s): ${unverified.join(', ')}`)
  }
  if (report.segments.wholeStatement.status !== 'actual') {
    issues.push(`wholeStatement status is ${report.segments.wholeStatement.status}`)
  }
  const wholeProofBytes = report.segments.wholeStatement.proofBytes ??
    report.segments.wholeStatement.estimatedProofBytes
  if (
    wholeProofBytes !== undefined &&
    wholeProofBytes > BRC69_PRODUCTION_MAX_PROOF_BYTES
  ) {
    issues.push(
      `wholeStatement proof bytes ${wholeProofBytes} exceeds ` +
      `${BRC69_PRODUCTION_MAX_PROOF_BYTES}`
    )
  }
  if (
    report.profile.blowupFactor !== BRC69_PRODUCTION_METRICS_PROFILE.blowupFactor ||
    report.profile.numQueries !== BRC69_PRODUCTION_METRICS_PROFILE.numQueries ||
    report.profile.maxRemainderSize !==
      BRC69_PRODUCTION_METRICS_PROFILE.maxRemainderSize ||
    report.profile.maskDegree !== BRC69_PRODUCTION_METRICS_PROFILE.maskDegree ||
    report.profile.cosetOffset !== BRC69_PRODUCTION_METRICS_PROFILE.cosetOffset
  ) {
    issues.push('metrics profile does not match the production STARK profile')
  }
  return issues
}

export function assertBRC69ProductionAcceptanceGate (
  report: BRC69ProductionMetricsReport
): void {
  const issues = brc69ProductionAcceptanceIssues(report)
  if (issues.length > 0) {
    throw new Error(
      'BRC69 production acceptance gate failed: ' + issues.join('; ')
    )
  }
}

function deterministicInputs (): {
  invoiceString: string
  invoice: number[]
  scalar: bigint
  baseB: ReturnType<typeof scalarMultiply>
  sharedS: ReturnType<typeof scalarMultiply>
  key: number[]
  linkage: number[]
} {
  const prefix = 'specific linkage revelation '
  const protocolName = prefix + 'a'.repeat(430 - prefix.length)
  const keyID = 'k'.repeat(800)
  const invoiceString = computeInvoiceNumber([2, protocolName], keyID)
  const invoice = toArray(invoiceString, 'utf8')
  if (invoice.length !== 1233) {
    throw new Error('BRC69 max-invoice fixture length mismatch')
  }
  const scalar = SECP256K1_N - 123456789n
  const baseB = scalarMultiply(7n)
  const sharedS = scalarMultiply(scalar, baseB)
  const key = compressPoint(sharedS)
  const linkage = hmacSha256(key, invoice)
  return {
    invoiceString,
    invoice,
    scalar,
    baseB,
    sharedS,
    key,
    linkage
  }
}

function hmacCompactTagCounts (
  totalBlocks: number
): Record<string, number> {
  const rounds = totalBlocks * 64
  return {
    shaRound: rounds,
    shaBitBoolean: rounds * 8 * 32,
    hmacKeyByte: 33
  }
}

function actualSegment (input: {
  activeRows: number
  paddedRows: number
  width: number
  fixedRows: number
  tagCounts: Record<string, number>
  proof?: StarkProof | MultiTraceStarkProof
  proofBytes?: number
  committedCells?: number
  ldeCells?: number
  build: TimedResult<unknown>
  prove?: TimedResult<unknown>
  verify?: TimedResult<boolean>
  tableGenerationMs?: number
  tableRootMs?: number
  backend?: TypedStarkBackendBenchmarkMetrics
  diagnostic?: unknown
  verified?: boolean
  notes?: string[]
}): BRC69ProductionSegmentMetrics {
  return {
    status: 'actual',
    activeRows: input.activeRows,
    paddedRows: input.paddedRows,
    committedWidth: input.width,
    committedCells: input.committedCells ?? input.paddedRows * input.width,
    ldeRows: input.paddedRows * BRC69_PRODUCTION_METRICS_PROFILE.blowupFactor,
    ldeCells: input.ldeCells ?? input.paddedRows *
      input.width *
      BRC69_PRODUCTION_METRICS_PROFILE.blowupFactor,
    fixedPreprocessedRows: input.fixedRows,
    lookupRequestsByTag: input.tagCounts,
    proofBytes: input.proofBytes ?? (
      input.proof === undefined
        ? undefined
        : proofBytes(input.proof)
    ),
    estimatedProofBytes: input.proof === undefined && input.proofBytes === undefined
      ? estimateStarkProofBytes({
        traceLength: input.paddedRows,
        traceWidth: input.width,
        blowupFactor: BRC69_PRODUCTION_METRICS_PROFILE.blowupFactor,
        numQueries: BRC69_PRODUCTION_METRICS_PROFILE.numQueries,
        maxRemainderSize: BRC69_PRODUCTION_METRICS_PROFILE.maxRemainderSize
      })
      : undefined,
    buildMs: input.build.ms,
    proveMs: input.prove?.ms,
    verifyMs: input.verify?.ms,
    tableGenerationMs: input.tableGenerationMs,
    tableRootMs: input.tableRootMs,
    verified: input.verified,
    diagnostic: input.diagnostic,
    memory: mergeMemory(input.build, input.prove, input.verify),
    backend: input.backend,
    notes: input.notes
  }
}

function backendMetrics (
  paddedRows: number,
  width: number,
  sampleColumns: number,
  maxSampleTraceLength: number,
  now: () => number
): TypedStarkBackendBenchmarkMetrics {
  return benchmarkTypedStarkBackendShape({
    traceLength: paddedRows,
    traceWidth: width,
    blowupFactor: BRC69_PRODUCTION_METRICS_PROFILE.blowupFactor,
    cosetOffset: BRC69_PRODUCTION_METRICS_PROFILE.cosetOffset,
    numQueries: BRC69_PRODUCTION_METRICS_PROFILE.numQueries,
    maxRemainderSize: BRC69_PRODUCTION_METRICS_PROFILE.maxRemainderSize,
    sampleColumns,
    maxSampleTraceLength,
    now
  })
}

function timed<T> (
  now: () => number,
  fn: () => T,
  progress?: StarkProgressCallback,
  phase?: string,
  metricSegment?: BRC69ProductionSegmentName
): TimedResult<T> {
  const before = memorySnapshot()
  const start = now()
  emitOptionalStarkProgress(progress, phase === undefined
    ? undefined
    : {
        phase,
        status: 'start',
        metricSegment
      })
  try {
    const value = fn()
    const ms = now() - start
    const after = memorySnapshot()
    emitOptionalStarkProgress(progress, phase === undefined
      ? undefined
      : {
          phase,
          status: 'end',
          metricSegment,
          elapsedMs: ms
        })
    return {
      value,
      ms,
      memory: {
        beforeHeapUsed: before.heapUsed,
        afterHeapUsed: after.heapUsed,
        deltaHeapUsed: after.heapUsed - before.heapUsed,
        beforeRss: before.rss,
        afterRss: after.rss,
        deltaRss: after.rss - before.rss
      }
    }
  } catch (err) {
    emitOptionalStarkProgress(progress, phase === undefined
      ? undefined
      : {
          phase,
          status: 'error',
          metricSegment,
          elapsedMs: now() - start,
          error: err instanceof Error ? err.message : String(err)
        })
    throw err
  }
}

function emitOptionalStarkProgress (
  progress: StarkProgressCallback | undefined,
  event: Parameters<StarkProgressCallback>[0] | undefined
): void {
  if (event !== undefined) {
    progress?.(event)
  }
}

function memorySnapshot (): { heapUsed: number, rss: number } {
  const usage = (globalThis as unknown as {
    process?: { memoryUsage?: () => { heapUsed: number, rss: number } }
  }).process?.memoryUsage?.()
  return {
    heapUsed: usage?.heapUsed ?? 0,
    rss: usage?.rss ?? 0
  }
}

function mergeMemory (
  ...items: Array<TimedResult<unknown> | undefined>
): BRC69ProductionMemoryDelta | undefined {
  const present = items.filter(item => item !== undefined)
  if (present.length === 0) return undefined
  return {
    beforeHeapUsed: present[0].memory.beforeHeapUsed,
    afterHeapUsed: present[present.length - 1].memory.afterHeapUsed,
    deltaHeapUsed: sum(present, item => item.memory.deltaHeapUsed),
    beforeRss: present[0].memory.beforeRss,
    afterRss: present[present.length - 1].memory.afterRss,
    deltaRss: sum(present, item => item.memory.deltaRss)
  }
}

function environment (
  options: BRC69ProductionMetricsOptions
): BRC69ProductionMetricsEnvironment {
  const processLike = (globalThis as unknown as {
    process?: {
      version?: string
      platform?: string
      arch?: string
    }
  }).process
  return {
    timestamp: new Date().toISOString(),
    node: processLike?.version,
    platform: processLike?.platform,
    arch: processLike?.arch,
    cpuCount: options.cpuCount,
    gitCommit: options.gitCommit
  }
}

function proofBytes (proof: StarkProof | MultiTraceStarkProof): number {
  return 'segments' in proof
    ? serializeMultiTraceStarkProof(proof).length
    : serializeStarkProof(proof).length
}

function actualSegmentAttemptedProof (
  segment: BRC69ProductionSegmentMetrics
): boolean {
  return segment.proofBytes !== undefined ||
    segment.proveMs !== undefined ||
    segment.verifyMs !== undefined
}

function bytesEqual (left: number[], right: number[]): boolean {
  return left.length === right.length &&
    left.every((byte, index) => byte === right[index])
}

function sum<T> (items: T[], fn: (item: T) => number): number {
  return items.reduce((total, item) => total + fn(item), 0)
}

function formatMs (value: number | undefined): string {
  return value === undefined ? 'n/a' : value.toFixed(1)
}
