import PrivateKey from '../../../primitives/PrivateKey.js'
import { Writer, toArray, toHex } from '../../../primitives/utils.js'
import { WalletCounterparty, WalletProtocol } from '../../Wallet.interfaces.js'
import {
  AirDefinition,
  FieldElement,
  StarkProofDegreeBounds,
  StarkProof,
  StarkProverOptions,
  parseStarkProofWithDegreeBounds,
  serializeStarkProofWithoutDegreeBounds,
  proveStark,
  verifyStark,
  F
} from '../stark/index.js'
import {
  compressPoint,
  decompressPublicKey,
  hmacSha256,
  pointDouble,
  scalarMultiply,
  validateScalar,
  SECP256K1_G
} from '../circuit/index.js'
import { SecpPoint } from '../circuit/Types.js'
import {
  fieldLimb
} from './Method2Field.js'
import {
  METHOD2_POINT_LAYOUT,
  evaluateMethod2CompressedPointConstraints,
  evaluateMethod2PointConstraints,
  writeMethod2PointWitness
} from './Method2Point.js'
import { METHOD2_SCALAR_LAYOUT } from './Method2Scalar.js'
import {
  METHOD2_FIXED_BASE_MUL_BITS,
  Method2FixedBaseMulLayout,
  buildMethod2BaseMulTrace,
  evaluateMethod2BaseMulTransition,
  method2BaseMulPointBoundaryConstraints,
  method2BaseMulZeroBoundaryConstraints,
  method2FixedBaseMulLayout
} from './Method2FixedBaseMul.js'
import {
  evaluateMethod2HmacPlannerConstraints,
  method2HmacWitnessPlan,
  method2HmacLayout,
  writeMethod2HmacWitness
} from './Method2Hmac.js'
import {
  METHOD2_SHA256_BLOCK_LAYOUT,
  METHOD2_SHA256_INITIAL_STATE,
  METHOD2_SHA256_K,
  Method2Sha256BlockLayout,
  buildMethod2Sha256BlockTrace,
  evaluateMethod2Sha256BlockTransition,
  method2Sha256BlockLayoutAt
} from './Method2Sha256.js'
import {
  METHOD2_VM_LAYOUT,
  Method2VmBuilder,
  Method2VmProgram,
  buildMethod2VmAir
} from './Method2Vm.js'
import {
  METHOD2_VM_SCALAR_BITS,
  appendMethod2VmRegisterizedScalarMul,
  appendMethod2VmRegisterizedScalarMulHmacInput,
  fixPointRegisterCheckpointRows
} from './Method2VmScalarMul.js'
import { method2V2PublicInputDigest } from './Method2V2.js'

export const BRC97_METHOD2_STARK_DOMAIN = 'BRC97_METHOD2_STARK_V1'
export const BRC97_METHOD2_COMPOSITE_DOMAIN = 'BRC97_METHOD2_COMPOSITE_V1'
export const BRC97_METHOD2_PROOF_TYPE = 1
export const BRC97_METHOD2_PRODUCTION_PROFILE = 1
export const BRC97_METHOD2_REDUCED_TEST_PROFILE = 255

const METHOD2_COMPOSITE_MAGIC = toArray(
  BRC97_METHOD2_COMPOSITE_DOMAIN,
  'utf8'
)
const METHOD2_PRODUCTION_BLOWUP_FACTOR = 16
const METHOD2_PRODUCTION_NUM_QUERIES = 48
const METHOD2_PRODUCTION_MAX_REMAINDER_SIZE = 16
const METHOD2_PRODUCTION_MASK_DEGREE = 2
const METHOD2_PRODUCTION_COSET_OFFSET = 7n
const METHOD2_MAX_COMPOSITE_STARK_PROOF_BYTES = 512 * 1024 * 1024
const METHOD2_TEST_FIXED_BASE_BITS_MINIMUM = 1
const METHOD2_VM_TRANSITION_DEGREE = 6

export interface SpecificKeyLinkageStatement {
  prover: string
  counterparty: string
  protocolID: WalletProtocol
  keyID: string
  linkage: number[]
}

export interface CreateSpecificKeyLinkageProofArgs {
  proverPrivateKey: PrivateKey | bigint | string
  statement: SpecificKeyLinkageStatement
  starkOptions?: StarkProverOptions
  method2Options?: {
    fixedBaseMulBits?: number
    allowReducedProfile?: boolean
  }
}

export interface VerifySpecificKeyLinkageProofOptions {
  allowReducedFixedBaseMulBits?: boolean
  allowReducedProfile?: boolean
}

export interface Method2CompositeProof {
  profileId: number
  vmScalarBits: number
  publicInputDigest: number[]
  starkProof: StarkProof
}

interface Method2TraceLayout {
  mul: Method2FixedBaseMulLayout
  phase: number
  sharedPoint: number
  counterparty: number
  shared: number
  hmac: number
  hmacWidth: number
  sha: number
  shaWidth: number
  shaSelectors: number
  shaSelectorCount: number
  shaInnerBlockSelectors: number
  shaOuterBlockSelectors: number
  shaInnerDigestSelector: number
  shaOuterDigestSelector: number
  width: number
}

interface Method2HmacShaPlan {
  invoiceLength: number
  innerBlocks: number
  outerBlocks: number
  innerOutputRow: number
  outerStartRow: number
  outerOutputRow: number
  requiredRows: number
}

export type ParsedSpecificKeyLinkageProofPayload =
  | { proofType: 0 }
  | { proofType: 1, proof: Method2CompositeProof }

export function computeInvoiceNumber (
  protocolID: WalletProtocol,
  keyID: string
): string {
  const securityLevel = protocolID[0]
  if (
    !Number.isInteger(securityLevel) ||
    securityLevel < 0 ||
    securityLevel > 2
  ) {
    throw new Error('Protocol security level must be 0, 1, or 2')
  }
  const protocolName = protocolID[1].toLowerCase().trim()
  if (keyID.length > 800) {
    throw new Error('Key IDs must be 800 characters or less')
  }
  if (keyID.length < 1) {
    throw new Error('Key IDs must be 1 character or more')
  }
  if (protocolName.length > 400) {
    if (protocolName.startsWith('specific linkage revelation ')) {
      if (protocolName.length > 430) {
        throw new Error(
          'Specific linkage revelation protocol names must be 430 characters or less'
        )
      }
    } else {
      throw new Error('Protocol names must be 400 characters or less')
    }
  }
  if (protocolName.length < 5) {
    throw new Error('Protocol names must be 5 characters or more')
  }
  if (protocolName.includes('  ')) {
    throw new Error(
      'Protocol names cannot contain multiple consecutive spaces ("  ")'
    )
  }
  if (!/^[a-z0-9 ]+$/g.test(protocolName)) {
    throw new Error(
      'Protocol names can only contain letters, numbers and spaces'
    )
  }
  if (protocolName.endsWith(' protocol')) {
    throw new Error('No need to end your protocol name with " protocol"')
  }
  return `${securityLevel}-${protocolName}-${keyID}`
}

export function normalizeSpecificKeyLinkageCounterparty (
  counterparty: WalletCounterparty,
  prover: string
): string {
  if (counterparty === 'self') return prover
  if (counterparty === 'anyone') return toHex(compressPoint(SECP256K1_G))
  assertCompressedPublicKeyHex(counterparty, 'counterparty')
  return counterparty
}

export function createSpecificKeyLinkageProof (
  args: CreateSpecificKeyLinkageProofArgs
): Method2CompositeProof {
  const statement = normalizeStatement(args.statement)
  const scalar = privateKeyToScalar(args.proverPrivateKey)
  validateScalar(scalar)

  const proverPoint = scalarMultiply(scalar)
  if (toHex(compressPoint(proverPoint)) !== statement.prover) {
    throw new Error('Prover private key does not match public prover key')
  }

  const counterpartyPoint = decompressPublicKey(toArray(statement.counterparty, 'hex'))
  const sharedPoint = scalarMultiply(scalar, counterpartyPoint)
  const encodedShared = compressPoint(sharedPoint)
  const invoiceBytes = toArray(
    computeInvoiceNumber(statement.protocolID, statement.keyID),
    'utf8'
  )
  const expectedLinkage = hmacSha256(encodedShared, invoiceBytes)
  if (!bytesEqual(expectedLinkage, statement.linkage)) {
    throw new Error('Linkage does not match Method 2 witness relation')
  }

  const vmScalarBits = args.method2Options?.fixedBaseMulBits ??
    METHOD2_VM_SCALAR_BITS
  const publicInputDigest = method2PublicInputDigest(statement)
  const program = buildMethod2VmProverProgram(
    scalar,
    proverPoint,
    counterpartyPoint,
    invoiceBytes,
    statement.linkage,
    vmScalarBits,
    publicInputDigest
  )
  const starkProof = proveStark(buildMethod2VmAir(program), program.trace.rows, {
    ...(args.starkOptions ?? {}),
    publicInputDigest,
    transcriptDomain: BRC97_METHOD2_STARK_DOMAIN
  })
  return {
    profileId: method2ProfileIdForProof(
      starkProof,
      vmScalarBits,
      args.method2Options?.allowReducedProfile === true
    ),
    vmScalarBits,
    publicInputDigest,
    starkProof
  }
}

export function verifySpecificKeyLinkageProof (
  statement: SpecificKeyLinkageStatement,
  payload: number[] | Method2CompositeProof,
  options: VerifySpecificKeyLinkageProofOptions = {}
): boolean {
  try {
    const normalized = normalizeStatement(statement)
    const parsed = Array.isArray(payload)
      ? parseSpecificKeyLinkageProofPayload(payload)
      : { proofType: 1 as const, proof: payload }
    if (parsed.proofType !== 1) return false
    const proof = parsed.proof.starkProof
    const expectedPublicInputDigest = method2PublicInputDigest(normalized)
    if (!bytesEqual(parsed.proof.publicInputDigest, expectedPublicInputDigest)) {
      return false
    }
    if (!bytesEqual(parsed.proof.publicInputDigest, proof.publicInputDigest)) {
      return false
    }
    if (!method2ProfileAccepted(parsed.proof, options)) return false
    const invoiceBytes = toArray(
      computeInvoiceNumber(normalized.protocolID, normalized.keyID),
      'utf8'
    )
    if (proof.traceWidth !== METHOD2_VM_LAYOUT.width) return false
    const vmScalarBits = parsed.proof.vmScalarBits
    if (
      vmScalarBits !== METHOD2_VM_SCALAR_BITS &&
      options.allowReducedFixedBaseMulBits !== true
    ) {
      return false
    }
    const program = buildMethod2VmVerifierProgram(
      normalized,
      invoiceBytes,
      vmScalarBits,
      expectedPublicInputDigest
    )
    if (program.trace.rows.length !== proof.traceLength) return false
    const degreeBounds = method2StarkDegreeBounds(
      proof.traceLength,
      proof.blowupFactor,
      proof.maskDegree
    )
    return verifyStark(buildMethod2VmAir(program), proof, {
      blowupFactor: proof.blowupFactor,
      numQueries: proof.numQueries,
      maxRemainderSize: proof.maxRemainderSize,
      maskDegree: proof.maskDegree,
      traceDegreeBound: degreeBounds.traceDegreeBound,
      compositionDegreeBound: degreeBounds.compositionDegreeBound,
      cosetOffset: proof.cosetOffset,
      publicInputDigest: expectedPublicInputDigest,
      transcriptDomain: BRC97_METHOD2_STARK_DOMAIN
    })
  } catch {
    return false
  }
}

export function serializeSpecificKeyLinkageProofPayload (
  proof: Method2CompositeProof
): number[] {
  return [
    BRC97_METHOD2_PROOF_TYPE,
    ...serializeMethod2CompositeProof(proof)
  ]
}

export function parseSpecificKeyLinkageProofPayload (
  payload: number[]
): ParsedSpecificKeyLinkageProofPayload {
  assertBytes(payload, 'proof payload')
  if (payload.length < 1) throw new Error('Proof payload is empty')
  const proofType = payload[0]
  if (proofType === 0) {
    if (payload.length !== 1) {
      throw new Error('Proof type 0 payload must not contain proof bytes')
    }
    return { proofType: 0 }
  }
  if (proofType !== BRC97_METHOD2_PROOF_TYPE) {
    throw new Error('Unsupported BRC-97 proof type')
  }
  return {
    proofType: 1,
    proof: parseMethod2CompositeProof(payload.slice(1))
  }
}

export function serializeMethod2CompositeProof (
  proof: Method2CompositeProof
): number[] {
  assertMethod2CompositeProofShape(proof)
  const starkProof = serializeStarkProofWithoutDegreeBounds(proof.starkProof)
  const writer = new Writer()
  writer.write(METHOD2_COMPOSITE_MAGIC)
  writer.writeUInt8(proof.profileId)
  writer.writeVarIntNum(proof.vmScalarBits)
  writer.write(proof.publicInputDigest)
  writer.writeVarIntNum(starkProof.length)
  writer.write(starkProof)
  return writer.toArray()
}

export function parseMethod2CompositeProof (
  bytes: number[]
): Method2CompositeProof {
  assertBytes(bytes, 'Method 2 composite proof')
  const reader = new Method2CompositeReader(bytes)
  const magic = reader.read(METHOD2_COMPOSITE_MAGIC.length)
  if (!bytesEqual(magic, METHOD2_COMPOSITE_MAGIC)) {
    throw new Error('Invalid Method 2 composite proof magic')
  }
  const profileId = reader.readUInt8()
  if (
    profileId !== BRC97_METHOD2_PRODUCTION_PROFILE &&
    profileId !== BRC97_METHOD2_REDUCED_TEST_PROFILE
  ) {
    throw new Error('Unsupported Method 2 proof profile')
  }
  const vmScalarBits = reader.readVarIntNum()
  const publicInputDigest = reader.read(32)
  const starkProofLength = reader.readVarIntNum()
  if (starkProofLength > METHOD2_MAX_COMPOSITE_STARK_PROOF_BYTES) {
    throw new Error('Method 2 STARK proof is too large')
  }
  const starkProofBytes = reader.read(starkProofLength)
  const starkMetadata = parseMethod2StarkProofMetadata(starkProofBytes)
  const starkProof = parseStarkProofWithDegreeBounds(
    starkProofBytes,
    method2StarkDegreeBounds(
      starkMetadata.traceLength,
      starkMetadata.blowupFactor,
      starkMetadata.maskDegree
    )
  )
  if (!reader.eof()) {
    throw new Error('Unexpected trailing bytes in Method 2 proof payload')
  }
  const proof = {
    profileId,
    vmScalarBits,
    publicInputDigest,
    starkProof
  }
  assertMethod2CompositeProofShape(proof)
  return proof
}

export function method2PublicInputDigest (
  statement: SpecificKeyLinkageStatement
): number[] {
  const normalized = normalizeStatement(statement)
  const invoiceBytes = toArray(
    computeInvoiceNumber(normalized.protocolID, normalized.keyID),
    'utf8'
  )
  return method2V2PublicInputDigest(normalized, invoiceBytes)
}

function method2ProfileIdForProof (
  proof: StarkProof,
  vmScalarBits: number,
  allowReducedProfile: boolean
): number {
  if (
    vmScalarBits === METHOD2_VM_SCALAR_BITS &&
    method2ProofHasProductionParameters(proof)
  ) {
    return BRC97_METHOD2_PRODUCTION_PROFILE
  }
  if (allowReducedProfile) return BRC97_METHOD2_REDUCED_TEST_PROFILE
  throw new Error('Method 2 proof does not satisfy the production profile')
}

function method2ProfileAccepted (
  proof: Method2CompositeProof,
  options: VerifySpecificKeyLinkageProofOptions
): boolean {
  if (proof.profileId === BRC97_METHOD2_PRODUCTION_PROFILE) {
    return method2ProofHasProductionParameters(proof.starkProof)
  }
  if (proof.profileId === BRC97_METHOD2_REDUCED_TEST_PROFILE) {
    return options.allowReducedProfile === true ||
      options.allowReducedFixedBaseMulBits === true
  }
  return false
}

function method2ProofHasProductionParameters (proof: StarkProof): boolean {
  const degreeBounds = method2StarkDegreeBounds(
    proof.traceLength,
    proof.blowupFactor,
    proof.maskDegree
  )
  return proof.blowupFactor >= METHOD2_PRODUCTION_BLOWUP_FACTOR &&
    proof.numQueries >= METHOD2_PRODUCTION_NUM_QUERIES &&
    proof.maxRemainderSize <= METHOD2_PRODUCTION_MAX_REMAINDER_SIZE &&
    proof.maskDegree >= METHOD2_PRODUCTION_MASK_DEGREE &&
    proof.cosetOffset === METHOD2_PRODUCTION_COSET_OFFSET &&
    proof.traceDegreeBound === degreeBounds.traceDegreeBound &&
    proof.compositionDegreeBound === degreeBounds.compositionDegreeBound
}

function method2StarkDegreeBounds (
  traceLength: number,
  blowupFactor: number,
  maskDegree: number
): StarkProofDegreeBounds {
  const ldeSize = traceLength * blowupFactor
  const traceDegreeBound = traceLength + maskDegree
  const transitionNumeratorBound = Math.max(
    1,
    METHOD2_VM_TRANSITION_DEGREE * traceDegreeBound
  )
  const transitionQuotientBound = Math.max(
    1,
    transitionNumeratorBound - traceLength + 1
  )
  return {
    traceDegreeBound,
    compositionDegreeBound: Math.min(
      ldeSize - 1,
      Math.max(transitionQuotientBound, traceDegreeBound) + 8
    )
  }
}

function parseMethod2StarkProofMetadata (bytes: number[]): {
  traceLength: number
  blowupFactor: number
  maskDegree: number
} {
  const reader = new Method2CompositeReader(bytes)
  const traceLength = reader.readVarIntNum()
  reader.readVarIntNum() // traceWidth
  const blowupFactor = reader.readVarIntNum()
  reader.readVarIntNum() // numQueries
  reader.readVarIntNum() // maxRemainderSize
  const maskDegree = reader.readVarIntNum()
  return { traceLength, blowupFactor, maskDegree }
}

function assertMethod2CompositeProofShape (
  proof: Method2CompositeProof
): void {
  if (
    proof.profileId !== BRC97_METHOD2_PRODUCTION_PROFILE &&
    proof.profileId !== BRC97_METHOD2_REDUCED_TEST_PROFILE
  ) {
    throw new Error('Unsupported Method 2 proof profile')
  }
  if (
    !Number.isInteger(proof.vmScalarBits) ||
    proof.vmScalarBits < 1 ||
    proof.vmScalarBits > METHOD2_VM_SCALAR_BITS
  ) {
    throw new Error('Method 2 VM scalar-bit count is out of range')
  }
  assertBytes(proof.publicInputDigest, 'Method 2 public input digest')
  if (proof.publicInputDigest.length !== 32) {
    throw new Error('Method 2 public input digest must be 32 bytes')
  }
  if (!bytesEqual(proof.publicInputDigest, proof.starkProof.publicInputDigest)) {
    throw new Error('Method 2 composite proof digest mismatch')
  }
  const degreeBounds = method2StarkDegreeBounds(
    proof.starkProof.traceLength,
    proof.starkProof.blowupFactor,
    proof.starkProof.maskDegree
  )
  if (
    proof.starkProof.traceDegreeBound !== degreeBounds.traceDegreeBound ||
    proof.starkProof.compositionDegreeBound !==
      degreeBounds.compositionDegreeBound
  ) {
    throw new Error('Method 2 proof degree bounds are invalid')
  }
}

function buildMethod2VmProverProgram (
  scalar: bigint,
  proverPoint: SecpPoint,
  counterpartyPoint: SecpPoint,
  invoiceBytes: number[],
  linkage: number[],
  vmScalarBits: number,
  publicInputDigest: number[]
): Method2VmProgram {
  const builder = new Method2VmBuilder()
  const fixedBase = appendMethod2VmRegisterizedScalarMul(
    builder,
    scalar,
    SECP256K1_G,
    vmScalarBits,
    proverPoint
  )
  fixPointRegisterCheckpointRows(
    builder,
    fixedBase.baseCheckpointStart,
    SECP256K1_G
  )
  const variableBase = appendMethod2VmRegisterizedScalarMulHmacInput(
    builder,
    scalar,
    counterpartyPoint,
    invoiceBytes,
    linkage,
    vmScalarBits
  )
  fixPointRegisterCheckpointRows(
    builder,
    variableBase.scalarMul.baseCheckpointStart,
    counterpartyPoint
  )
  return builder.build(publicInputDigest)
}

function buildMethod2VmVerifierProgram (
  statement: SpecificKeyLinkageStatement,
  invoiceBytes: number[],
  vmScalarBits: number,
  publicInputDigest: number[]
): Method2VmProgram {
  const normalized = normalizeStatement(statement)
  const proverPoint = decompressPublicKey(toArray(normalized.prover, 'hex'))
  const counterpartyPoint = decompressPublicKey(toArray(
    normalized.counterparty,
    'hex'
  ))
  const builder = new Method2VmBuilder()
  const fixedBase = appendMethod2VmRegisterizedScalarMul(
    builder,
    1n,
    SECP256K1_G,
    vmScalarBits,
    proverPoint
  )
  fixPointRegisterCheckpointRows(
    builder,
    fixedBase.baseCheckpointStart,
    SECP256K1_G
  )
  const variableBase = appendMethod2VmRegisterizedScalarMulHmacInput(
    builder,
    1n,
    counterpartyPoint,
    invoiceBytes,
    normalized.linkage,
    vmScalarBits,
    false
  )
  fixPointRegisterCheckpointRows(
    builder,
    variableBase.scalarMul.baseCheckpointStart,
    counterpartyPoint
  )
  return builder.build(publicInputDigest)
}

export function buildMethod2Air (
  statement: SpecificKeyLinkageStatement,
  fixedBaseMulBits = METHOD2_FIXED_BASE_MUL_BITS
): AirDefinition {
  const normalized = normalizeStatement(statement)
  const proverPoint = decompressPublicKey(toArray(normalized.prover, 'hex'))
  const counterpartyPoint = decompressPublicKey(toArray(normalized.counterparty, 'hex'))
  const counterpartyBytes = toArray(normalized.counterparty, 'hex')
  const invoiceBytes = toArray(
    computeInvoiceNumber(normalized.protocolID, normalized.keyID),
    'utf8'
  )
  const layout = method2TraceLayout(fixedBaseMulBits, invoiceBytes.length)
  const hmacShaPlan = method2HmacShaPlan(invoiceBytes.length)
  const traceLength = method2TraceLength(fixedBaseMulBits, invoiceBytes.length)
  const mul = layout.mul
  const firstPaddingRow = fixedBaseMulBits * 2
  const shaLayout = method2Sha256BlockLayoutAt(layout.sha)
  return {
    traceWidth: layout.width,
    transitionDegree: 7,
    publicInputDigest: method2PublicInputDigest(normalized),
    boundaryConstraints: [
      ...method2BaseSegmentBoundaryConstraints(
        0,
        mul,
        SECP256K1_G
      ),
      ...method2BaseSegmentBoundaryConstraints(
        fixedBaseMulBits,
        mul,
        counterpartyPoint
      ),
      ...method2BaseMulPointBoundaryConstraints(
        fixedBaseMulBits - 1,
        mul.output,
        proverPoint
      ),
      { column: layout.phase, row: 0, value: 0n },
      { column: layout.phase, row: fixedBaseMulBits, value: 1n },
      { column: layout.phase, row: firstPaddingRow, value: 0n },
      ...method2BaseMulZeroBoundaryConstraints(
        firstPaddingRow,
        mul.bitSelectors,
        fixedBaseMulBits
      ),
      ...byteBoundaryConstraints(layout.counterparty, counterpartyBytes),
      ...method2HmacShaBoundaryConstraints(
        layout,
        shaLayout,
        hmacShaPlan,
        traceLength
      )
    ],
    evaluateTransition: (current, next) => {
      const constraints = evaluateMethod2BaseMulTransition(current, next, mul)
      const lastSelector = current[mul.bitSelectors + mul.activeBits - 1]
      const resetSelector = F.mul(lastSelector, next[mul.bitSelectors])
      const nextActive = method2SelectorSum(next, mul)
      const continueSelector = F.sub(nextActive, resetSelector)

      constraints.push(booleanConstraint(current[layout.phase]))
      constraints.push(F.mul(
        continueSelector,
        F.sub(next[layout.phase], current[layout.phase])
      ))
      constraints.push(F.mul(
        resetSelector,
        F.sub(next[layout.phase], F.add(current[layout.phase], 1n))
      ))
      constraints.push(...copyRangeConstraints(
        current,
        layout.sharedPoint,
        next,
        layout.sharedPoint,
        METHOD2_POINT_LAYOUT.width
      ))
      constraints.push(...copyRangeConstraints(
        current,
        layout.counterparty,
        next,
        layout.counterparty,
        33
      ))
      constraints.push(...copyRangeConstraints(
        current,
        layout.shared,
        next,
        layout.shared,
        33
      ))
      constraints.push(...copyRangeConstraints(
        current,
        layout.hmac,
        next,
        layout.hmac,
        layout.hmacWidth
      ))
      constraints.push(...evaluateMethod2PointConstraints(
        current,
        layout.sharedPoint
      ))
      constraints.push(...evaluateMethod2CompressedPointConstraints(
        current,
        layout.sharedPoint,
        layout.shared
      ))
      constraints.push(...evaluateMethod2HmacPlannerConstraints(
        current,
        layout.hmac,
        layout.shared,
        invoiceBytes,
        normalized.linkage
      ))
      constraints.push(...evaluateMethod2Sha256BlockTransition(
        current,
        next,
        shaLayout
      ))
      constraints.push(...evaluateMethod2HmacShaLinkConstraints(
        current,
        layout,
        shaLayout,
        hmacShaPlan
      ))
      constraints.push(...gateConstraints(
        pointEqualityConstraints(
          current,
          mul.output,
          current,
          layout.sharedPoint
        ),
        F.mul(current[layout.phase], lastSelector)
      ))
      return constraints
    }
  }
}

export function buildMethod2Trace (
  scalar: bigint,
  counterpartyPoint: SecpPoint,
  counterparty: number[],
  shared: number[],
  invoiceBytes: number[],
  linkage: number[],
  fixedBaseMulBits = METHOD2_FIXED_BASE_MUL_BITS
): FieldElement[][] {
  const fixedBaseTrace = buildMethod2BaseMulTrace(
    scalar,
    SECP256K1_G,
    fixedBaseMulBits
  )
  const variableBaseTrace = buildMethod2BaseMulTrace(
    scalar,
    counterpartyPoint,
    fixedBaseMulBits
  )
  if (!bytesEqual(compressPoint(variableBaseTrace.output), shared)) {
    throw new Error('Shared secret witness does not match variable-base scalar multiplication')
  }
  const layout = method2TraceLayout(fixedBaseMulBits, invoiceBytes.length)
  const hmacShaPlan = method2HmacShaPlan(invoiceBytes.length)
  const traceLength = method2TraceLength(fixedBaseMulBits, invoiceBytes.length)
  const traceRows = new Array<FieldElement[]>(traceLength)
    .fill([])
    .map(() => new Array<FieldElement>(layout.width).fill(0n))

  for (let rowIndex = 0; rowIndex < traceRows.length; rowIndex++) {
    const row = traceRows[rowIndex]
    writeMethod2PointWitness(row, layout.sharedPoint, variableBaseTrace.output)
    writeNumbers(row, layout.counterparty, counterparty)
    writeNumbers(row, layout.shared, shared)
    writeMethod2HmacWitness(
      row,
      layout.hmac,
      shared,
      invoiceBytes,
      linkage
    )
  }
  writeMethod2HmacShaTrace(
    traceRows,
    layout,
    hmacShaPlan,
    shared,
    invoiceBytes,
    linkage
  )

  for (let bit = 0; bit < fixedBaseMulBits; bit++) {
    const fixedRow = traceRows[bit]
    const variableRow = traceRows[fixedBaseMulBits + bit]
    for (let i = 0; i < layout.mul.width; i++) {
      fixedRow[i] = fixedBaseTrace.traceRows[bit][i]
      variableRow[i] = variableBaseTrace.traceRows[bit][i]
    }
    fixedRow[layout.phase] = 0n
    variableRow[layout.phase] = 1n
  }

  return traceRows
}

function method2TraceLayout (
  fixedBaseMulBits = METHOD2_FIXED_BASE_MUL_BITS,
  invoiceLength = maxMethod2InvoiceLength()
): Method2TraceLayout {
  const mul = method2FixedBaseMulLayout(fixedBaseMulBits)
  const phase = mul.width
  const sharedPoint = phase + 1
  const counterparty = sharedPoint + METHOD2_POINT_LAYOUT.width
  const shared = counterparty + 33
  const hmac = shared + 33
  const hmacWidth = method2HmacLayout(invoiceLength).width
  const hmacShaPlan = method2HmacShaPlan(invoiceLength)
  const sha = hmac + hmacWidth
  const shaWidth = METHOD2_SHA256_BLOCK_LAYOUT.width
  const shaSelectors = sha + shaWidth
  const shaInnerBlockSelectors = shaSelectors
  const shaOuterBlockSelectors = shaInnerBlockSelectors +
    hmacShaPlan.innerBlocks
  const shaInnerDigestSelector = shaOuterBlockSelectors +
    hmacShaPlan.outerBlocks
  const shaOuterDigestSelector = shaInnerDigestSelector + 1
  const shaSelectorCount = hmacShaPlan.innerBlocks +
    hmacShaPlan.outerBlocks +
    2
  return {
    mul,
    phase,
    sharedPoint,
    counterparty,
    shared,
    hmac,
    hmacWidth,
    sha,
    shaWidth,
    shaSelectors,
    shaSelectorCount,
    shaInnerBlockSelectors,
    shaOuterBlockSelectors,
    shaInnerDigestSelector,
    shaOuterDigestSelector,
    width: shaSelectors + shaSelectorCount
  }
}

export function fixedBaseMulBitsFromTraceWidth (
  traceWidth: number,
  invoiceLength = maxMethod2InvoiceLength()
): number {
  for (
    let bits = METHOD2_TEST_FIXED_BASE_BITS_MINIMUM;
    bits <= METHOD2_FIXED_BASE_MUL_BITS;
    bits++
  ) {
    if (method2TraceLayout(bits, invoiceLength).width === traceWidth) return bits
  }
  throw new Error('Method 2 proof trace width does not match supported layout')
}

function maxMethod2InvoiceLength (): number {
  return computeInvoiceNumber([
    0,
    `specific linkage revelation ${'a'.repeat(402)}`
  ], 'a'.repeat(800)).length
}

function method2TraceLength (
  fixedBaseMulBits: number,
  invoiceLength: number
): number {
  return nextPowerOfTwo(Math.max(
    fixedBaseMulBits * 2 + 1,
    method2HmacShaPlan(invoiceLength).requiredRows
  ))
}

function method2HmacShaPlan (invoiceLength: number): Method2HmacShaPlan {
  const hmacLayout = method2HmacLayout(invoiceLength)
  const innerBlocks = hmacLayout.innerMessageLength / 64
  const outerBlocks = hmacLayout.outerMessageLength / 64
  if (!Number.isInteger(innerBlocks) || !Number.isInteger(outerBlocks)) {
    throw new Error('Method 2 HMAC SHA message length is not block aligned')
  }
  const innerOutputRow = innerBlocks * 64
  const outerStartRow = innerOutputRow + 1
  const outerOutputRow = outerStartRow + outerBlocks * 64
  return {
    invoiceLength,
    innerBlocks,
    outerBlocks,
    innerOutputRow,
    outerStartRow,
    outerOutputRow,
    requiredRows: outerOutputRow + 2
  }
}

function method2HmacShaBoundaryConstraints (
  layout: Method2TraceLayout,
  shaLayout: Method2Sha256BlockLayout,
  plan: Method2HmacShaPlan,
  traceLength: number
): Array<{ column: number, row: number, value: FieldElement }> {
  const constraints: Array<{ column: number, row: number, value: FieldElement }> = []
  appendShaBlockControlBoundaryConstraints(
    constraints,
    shaLayout,
    0,
    plan.innerBlocks
  )
  appendShaBlockControlBoundaryConstraints(
    constraints,
    shaLayout,
    plan.outerStartRow,
    plan.outerBlocks
  )
  constraints.push(...shaControlBoundaryConstraints(
    shaLayout,
    plan.innerOutputRow,
    0,
    0,
    0
  ))
  constraints.push(...shaControlBoundaryConstraints(
    shaLayout,
    plan.outerOutputRow,
    0,
    0,
    0
  ))
  constraints.push(...shaControlBoundaryConstraints(
    shaLayout,
    plan.requiredRows - 1,
    0,
    0,
    0
  ))
  constraints.push(...shaWordBoundaryConstraints(
    0,
    shaLayout.state,
    METHOD2_SHA256_INITIAL_STATE
  ))
  constraints.push(...shaWordBoundaryConstraints(
    0,
    shaLayout.chain,
    METHOD2_SHA256_INITIAL_STATE
  ))
  constraints.push(...shaWordBoundaryConstraints(
    plan.outerStartRow,
    shaLayout.state,
    METHOD2_SHA256_INITIAL_STATE
  ))
  constraints.push(...shaWordBoundaryConstraints(
    plan.outerStartRow,
    shaLayout.chain,
    METHOD2_SHA256_INITIAL_STATE
  ))
  for (let block = 0; block < plan.innerBlocks; block++) {
    constraints.push({
      column: layout.shaInnerBlockSelectors + block,
      row: block * 64,
      value: 1n
    })
  }
  for (let block = 0; block < plan.outerBlocks; block++) {
    constraints.push({
      column: layout.shaOuterBlockSelectors + block,
      row: plan.outerStartRow + block * 64,
      value: 1n
    })
  }
  constraints.push({
    column: layout.shaInnerDigestSelector,
    row: plan.innerOutputRow,
    value: 1n
  })
  constraints.push({
    column: layout.shaOuterDigestSelector,
    row: plan.outerOutputRow,
    value: 1n
  })
  for (let row = plan.requiredRows - 1; row < traceLength; row++) {
    constraints.push(...shaControlBoundaryConstraints(
      shaLayout,
      row,
      0,
      0,
      0
    ))
  }
  for (let row = 0; row < traceLength; row++) {
    for (let selector = 0; selector < layout.shaSelectorCount; selector++) {
      constraints.push({
        column: layout.shaSelectors + selector,
        row,
        value: expectedHmacShaSelector(layout, plan, row, selector)
      })
    }
  }
  return constraints
}

function expectedHmacShaSelector (
  layout: Method2TraceLayout,
  plan: Method2HmacShaPlan,
  row: number,
  selector: number
): FieldElement {
  const column = layout.shaSelectors + selector
  if (
    column >= layout.shaInnerBlockSelectors &&
    column < layout.shaInnerBlockSelectors + plan.innerBlocks
  ) {
    const block = column - layout.shaInnerBlockSelectors
    return row === block * 64 ? 1n : 0n
  }
  if (
    column >= layout.shaOuterBlockSelectors &&
    column < layout.shaOuterBlockSelectors + plan.outerBlocks
  ) {
    const block = column - layout.shaOuterBlockSelectors
    return row === plan.outerStartRow + block * 64 ? 1n : 0n
  }
  if (column === layout.shaInnerDigestSelector) {
    return row === plan.innerOutputRow ? 1n : 0n
  }
  if (column === layout.shaOuterDigestSelector) {
    return row === plan.outerOutputRow ? 1n : 0n
  }
  return 0n
}

function appendShaBlockControlBoundaryConstraints (
  constraints: Array<{ column: number, row: number, value: FieldElement }>,
  layout: Method2Sha256BlockLayout,
  rowOffset: number,
  blockCount: number
): void {
  for (let block = 0; block < blockCount; block++) {
    const blockOffset = rowOffset + block * 64
    for (let round = 0; round < 64; round++) {
      const row = blockOffset + round
      constraints.push(...shaControlBoundaryConstraints(
        layout,
        row,
        1,
        round < 48 ? 1 : 0,
        round === 63 ? 1 : 0
      ))
      constraints.push(...shaWordBoundaryConstraints(
        row,
        layout.k,
        [METHOD2_SHA256_K[round]]
      ))
    }
  }
}

function shaControlBoundaryConstraints (
  layout: Method2Sha256BlockLayout,
  row: number,
  active: number,
  scheduleActive: number,
  last: number
): Array<{ column: number, row: number, value: FieldElement }> {
  return [
    { column: layout.active, row, value: BigInt(active) },
    { column: layout.scheduleActive, row, value: BigInt(scheduleActive) },
    { column: layout.last, row, value: BigInt(last) }
  ]
}

function shaWordBoundaryConstraints (
  row: number,
  offset: number,
  words: number[]
): Array<{ column: number, row: number, value: FieldElement }> {
  const constraints: Array<{ column: number, row: number, value: FieldElement }> = []
  for (let word = 0; word < words.length; word++) {
    for (let bit = 0; bit < 32; bit++) {
      constraints.push({
        column: offset + word * 32 + bit,
        row,
        value: BigInt((words[word] >>> bit) & 1)
      })
    }
  }
  return constraints
}

function evaluateMethod2HmacShaLinkConstraints (
  row: FieldElement[],
  layout: Method2TraceLayout,
  shaLayout: Method2Sha256BlockLayout,
  plan: Method2HmacShaPlan
): FieldElement[] {
  const constraints: FieldElement[] = []
  const hmacLayout = method2HmacLayoutFromShaPlan(plan)
  for (let i = 0; i < layout.shaSelectorCount; i++) {
    constraints.push(booleanConstraint(row[layout.shaSelectors + i]))
  }
  for (let block = 0; block < plan.innerBlocks; block++) {
    const selector = row[layout.shaInnerBlockSelectors + block]
    constraints.push(...gateConstraints(
      shaMessageBlockConstraints(
        row,
        shaLayout,
        layout.hmac + hmacLayout.innerMessage + block * 64
      ),
      selector
    ))
  }
  for (let block = 0; block < plan.outerBlocks; block++) {
    const selector = row[layout.shaOuterBlockSelectors + block]
    constraints.push(...gateConstraints(
      shaMessageBlockConstraints(
        row,
        shaLayout,
        layout.hmac + hmacLayout.outerMessage + block * 64
      ),
      selector
    ))
  }
  constraints.push(...gateConstraints(
    shaDigestConstraints(row, shaLayout, layout.hmac + hmacLayout.innerDigest),
    row[layout.shaInnerDigestSelector]
  ))
  constraints.push(...gateConstraints(
    shaDigestConstraints(row, shaLayout, layout.hmac + hmacLayout.linkage),
    row[layout.shaOuterDigestSelector]
  ))
  return constraints
}

function method2HmacLayoutFromShaPlan (
  plan: Method2HmacShaPlan
): ReturnType<typeof method2HmacLayout> {
  return method2HmacLayout(plan.invoiceLength)
}

function shaMessageBlockConstraints (
  row: FieldElement[],
  layout: Method2Sha256BlockLayout,
  messageOffset: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  for (let byte = 0; byte < 64; byte++) {
    constraints.push(F.sub(
      shaWordByte(row, layout.schedule, byte),
      row[messageOffset + byte]
    ))
  }
  return constraints
}

function shaDigestConstraints (
  row: FieldElement[],
  layout: Method2Sha256BlockLayout,
  digestOffset: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  for (let byte = 0; byte < 32; byte++) {
    constraints.push(F.sub(
      shaWordByte(row, layout.state, byte),
      row[digestOffset + byte]
    ))
  }
  return constraints
}

function shaWordByte (
  row: FieldElement[],
  wordsOffset: number,
  byteIndex: number
): FieldElement {
  const word = Math.floor(byteIndex / 4)
  const byteInWord = byteIndex % 4
  const bitOffset = wordsOffset + word * 32 + (3 - byteInWord) * 8
  let value = 0n
  for (let bit = 0; bit < 8; bit++) {
    value = F.add(value, F.mul(row[bitOffset + bit], BigInt(1 << bit)))
  }
  return value
}

function writeMethod2HmacShaTrace (
  traceRows: FieldElement[][],
  layout: Method2TraceLayout,
  plan: Method2HmacShaPlan,
  shared: number[],
  invoiceBytes: number[],
  linkage: number[]
): void {
  const hmacPlan = method2HmacWitnessPlan(shared, invoiceBytes, linkage)
  writeMethod2ShaBlocks(
    traceRows,
    layout.sha,
    0,
    hmacPlan.innerMessage
  )
  traceRows[plan.innerOutputRow][layout.shaInnerDigestSelector] = 1n
  writeMethod2ShaBlocks(
    traceRows,
    layout.sha,
    plan.outerStartRow,
    hmacPlan.outerMessage
  )
  traceRows[plan.outerOutputRow][layout.shaOuterDigestSelector] = 1n
  for (let block = 0; block < plan.innerBlocks; block++) {
    traceRows[block * 64][layout.shaInnerBlockSelectors + block] = 1n
  }
  for (let block = 0; block < plan.outerBlocks; block++) {
    traceRows[plan.outerStartRow + block * 64][
      layout.shaOuterBlockSelectors + block
    ] = 1n
  }
}

function writeMethod2ShaBlocks (
  traceRows: FieldElement[][],
  shaOffset: number,
  rowOffset: number,
  message: number[]
): void {
  let state = METHOD2_SHA256_INITIAL_STATE.slice()
  const blockCount = message.length / 64
  if (!Number.isInteger(blockCount)) {
    throw new Error('Method 2 SHA message length is not block aligned')
  }
  for (let block = 0; block < blockCount; block++) {
    const blockBytes = message.slice(block * 64, block * 64 + 64)
    const blockTrace = buildMethod2Sha256BlockTrace(state, blockBytes)
    for (let round = 0; round < 64; round++) {
      writeMethod2ShaRow(
        traceRows[rowOffset + block * 64 + round],
        shaOffset,
        blockTrace.traceRows[round]
      )
    }
    state = blockTrace.outputState
    if (block === blockCount - 1) {
      writeMethod2ShaRow(
        traceRows[rowOffset + (block + 1) * 64],
        shaOffset,
        blockTrace.traceRows[64]
      )
    }
  }
}

function writeMethod2ShaRow (
  row: FieldElement[],
  offset: number,
  shaRow: FieldElement[]
): void {
  for (let i = 0; i < METHOD2_SHA256_BLOCK_LAYOUT.width; i++) {
    row[offset + i] = shaRow[i]
  }
}

function method2BaseSegmentBoundaryConstraints (
  rowOffset: number,
  layout: Method2FixedBaseMulLayout,
  basePoint: SecpPoint
): Array<{ column: number, row: number, value: FieldElement }> {
  const constraints: Array<{ column: number, row: number, value: FieldElement }> = [
    ...method2BaseMulPointBoundaryConstraints(
      rowOffset,
      layout.left,
      basePoint
    ),
    { column: layout.bitSelectors, row: rowOffset, value: 1n },
    { column: layout.borrowIn, row: rowOffset, value: 1n },
    { column: layout.borrowOut, row: rowOffset + layout.activeBits - 1, value: 0n },
    ...method2BaseMulZeroBoundaryConstraints(
      rowOffset,
      layout.bitSelectors + 1,
      layout.activeBits - 1
    ),
    ...method2BaseMulZeroBoundaryConstraints(
      rowOffset,
      layout.scalar + METHOD2_SCALAR_LAYOUT.bits + layout.activeBits,
      256 - layout.activeBits
    )
  ]
  let base = basePoint
  for (let bit = 0; bit < layout.activeBits; bit++) {
    constraints.push(...method2BaseMulPointBoundaryConstraints(
      rowOffset + bit,
      layout.right,
      base
    ))
    base = pointDouble(base)
  }
  return constraints
}

function method2SelectorSum (
  row: FieldElement[],
  layout: Method2FixedBaseMulLayout
): FieldElement {
  let sum = 0n
  for (let bit = 0; bit < layout.activeBits; bit++) {
    sum = F.add(sum, row[layout.bitSelectors + bit])
  }
  return sum
}

function pointEqualityConstraints (
  leftRow: FieldElement[],
  leftOffset: number,
  rightRow: FieldElement[],
  rightOffset: number
): FieldElement[] {
  return [
    ...fieldEqualityConstraints(
      leftRow,
      leftOffset + METHOD2_POINT_LAYOUT.x,
      rightRow,
      rightOffset + METHOD2_POINT_LAYOUT.x
    ),
    ...fieldEqualityConstraints(
      leftRow,
      leftOffset + METHOD2_POINT_LAYOUT.y,
      rightRow,
      rightOffset + METHOD2_POINT_LAYOUT.y
    )
  ]
}

function fieldEqualityConstraints (
  leftRow: FieldElement[],
  leftOffset: number,
  rightRow: FieldElement[],
  rightOffset: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  for (let limb = 0; limb < 16; limb++) {
    constraints.push(F.sub(
      fieldLimb(leftRow, leftOffset, limb),
      fieldLimb(rightRow, rightOffset, limb)
    ))
  }
  return constraints
}

function copyRangeConstraints (
  leftRow: FieldElement[],
  leftOffset: number,
  rightRow: FieldElement[],
  rightOffset: number,
  width: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  for (let i = 0; i < width; i++) {
    constraints.push(F.sub(leftRow[leftOffset + i], rightRow[rightOffset + i]))
  }
  return constraints
}

function gateConstraints (
  constraints: FieldElement[],
  selector: FieldElement
): FieldElement[] {
  return constraints.map(constraint => F.mul(selector, constraint))
}

function booleanConstraint (value: FieldElement): FieldElement {
  return F.mul(value, F.sub(value, 1n))
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}

function byteBoundaryConstraints (
  offset: number,
  bytes: number[]
): Array<{ column: number, row: number, value: FieldElement }> {
  return bytes.map((byte, index) => ({
    column: offset + index,
    row: 0,
    value: BigInt(byte)
  }))
}

function writeNumbers (
  row: FieldElement[],
  offset: number,
  values: number[]
): void {
  for (let i = 0; i < values.length; i++) row[offset + i] = BigInt(values[i])
}

class Method2CompositeReader {
  private position = 0

  constructor (private readonly bytes: number[]) {}

  eof (): boolean {
    return this.position === this.bytes.length
  }

  read (length: number): number[] {
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new Error('Invalid Method 2 proof read length')
    }
    if (this.position + length > this.bytes.length) {
      throw new Error('Truncated Method 2 proof payload')
    }
    const out = this.bytes.slice(this.position, this.position + length)
    this.position += length
    return out
  }

  readUInt8 (): number {
    return this.read(1)[0]
  }

  readVarIntNum (): number {
    const first = this.readUInt8()
    if (first < 0xfd) return first
    if (first === 0xfd) {
      const value = this.readUInt16LE()
      if (value < 0xfd) throw new Error('Non-canonical Method 2 varint')
      return value
    }
    if (first === 0xfe) {
      const value = this.readUInt32LE()
      if (value < 0x10000) throw new Error('Non-canonical Method 2 varint')
      return value
    }
    const value = this.readUInt64LE()
    if (value < 0x100000000) {
      throw new Error('Non-canonical Method 2 varint')
    }
    if (value > Number.MAX_SAFE_INTEGER) {
      throw new Error('Method 2 varint exceeds safe integer range')
    }
    return value
  }

  private readUInt16LE (): number {
    const bytes = this.read(2)
    return bytes[0] | (bytes[1] << 8)
  }

  private readUInt32LE (): number {
    const bytes = this.read(4)
    return (
      bytes[0] |
      (bytes[1] << 8) |
      (bytes[2] << 16) |
      (bytes[3] << 24)
    ) >>> 0
  }

  private readUInt64LE (): number {
    const bytes = this.read(8)
    let value = 0
    let multiplier = 1
    for (let i = 0; i < bytes.length; i++) {
      value += bytes[i] * multiplier
      multiplier *= 0x100
    }
    return value
  }
}

function normalizeStatement (
  statement: SpecificKeyLinkageStatement
): SpecificKeyLinkageStatement {
  assertCompressedPublicKeyHex(statement.prover, 'prover')
  assertCompressedPublicKeyHex(statement.counterparty, 'counterparty')
  assertBytes(statement.linkage, 'linkage')
  if (statement.linkage.length !== 32) throw new Error('Linkage must be 32 bytes')
  computeInvoiceNumber(statement.protocolID, statement.keyID)
  return {
    prover: statement.prover.toLowerCase(),
    counterparty: statement.counterparty.toLowerCase(),
    protocolID: [
      statement.protocolID[0],
      statement.protocolID[1].toLowerCase().trim()
    ],
    keyID: statement.keyID,
    linkage: statement.linkage.slice()
  }
}

function privateKeyToScalar (
  privateKey: PrivateKey | bigint | string
): bigint {
  if (typeof privateKey === 'bigint') return privateKey
  if (typeof privateKey === 'string') return BigInt(`0x${privateKey}`)
  return BigInt(`0x${privateKey.toString('hex', 64)}`)
}

function assertCompressedPublicKeyHex (
  value: string,
  label: string
): void {
  if (!/^(02|03)[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`Invalid ${label} compressed public key`)
  }
  decompressPublicKey(toArray(value, 'hex'))
}

function assertBytes (bytes: number[], label: string): void {
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
