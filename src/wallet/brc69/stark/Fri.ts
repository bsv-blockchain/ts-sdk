import {
  F,
  FieldElement,
  assertPowerOfTwo,
  getPowerOfTwoRootOfUnity,
  isPowerOfTwo
} from './Field.js'
import {
  MerkleHash,
  MerklePathItem,
  buildMerkleTree,
  buildMerkleTreeFromLeafFactory,
  fieldElementLeaf,
  openMerklePath,
  verifyMerklePath
} from './Merkle.js'
import { FiatShamirTranscript } from './Transcript.js'
import {
  degreeLessThan,
  interpolateEvaluations,
  serializeFieldElements
} from './Polynomial.js'
import { Writer } from '../../../primitives/utils.js'
import {
  StarkProgressCallback,
  emitStarkProgress,
  shouldEmitProgress
} from './Progress.js'
import {
  TypedFieldColumn,
  typedFieldAdd,
  typedFieldColumnToBigints,
  typedFieldElement,
  typedFieldElementBytes,
  typedFieldInv,
  typedFieldMul,
  typedFieldSub,
  typedFieldToBigint
} from './TypedField.js'

export const FRI_TRANSCRIPT_DOMAIN = 'BRC69_STARK_FRI_V1'
export const FRI_DEFAULT_NUM_QUERIES = 48
export const FRI_DEFAULT_MAX_REMAINDER_SIZE = 16

export interface FriOptions {
  degreeBound: number
  numQueries?: number
  maxRemainderSize?: number
  domainOffset?: FieldElement
  transcriptDomain?: string
  transcriptContext?: number[]
  progress?: StarkProgressCallback
}

export interface FriVerifierInput {
  expectedRoot: MerkleHash
  domainSize: number
  degreeBound: number
  numQueries: number
  maxRemainderSize: number
  domainOffset: FieldElement
  transcriptDomain?: string
  transcriptContext?: number[]
}

export interface FriLayerQuery {
  leftIndex: number
  rightIndex: number
  leftValue: FieldElement
  rightValue: FieldElement
  leftPath: MerklePathItem[]
  rightPath: MerklePathItem[]
}

export interface FriQueryProof {
  initialIndex: number
  layers: FriLayerQuery[]
  finalIndex: number
}

export interface FriProof {
  domainSize: number
  degreeBound: number
  numQueries: number
  maxRemainderSize: number
  domainOffset: FieldElement
  roots: MerkleHash[]
  finalValues: FieldElement[]
  queries: FriQueryProof[]
}

interface FriProverLayer {
  evaluations: FieldElement[]
  root: MerkleHash
  tree: ReturnType<typeof buildMerkleTree>
  beta: FieldElement
  domainOffset: FieldElement
}

interface TypedFriProverLayer {
  evaluations: TypedFieldColumn
  root: MerkleHash
  tree: ReturnType<typeof buildMerkleTree>
  beta: FieldElement
  domainOffset: FieldElement
}

const FRI_INV_TWO = F.inv(2n)

export function foldFriPair (
  leftValue: FieldElement,
  rightValue: FieldElement,
  x: FieldElement,
  beta: FieldElement
): FieldElement {
  leftValue = F.normalize(leftValue)
  rightValue = F.normalize(rightValue)
  x = F.normalize(x)
  beta = F.normalize(beta)
  if (x === 0n) {
    throw new Error('FRI fold point must be non-zero')
  }
  const even = F.mul(F.add(leftValue, rightValue), FRI_INV_TWO)
  const odd = F.mul(
    F.mul(F.sub(leftValue, rightValue), FRI_INV_TWO),
    F.inv(x)
  )
  return F.add(even, F.mul(beta, odd))
}

export function foldFriLayer (
  evaluations: FieldElement[],
  beta: FieldElement,
  domainOffset: FieldElement = 1n,
  progress?: StarkProgressCallback
): FieldElement[] {
  const n = evaluations.length
  assertPowerOfTwo(n)
  domainOffset = F.normalize(domainOffset)
  if (domainOffset === 0n) {
    throw new Error('FRI domain offset must be non-zero')
  }
  if (n < 2) {
    throw new Error('Cannot fold a singleton FRI layer')
  }
  const half = n >> 1
  const root = getPowerOfTwoRootOfUnity(n)
  const folded = new Array<FieldElement>(half)
  const invRoot = F.inv(root)
  let invX = F.inv(domainOffset)
  for (let i = 0; i < half; i++) {
    const left = F.normalize(evaluations[i])
    const right = F.normalize(evaluations[i + half])
    const even = F.mul(F.add(left, right), FRI_INV_TWO)
    const odd = F.mul(
      F.mul(F.sub(left, right), FRI_INV_TWO),
      invX
    )
    folded[i] = F.add(even, F.mul(beta, odd))
    invX = F.mul(invX, invRoot)
    if (shouldEmitProgress(i, half)) {
      emitStarkProgress(progress, {
        phase: 'fri.fold',
        status: 'progress',
        count: i + 1,
        total: half
      })
    }
  }
  return folded
}

export function foldTypedFriLayer (
  evaluations: TypedFieldColumn,
  beta: FieldElement,
  domainOffset: FieldElement = 1n,
  progress?: StarkProgressCallback
): TypedFieldColumn {
  const n = evaluations.lo.length
  if (evaluations.hi.length !== n) {
    throw new Error('Typed FRI lane length mismatch')
  }
  assertPowerOfTwo(n)
  domainOffset = F.normalize(domainOffset)
  if (domainOffset === 0n) {
    throw new Error('FRI domain offset must be non-zero')
  }
  if (n < 2) {
    throw new Error('Cannot fold a singleton FRI layer')
  }
  const half = n >> 1
  const folded = {
    lo: new Uint32Array(half),
    hi: new Uint32Array(half)
  }
  const betaTyped = typedFieldElement(beta)
  const invRoot = typedFieldInv(typedFieldElement(getPowerOfTwoRootOfUnity(n)))
  let invX = typedFieldInv(typedFieldElement(domainOffset))
  const invTwo = typedFieldElement(FRI_INV_TWO)
  for (let i = 0; i < half; i++) {
    const left = {
      lo: evaluations.lo[i],
      hi: evaluations.hi[i]
    }
    const right = {
      lo: evaluations.lo[i + half],
      hi: evaluations.hi[i + half]
    }
    const even = typedFieldMul(typedFieldAdd(left, right), invTwo)
    const odd = typedFieldMul(
      typedFieldMul(typedFieldSub(left, right), invTwo),
      invX
    )
    const value = typedFieldAdd(even, typedFieldMul(betaTyped, odd))
    folded.lo[i] = value.lo
    folded.hi[i] = value.hi
    invX = typedFieldMul(invX, invRoot)
    if (shouldEmitProgress(i, half)) {
      emitStarkProgress(progress, {
        phase: 'fri.fold',
        status: 'progress',
        count: i + 1,
        total: half
      })
    }
  }
  return folded
}

export function proveFri (
  evaluations: FieldElement[],
  options: FriOptions
): FriProof {
  const domainSize = evaluations.length
  const start = Date.now()
  assertPowerOfTwo(domainSize)
  validateFriParameters(
    domainSize,
    options.degreeBound,
    options.numQueries ?? FRI_DEFAULT_NUM_QUERIES,
    options.maxRemainderSize ?? FRI_DEFAULT_MAX_REMAINDER_SIZE,
    F.normalize(options.domainOffset ?? 1n)
  )

  const numQueries = options.numQueries ?? FRI_DEFAULT_NUM_QUERIES
  const maxRemainderSize = options.maxRemainderSize ?? FRI_DEFAULT_MAX_REMAINDER_SIZE
  const domainOffset = F.normalize(options.domainOffset ?? 1n)

  const transcript = createFriTranscript(
    domainSize,
    options.degreeBound,
    numQueries,
    maxRemainderSize,
    domainOffset,
    options.transcriptDomain,
    options.transcriptContext
  )

  emitStarkProgress(options.progress, {
    phase: 'fri.prove',
    status: 'start',
    ldeSize: domainSize,
    rows: domainSize
  })
  const layers: FriProverLayer[] = []
  let current = evaluations.map(v => F.normalize(v))
  let currentOffset = domainOffset
  let layerIndex = 0
  while (current.length > maxRemainderSize) {
    emitStarkProgress(options.progress, {
      phase: 'fri.layer',
      status: 'start',
      layer: layerIndex,
      layerSize: current.length
    })
    const leaves = new Array<number[]>(current.length)
    for (let i = 0; i < current.length; i++) {
      leaves[i] = fieldElementLeaf(current[i])
      if (shouldEmitProgress(i, current.length)) {
        emitStarkProgress(options.progress, {
          phase: 'fri.layer.leaf-serialization',
          status: 'progress',
          layer: layerIndex,
          count: i + 1,
          total: current.length
        })
      }
    }
    const tree = buildMerkleTree(leaves, {
      progress: options.progress,
      phase: 'fri.layer.merkle'
    })
    transcript.absorb('fri-root', tree.root)
    const beta = transcript.challengeFieldElement('fri-beta')
    layers.push({
      evaluations: current,
      root: tree.root,
      tree,
      beta,
      domainOffset: currentOffset
    })
    current = foldFriLayer(current, beta, currentOffset, options.progress)
    currentOffset = F.mul(currentOffset, currentOffset)
    emitStarkProgress(options.progress, {
      phase: 'fri.layer',
      status: 'end',
      layer: layerIndex,
      layerSize: current.length
    })
    layerIndex++
  }

  const finalValues = current
  transcript.absorb('fri-final', serializeFieldElements(finalValues))
  const initialIndexes = deriveQueryIndexes(transcript, domainSize, numQueries)

  emitStarkProgress(options.progress, {
    phase: 'fri.queries',
    status: 'start',
    count: initialIndexes.length,
    total: initialIndexes.length
  })
  const queries = initialIndexes.map(initialIndex => {
    let index = initialIndex
    const layerQueries: FriLayerQuery[] = []
    for (const layer of layers) {
      const n = layer.evaluations.length
      const half = n >> 1
      const leftIndex = index % half
      const rightIndex = leftIndex + half
      layerQueries.push({
        leftIndex,
        rightIndex,
        leftValue: layer.evaluations[leftIndex],
        rightValue: layer.evaluations[rightIndex],
        leftPath: openMerklePath(layer.tree, leftIndex),
        rightPath: openMerklePath(layer.tree, rightIndex)
      })
      index = leftIndex
    }
    return {
      initialIndex,
      layers: layerQueries,
      finalIndex: index % finalValues.length
    }
  })
  emitStarkProgress(options.progress, {
    phase: 'fri.queries',
    status: 'end',
    count: queries.length,
    total: initialIndexes.length
  })
  emitStarkProgress(options.progress, {
    phase: 'fri.prove',
    status: 'end',
    ldeSize: domainSize,
    elapsedMs: Date.now() - start
  })

  return {
    domainSize,
    degreeBound: options.degreeBound,
    numQueries,
    maxRemainderSize,
    domainOffset,
    roots: layers.map(layer => layer.root),
    finalValues,
    queries
  }
}

export function proveFriTyped (
  evaluations: TypedFieldColumn,
  options: FriOptions
): FriProof {
  const domainSize = evaluations.lo.length
  const start = Date.now()
  if (evaluations.hi.length !== domainSize) {
    throw new Error('Typed FRI lane length mismatch')
  }
  assertPowerOfTwo(domainSize)
  validateFriParameters(
    domainSize,
    options.degreeBound,
    options.numQueries ?? FRI_DEFAULT_NUM_QUERIES,
    options.maxRemainderSize ?? FRI_DEFAULT_MAX_REMAINDER_SIZE,
    F.normalize(options.domainOffset ?? 1n)
  )

  const numQueries = options.numQueries ?? FRI_DEFAULT_NUM_QUERIES
  const maxRemainderSize = options.maxRemainderSize ?? FRI_DEFAULT_MAX_REMAINDER_SIZE
  const domainOffset = F.normalize(options.domainOffset ?? 1n)

  const transcript = createFriTranscript(
    domainSize,
    options.degreeBound,
    numQueries,
    maxRemainderSize,
    domainOffset,
    options.transcriptDomain,
    options.transcriptContext
  )

  emitStarkProgress(options.progress, {
    phase: 'fri.prove',
    status: 'start',
    ldeSize: domainSize,
    rows: domainSize
  })
  const layers: TypedFriProverLayer[] = []
  let current: TypedFieldColumn = {
    lo: new Uint32Array(evaluations.lo),
    hi: new Uint32Array(evaluations.hi)
  }
  let currentOffset = domainOffset
  let layerIndex = 0
  while (current.lo.length > maxRemainderSize) {
    emitStarkProgress(options.progress, {
      phase: 'fri.layer',
      status: 'start',
      layer: layerIndex,
      layerSize: current.lo.length
    })
    const tree = buildMerkleTreeFromLeafFactory(
      current.lo.length,
      i => {
        if (shouldEmitProgress(i, current.lo.length)) {
          emitStarkProgress(options.progress, {
            phase: 'fri.layer.leaf-serialization',
            status: 'progress',
            layer: layerIndex,
            count: i + 1,
            total: current.lo.length
          })
        }
        return typedFieldElementBytes({
          lo: current.lo[i],
          hi: current.hi[i]
        })
      },
      {
        progress: options.progress,
        phase: 'fri.layer.merkle'
      }
    )
    transcript.absorb('fri-root', tree.root)
    const beta = transcript.challengeFieldElement('fri-beta')
    layers.push({
      evaluations: current,
      root: tree.root,
      tree,
      beta,
      domainOffset: currentOffset
    })
    current = foldTypedFriLayer(current, beta, currentOffset, options.progress)
    currentOffset = F.mul(currentOffset, currentOffset)
    emitStarkProgress(options.progress, {
      phase: 'fri.layer',
      status: 'end',
      layer: layerIndex,
      layerSize: current.lo.length
    })
    layerIndex++
  }

  const finalValues = typedFieldColumnToBigints(current)
  transcript.absorb('fri-final', serializeFieldElements(finalValues))
  const initialIndexes = deriveQueryIndexes(transcript, domainSize, numQueries)

  emitStarkProgress(options.progress, {
    phase: 'fri.queries',
    status: 'start',
    count: initialIndexes.length,
    total: initialIndexes.length
  })
  const queries = initialIndexes.map(initialIndex => {
    let index = initialIndex
    const layerQueries: FriLayerQuery[] = []
    for (const layer of layers) {
      const n = layer.evaluations.lo.length
      const half = n >> 1
      const leftIndex = index % half
      const rightIndex = leftIndex + half
      layerQueries.push({
        leftIndex,
        rightIndex,
        leftValue: typedFieldToBigint({
          lo: layer.evaluations.lo[leftIndex],
          hi: layer.evaluations.hi[leftIndex]
        }),
        rightValue: typedFieldToBigint({
          lo: layer.evaluations.lo[rightIndex],
          hi: layer.evaluations.hi[rightIndex]
        }),
        leftPath: openMerklePath(layer.tree, leftIndex),
        rightPath: openMerklePath(layer.tree, rightIndex)
      })
      index = leftIndex
    }
    return {
      initialIndex,
      layers: layerQueries,
      finalIndex: index % finalValues.length
    }
  })
  emitStarkProgress(options.progress, {
    phase: 'fri.queries',
    status: 'end',
    count: queries.length,
    total: initialIndexes.length
  })
  emitStarkProgress(options.progress, {
    phase: 'fri.prove',
    status: 'end',
    ldeSize: domainSize,
    elapsedMs: Date.now() - start
  })

  return {
    domainSize,
    degreeBound: options.degreeBound,
    numQueries,
    maxRemainderSize,
    domainOffset,
    roots: layers.map(layer => layer.root),
    finalValues,
    queries
  }
}

export function verifyFri (
  proof: FriProof,
  input?: FriVerifierInput
): boolean {
  try {
    if (input === undefined) return false
    validateFriProofShape(proof)
    validateFriParameters(
      input.domainSize,
      input.degreeBound,
      input.numQueries,
      input.maxRemainderSize,
      input.domainOffset
    )
    if (
      proof.domainSize !== input.domainSize ||
      proof.degreeBound !== input.degreeBound ||
      proof.numQueries !== input.numQueries ||
      proof.maxRemainderSize !== input.maxRemainderSize ||
      proof.domainOffset !== F.normalize(input.domainOffset) ||
      !hashesEqual(proof.roots[0], input.expectedRoot)
    ) {
      return false
    }

    const expectedRounds = expectedFriRoundCount(
      input.domainSize,
      input.maxRemainderSize
    )
    if (proof.roots.length !== expectedRounds) return false

    const transcript = createFriTranscript(
      input.domainSize,
      input.degreeBound,
      input.numQueries,
      input.maxRemainderSize,
      F.normalize(input.domainOffset),
      input.transcriptDomain,
      input.transcriptContext
    )
    const betas: FieldElement[] = []
    let layerSize = input.domainSize
    for (const root of proof.roots) {
      transcript.absorb('fri-root', root)
      betas.push(transcript.challengeFieldElement('fri-beta'))
      layerSize >>= 1
    }
    if (proof.finalValues.length !== layerSize) return false

    const finalDegreeBound = foldDegreeBound(
      input.degreeBound,
      proof.roots.length
    )
    if (!degreeLessThan(interpolateEvaluations(proof.finalValues), finalDegreeBound)) {
      return false
    }

    transcript.absorb('fri-final', serializeFieldElements(proof.finalValues))
    const expectedIndexes = deriveQueryIndexes(
      transcript,
      input.domainSize,
      input.numQueries
    )
    if (proof.queries.length !== expectedIndexes.length) {
      return false
    }

    for (let q = 0; q < expectedIndexes.length; q++) {
      const query = proof.queries[q]
      if (query.initialIndex !== expectedIndexes[q]) {
        return false
      }
      let currentIndex = query.initialIndex
      let expectedValue: FieldElement | undefined
      layerSize = input.domainSize
      let currentOffset = F.normalize(input.domainOffset)

      for (let layerIndex = 0; layerIndex < proof.roots.length; layerIndex++) {
        const layer = query.layers[layerIndex]
        if (layer === undefined) return false
        const half = layerSize >> 1
        const leftIndex = currentIndex % half
        const rightIndex = leftIndex + half
        if (layer.leftIndex !== leftIndex || layer.rightIndex !== rightIndex) {
          return false
        }
        if (expectedValue !== undefined) {
          const carried = currentIndex < half
            ? layer.leftValue
            : layer.rightValue
          if (carried !== expectedValue) {
            return false
          }
        }
        if (!verifyMerklePath(
          fieldElementLeaf(layer.leftValue),
          leftIndex,
          proof.roots[layerIndex],
          layer.leftPath,
          layerSize
        )) {
          return false
        }
        if (!verifyMerklePath(
          fieldElementLeaf(layer.rightValue),
          rightIndex,
          proof.roots[layerIndex],
          layer.rightPath,
          layerSize
        )) {
          return false
        }

        const x = F.mul(
          currentOffset,
          F.pow(getPowerOfTwoRootOfUnity(layerSize), BigInt(leftIndex))
        )
        expectedValue = foldFriPair(
          layer.leftValue,
          layer.rightValue,
          x,
          betas[layerIndex]
        )
        currentIndex = leftIndex
        layerSize >>= 1
        currentOffset = F.mul(currentOffset, currentOffset)
      }

      if (query.layers.length !== proof.roots.length) {
        return false
      }
      if (query.finalIndex !== currentIndex % proof.finalValues.length) {
        return false
      }
      if (
        expectedValue !== undefined &&
        proof.finalValues[query.finalIndex] !== expectedValue
      ) {
        return false
      }
    }

    return true
  } catch {
    return false
  }
}

export function serializeFriProof (proof: FriProof): number[] {
  validateFriProofShape(proof)
  const writer = new Writer()
  writer.writeVarIntNum(proof.domainSize)
  writer.writeVarIntNum(proof.degreeBound)
  writer.writeVarIntNum(proof.numQueries)
  writer.writeVarIntNum(proof.maxRemainderSize)
  writeField(writer, proof.domainOffset)

  writer.writeVarIntNum(proof.roots.length)
  for (const root of proof.roots) writeHash(writer, root)

  writer.writeVarIntNum(proof.finalValues.length)
  for (const value of proof.finalValues) writeField(writer, value)

  writer.writeVarIntNum(proof.queries.length)
  for (const query of proof.queries) {
    writer.writeVarIntNum(query.initialIndex)
    writer.writeVarIntNum(query.finalIndex)
    writer.writeVarIntNum(query.layers.length)
    for (const layer of query.layers) {
      writer.writeVarIntNum(layer.leftIndex)
      writer.writeVarIntNum(layer.rightIndex)
      writeField(writer, layer.leftValue)
      writeField(writer, layer.rightValue)
      writeMerklePath(writer, layer.leftPath)
      writeMerklePath(writer, layer.rightPath)
    }
  }

  return writer.toArray()
}

export function parseFriProof (bytes: number[]): FriProof {
  const reader = new FriBinaryReader(bytes)
  const domainSize = reader.readVarIntNum()
  const degreeBound = reader.readVarIntNum()
  const numQueries = reader.readVarIntNum()
  const maxRemainderSize = reader.readVarIntNum()
  const domainOffset = readField(reader)

  const rootsLength = reader.readVarIntNum()
  if (rootsLength > 64) throw new Error('Too many FRI roots')
  const roots: MerkleHash[] = []
  for (let i = 0; i < rootsLength; i++) roots.push(readHash(reader))

  const finalValuesLength = reader.readVarIntNum()
  if (finalValuesLength < 1 || finalValuesLength > 1048576) {
    throw new Error('Invalid FRI final layer length')
  }
  const finalValues: FieldElement[] = []
  for (let i = 0; i < finalValuesLength; i++) {
    finalValues.push(readField(reader))
  }

  const queriesLength = reader.readVarIntNum()
  if (queriesLength > 1048576) throw new Error('Too many FRI queries')
  const queries: FriQueryProof[] = []
  for (let i = 0; i < queriesLength; i++) {
    const initialIndex = reader.readVarIntNum()
    const finalIndex = reader.readVarIntNum()
    const layersLength = reader.readVarIntNum()
    if (layersLength > 64) throw new Error('Too many FRI query layers')
    const layers: FriLayerQuery[] = []
    for (let j = 0; j < layersLength; j++) {
      layers.push({
        leftIndex: reader.readVarIntNum(),
        rightIndex: reader.readVarIntNum(),
        leftValue: readField(reader),
        rightValue: readField(reader),
        leftPath: readMerklePath(reader),
        rightPath: readMerklePath(reader)
      })
    }
    queries.push({
      initialIndex,
      finalIndex,
      layers
    })
  }

  if (!reader.eof()) {
    throw new Error('Unexpected trailing bytes in FRI proof')
  }

  const proof = {
    domainSize,
    degreeBound,
    numQueries,
    maxRemainderSize,
    domainOffset,
    roots,
    finalValues,
    queries
  }
  validateFriProofShape(proof)
  return proof
}

export function expectedFriRoundCount (
  domainSize: number,
  maxRemainderSize: number
): number {
  assertPowerOfTwo(domainSize)
  if (!isPowerOfTwo(maxRemainderSize)) {
    throw new Error('FRI maxRemainderSize must be a power of two')
  }
  if (maxRemainderSize < 1 || maxRemainderSize >= domainSize) {
    throw new Error('FRI maxRemainderSize must be in [1, domainSize)')
  }
  let rounds = 0
  let size = domainSize
  while (size > maxRemainderSize) {
    rounds++
    size >>= 1
  }
  return rounds
}

export function foldDegreeBound (
  degreeBound: number,
  rounds: number
): number {
  if (!Number.isSafeInteger(degreeBound) || degreeBound < 1) {
    throw new Error('FRI degreeBound must be positive')
  }
  if (!Number.isSafeInteger(rounds) || rounds < 0) {
    throw new Error('FRI round count must be non-negative')
  }
  let bound = degreeBound
  for (let i = 0; i < rounds; i++) {
    bound = Math.ceil(bound / 2)
  }
  return bound
}

function validateFriParameters (
  domainSize: number,
  degreeBound: number,
  numQueries: number,
  maxRemainderSize: number,
  domainOffset: FieldElement
): void {
  assertPowerOfTwo(domainSize)
  if (!Number.isSafeInteger(degreeBound) || degreeBound < 1 || degreeBound >= domainSize) {
    throw new Error('FRI degreeBound must be in [1, domainSize)')
  }
  if (!Number.isSafeInteger(numQueries) || numQueries < 1 || numQueries > domainSize) {
    throw new Error('FRI numQueries must be in [1, domainSize]')
  }
  if (!isPowerOfTwo(maxRemainderSize) || maxRemainderSize >= domainSize) {
    throw new Error('FRI maxRemainderSize must be a power of two smaller than domainSize')
  }
  domainOffset = F.normalize(domainOffset)
  if (domainOffset === 0n) {
    throw new Error('FRI domainOffset must be non-zero')
  }
}

function validateFriProofShape (proof: FriProof): void {
  validateFriParameters(
    proof.domainSize,
    proof.degreeBound,
    proof.numQueries,
    proof.maxRemainderSize,
    proof.domainOffset
  )
  if (proof.finalValues.length < 1) {
    throw new Error('FRI proof final layer must not be empty')
  }
  for (const root of proof.roots) assertHash(root)
  for (const value of proof.finalValues) F.assertCanonical(value)
  for (const query of proof.queries) {
    if (
      !Number.isSafeInteger(query.initialIndex) ||
      query.initialIndex < 0 ||
      query.initialIndex >= proof.domainSize ||
      !Number.isSafeInteger(query.finalIndex) ||
      query.finalIndex < 0
    ) {
      throw new Error('Invalid FRI query index')
    }
    for (const layer of query.layers) {
      if (
        !Number.isSafeInteger(layer.leftIndex) ||
        layer.leftIndex < 0 ||
        !Number.isSafeInteger(layer.rightIndex) ||
        layer.rightIndex < 0
      ) {
        throw new Error('Invalid FRI layer index')
      }
      F.assertCanonical(layer.leftValue)
      F.assertCanonical(layer.rightValue)
      assertMerklePath(layer.leftPath)
      assertMerklePath(layer.rightPath)
    }
  }
}

function createFriTranscript (
  domainSize: number,
  degreeBound: number,
  numQueries: number,
  maxRemainderSize: number,
  domainOffset: FieldElement,
  transcriptDomain?: string,
  transcriptContext?: number[]
): FiatShamirTranscript {
  const transcript = new FiatShamirTranscript(transcriptDomain ?? FRI_TRANSCRIPT_DOMAIN)
  if (transcriptContext !== undefined) {
    assertBytes(transcriptContext)
    if (transcriptContext.length !== 32) {
      throw new Error('FRI transcriptContext must be 32 bytes')
    }
    transcript.absorb('fri-transcript-context', transcriptContext)
  }
  transcript.absorb('fri-params', [
    ...u32(domainSize),
    ...u32(degreeBound),
    ...u32(numQueries),
    ...u32(maxRemainderSize),
    ...F.toBytesLE(domainOffset)
  ])
  return transcript
}

function deriveQueryIndexes (
  transcript: FiatShamirTranscript,
  domainSize: number,
  numQueries: number
): number[] {
  if (!Number.isSafeInteger(numQueries) || numQueries < 1 || numQueries > domainSize) {
    throw new Error('FRI numQueries must be in [1, domainSize]')
  }
  const indexes: number[] = []
  const seen = new Set<number>()
  let attempt = 0
  while (indexes.length < numQueries) {
    const index = transcript.challengeIndex(`fri-query-${attempt++}`, domainSize)
    if (!seen.has(index)) {
      seen.add(index)
      indexes.push(index)
    }
  }
  return indexes
}

function u32 (value: number): number[] {
  return [
    value & 0xff,
    (value >>> 8) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 24) & 0xff
  ]
}

function writeField (writer: Writer, value: FieldElement): void {
  F.assertCanonical(value)
  writer.write(F.toBytesLE(value))
}

function readField (reader: FriBinaryReader): FieldElement {
  return F.fromBytesLE(reader.read(8))
}

function writeHash (writer: Writer, hash: MerkleHash): void {
  assertHash(hash)
  writer.write(hash)
}

function readHash (reader: FriBinaryReader): MerkleHash {
  const hash = reader.read(32)
  assertHash(hash)
  return hash
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

function readMerklePath (reader: FriBinaryReader): MerklePathItem[] {
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

function assertHash (hash: number[]): void {
  if (hash.length !== 32) throw new Error('Merkle hashes must be 32 bytes')
  assertBytes(hash)
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

class FriBinaryReader {
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
      throw new Error('Unexpected end of FRI proof')
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
