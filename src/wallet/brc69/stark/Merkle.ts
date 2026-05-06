import { SHA256 } from '../../../primitives/Hash.js'
import { toArray, toHex } from '../../../primitives/utils.js'
import { F, FieldElement } from './Field.js'
import {
  StarkProgressCallback,
  emitStarkProgress,
  shouldEmitProgress
} from './Progress.js'

export type MerkleHash = number[]

const LEAF_DOMAIN = toArray('BRC69_STARK_MERKLE_LEAF_V1', 'utf8')
const NODE_DOMAIN = toArray('BRC69_STARK_MERKLE_NODE_V1', 'utf8')

export interface MerkleTree {
  levels: MerkleHash[][]
  root: MerkleHash
}

export interface MerklePathItem {
  sibling: MerkleHash
  siblingOnLeft: boolean
}

export interface MerkleBuildOptions {
  progress?: StarkProgressCallback
  phase?: string
}

export type MerkleLeafFactory = (index: number) => number[] | Uint8Array

export function hashMerkleLeaf (leaf: number[]): MerkleHash {
  assertBytes(leaf)
  return hashWithDomain(LEAF_DOMAIN, leaf)
}

export function hashMerkleNode (
  left: MerkleHash,
  right: MerkleHash
): MerkleHash {
  assertHash(left, 'left Merkle hash')
  assertHash(right, 'right Merkle hash')
  return hashNodeUnchecked(left, right)
}

export function buildMerkleTree (
  leaves: number[][],
  options: MerkleBuildOptions = {}
): MerkleTree {
  if (leaves.length < 1) {
    throw new Error('Merkle tree requires at least one leaf')
  }
  const phase = options.phase ?? 'merkle'
  const start = Date.now()
  emitStarkProgress(options.progress, {
    phase,
    status: 'start',
    rows: leaves.length
  })
  let current = new Array<MerkleHash>(leaves.length)
  for (let i = 0; i < leaves.length; i++) {
    current[i] = hashLeafUnchecked(leaves[i])
    if (shouldEmitProgress(i, leaves.length)) {
      emitStarkProgress(options.progress, {
        phase: `${phase}.leaves`,
        status: 'progress',
        count: i + 1,
        total: leaves.length
      })
    }
  }
  const levels: MerkleHash[][] = [current]
  let layer = 0

  while (current.length > 1) {
    const next: MerkleHash[] = []
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i]
      const right = current[i + 1] ?? current[i]
      next.push(hashMerkleNode(left, right))
    }
    levels.push(next)
    current = next
    layer++
    emitStarkProgress(options.progress, {
      phase: `${phase}.layer`,
      status: 'progress',
      layer,
      layerSize: current.length
    })
  }

  emitStarkProgress(options.progress, {
    phase,
    status: 'end',
    rows: leaves.length,
    elapsedMs: Date.now() - start
  })
  return {
    levels,
    root: current[0]
  }
}

export function buildMerkleTreeFromLeafFactory (
  leafCount: number,
  leafAt: MerkleLeafFactory,
  options: MerkleBuildOptions = {}
): MerkleTree {
  if (!Number.isSafeInteger(leafCount) || leafCount < 1) {
    throw new Error('Merkle tree requires at least one leaf')
  }
  const phase = options.phase ?? 'merkle'
  const start = Date.now()
  emitStarkProgress(options.progress, {
    phase,
    status: 'start',
    rows: leafCount
  })
  let current = new Array<MerkleHash>(leafCount)
  for (let i = 0; i < leafCount; i++) {
    current[i] = hashLeafUnchecked(leafAt(i))
    if (shouldEmitProgress(i, leafCount)) {
      emitStarkProgress(options.progress, {
        phase: `${phase}.leaves`,
        status: 'progress',
        count: i + 1,
        total: leafCount
      })
    }
  }
  const levels: MerkleHash[][] = [current]
  let layer = 0

  while (current.length > 1) {
    const next: MerkleHash[] = []
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i]
      const right = current[i + 1] ?? current[i]
      next.push(hashMerkleNode(left, right))
    }
    levels.push(next)
    current = next
    layer++
    emitStarkProgress(options.progress, {
      phase: `${phase}.layer`,
      status: 'progress',
      layer,
      layerSize: current.length
    })
  }

  emitStarkProgress(options.progress, {
    phase,
    status: 'end',
    rows: leafCount,
    elapsedMs: Date.now() - start
  })
  return {
    levels,
    root: current[0]
  }
}

function hashLeafUnchecked (leaf: number[] | Uint8Array): MerkleHash {
  return hashWithDomain(LEAF_DOMAIN, leaf)
}

function hashNodeUnchecked (
  left: MerkleHash,
  right: MerkleHash
): MerkleHash {
  const hash = new SHA256()
  hash.update(NODE_DOMAIN)
  hash.update(left)
  hash.update(right)
  return hash.digest()
}

function hashWithDomain (
  domain: number[],
  bytes: number[] | Uint8Array
): MerkleHash {
  const hash = new SHA256()
  hash.update(domain)
  hash.update(bytes)
  return hash.digest()
}

export function openMerklePath (
  tree: MerkleTree,
  leafIndex: number
): MerklePathItem[] {
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= tree.levels[0].length) {
    throw new Error('Merkle leaf index out of bounds')
  }

  const path: MerklePathItem[] = []
  let index = leafIndex
  for (let level = 0; level < tree.levels.length - 1; level++) {
    const nodes = tree.levels[level]
    const siblingIndex = index ^ 1
    const sibling = nodes[siblingIndex] ?? nodes[index]
    path.push({
      sibling,
      siblingOnLeft: siblingIndex < index
    })
    index >>= 1
  }
  return path
}

export function verifyMerklePath (
  leaf: number[],
  leafIndex: number,
  root: MerkleHash,
  path: MerklePathItem[],
  leafCount?: number
): boolean {
  try {
    assertBytes(leaf)
    assertHash(root, 'Merkle root')
    if (!Number.isSafeInteger(leafIndex) || leafIndex < 0) return false
    if (leafCount !== undefined) {
      if (!Number.isSafeInteger(leafCount) || leafCount < 1) return false
      if (leafIndex >= leafCount) return false
      if (path.length !== merklePathLength(leafCount)) return false
    }
    for (const item of path) {
      if (typeof item.siblingOnLeft !== 'boolean') return false
      assertHash(item.sibling, 'Merkle path sibling')
    }
  } catch {
    return false
  }

  let hash = hashMerkleLeaf(leaf)
  let index = leafIndex

  for (const item of path) {
    const siblingOnLeft = (index & 1) === 1
    if (item.siblingOnLeft !== siblingOnLeft) {
      return false
    }
    hash = item.siblingOnLeft
      ? hashMerkleNode(item.sibling, hash)
      : hashMerkleNode(hash, item.sibling)
    index >>= 1
  }

  return toHex(hash) === toHex(root)
}

export function fieldElementLeaf (value: FieldElement): number[] {
  return F.toBytesLE(value)
}

export function fieldElementLeaves (values: FieldElement[]): number[][] {
  return values.map(fieldElementLeaf)
}

export function merklePathLength (leafCount: number): number {
  if (!Number.isSafeInteger(leafCount) || leafCount < 1) {
    throw new Error('Merkle leaf count must be positive')
  }
  let height = 0
  let level = leafCount
  while (level > 1) {
    level = Math.ceil(level / 2)
    height++
  }
  return height
}

function assertHash (hash: number[], label: string): void {
  if (hash.length !== 32) {
    throw new Error(`${label} must be 32 bytes`)
  }
  assertBytes(hash)
}

function assertBytes (bytes: number[]): void {
  for (const byte of bytes) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error('Invalid byte value')
    }
  }
}
