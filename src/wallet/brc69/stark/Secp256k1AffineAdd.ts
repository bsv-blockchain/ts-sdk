import {
  SECP256K1_P,
  isOnCurve,
  modInvP,
  modP,
  pointAdd
} from '../circuit/Secp256k1.js'
import { SecpPoint } from '../circuit/Types.js'
import { StarkProof, StarkProverOptions, serializeStarkProof } from './Stark.js'
import {
  Secp256k1FieldLinearTrace,
  Secp256k1FieldMulTrace,
  buildSecp256k1FieldAddTrace,
  buildSecp256k1FieldMulTrace,
  buildSecp256k1FieldSubTrace,
  proveSecp256k1FieldLinear,
  proveSecp256k1FieldMul,
  verifySecp256k1FieldLinear,
  verifySecp256k1FieldMul
} from './Secp256k1FieldOps.js'

export interface Secp256k1AffineAddWitness {
  left: SecpPoint
  right: SecpPoint
  result: SecpPoint
  dx: bigint
  dy: bigint
  inverseDx: bigint
  slope: bigint
  slopeSquared: bigint
  xAfterFirstSub: bigint
  xDiff: bigint
  ySum: bigint
}

export interface Secp256k1AffineAddTraceBundle {
  witness: Secp256k1AffineAddWitness
  linear: {
    dx: Secp256k1FieldLinearTrace
    dy: Secp256k1FieldLinearTrace
    xFirstSub: Secp256k1FieldLinearTrace
    xSecondSub: Secp256k1FieldLinearTrace
    xDiff: Secp256k1FieldLinearTrace
    ySum: Secp256k1FieldLinearTrace
  }
  mul: {
    inverse: Secp256k1FieldMulTrace
    slope: Secp256k1FieldMulTrace
    slopeSquared: Secp256k1FieldMulTrace
    yRelation: Secp256k1FieldMulTrace
  }
}

export interface Secp256k1AffineAddProofBundle {
  linear: {
    dx: StarkProof
    dy: StarkProof
    xFirstSub: StarkProof
    xSecondSub: StarkProof
    xDiff: StarkProof
    ySum: StarkProof
  }
  mul: {
    inverse: StarkProof
    slope: StarkProof
    slopeSquared: StarkProof
    yRelation: StarkProof
  }
}

export interface Secp256k1AffineAddMetrics {
  linearProofs: number
  mulProofs: number
  totalProofBytes?: number
}

export function buildSecp256k1AffineAddWitness (
  left: SecpPoint,
  right: SecpPoint
): Secp256k1AffineAddWitness {
  validateAffinePoint(left, 'left')
  validateAffinePoint(right, 'right')
  const dx = modP(right.x - left.x)
  if (dx === 0n) {
    throw new Error('Affine add prototype requires distinct x-coordinates')
  }
  const dy = modP(right.y - left.y)
  const inverseDx = modInvP(dx)
  const slope = modP(dy * inverseDx)
  const slopeSquared = modP(slope * slope)
  const xAfterFirstSub = modP(slopeSquared - left.x)
  const result = pointAdd(left, right)
  validateAffinePoint(result, 'result')
  const xDiff = modP(left.x - result.x)
  const ySum = modP(result.y + left.y)

  if (result.x !== modP(xAfterFirstSub - right.x)) {
    throw new Error('Affine add x-coordinate witness mismatch')
  }
  if (ySum !== modP(slope * xDiff)) {
    throw new Error('Affine add y-coordinate witness mismatch')
  }

  return {
    left,
    right,
    result,
    dx,
    dy,
    inverseDx,
    slope,
    slopeSquared,
    xAfterFirstSub,
    xDiff,
    ySum
  }
}

export function buildSecp256k1AffineAddTraceBundle (
  left: SecpPoint,
  right: SecpPoint
): Secp256k1AffineAddTraceBundle {
  const witness = buildSecp256k1AffineAddWitness(left, right)
  return {
    witness,
    linear: {
      dx: buildSecp256k1FieldSubTrace(witness.right.x, witness.left.x, witness.dx),
      dy: buildSecp256k1FieldSubTrace(witness.right.y, witness.left.y, witness.dy),
      xFirstSub: buildSecp256k1FieldSubTrace(
        witness.slopeSquared,
        witness.left.x,
        witness.xAfterFirstSub
      ),
      xSecondSub: buildSecp256k1FieldSubTrace(
        witness.xAfterFirstSub,
        witness.right.x,
        witness.result.x
      ),
      xDiff: buildSecp256k1FieldSubTrace(witness.left.x, witness.result.x, witness.xDiff),
      ySum: buildSecp256k1FieldAddTrace(witness.result.y, witness.left.y, witness.ySum)
    },
    mul: {
      inverse: buildSecp256k1FieldMulTrace(witness.dx, witness.inverseDx, 1n),
      slope: buildSecp256k1FieldMulTrace(witness.dy, witness.inverseDx, witness.slope),
      slopeSquared: buildSecp256k1FieldMulTrace(witness.slope, witness.slope, witness.slopeSquared),
      yRelation: buildSecp256k1FieldMulTrace(witness.slope, witness.xDiff, witness.ySum)
    }
  }
}

export function proveSecp256k1AffineAdd (
  bundle: Secp256k1AffineAddTraceBundle,
  options: StarkProverOptions = {}
): Secp256k1AffineAddProofBundle {
  return {
    linear: {
      dx: proveSecp256k1FieldLinear(bundle.linear.dx, options),
      dy: proveSecp256k1FieldLinear(bundle.linear.dy, options),
      xFirstSub: proveSecp256k1FieldLinear(bundle.linear.xFirstSub, options),
      xSecondSub: proveSecp256k1FieldLinear(bundle.linear.xSecondSub, options),
      xDiff: proveSecp256k1FieldLinear(bundle.linear.xDiff, options),
      ySum: proveSecp256k1FieldLinear(bundle.linear.ySum, options)
    },
    mul: {
      inverse: proveSecp256k1FieldMul(bundle.mul.inverse, options),
      slope: proveSecp256k1FieldMul(bundle.mul.slope, options),
      slopeSquared: proveSecp256k1FieldMul(bundle.mul.slopeSquared, options),
      yRelation: proveSecp256k1FieldMul(bundle.mul.yRelation, options)
    }
  }
}

export function verifySecp256k1AffineAdd (
  bundle: Secp256k1AffineAddTraceBundle,
  proof: Secp256k1AffineAddProofBundle
): boolean {
  return verifySecp256k1FieldLinear(bundle.linear.dx, proof.linear.dx) &&
    verifySecp256k1FieldLinear(bundle.linear.dy, proof.linear.dy) &&
    verifySecp256k1FieldLinear(bundle.linear.xFirstSub, proof.linear.xFirstSub) &&
    verifySecp256k1FieldLinear(bundle.linear.xSecondSub, proof.linear.xSecondSub) &&
    verifySecp256k1FieldLinear(bundle.linear.xDiff, proof.linear.xDiff) &&
    verifySecp256k1FieldLinear(bundle.linear.ySum, proof.linear.ySum) &&
    verifySecp256k1FieldMul(bundle.mul.inverse, proof.mul.inverse) &&
    verifySecp256k1FieldMul(bundle.mul.slope, proof.mul.slope) &&
    verifySecp256k1FieldMul(bundle.mul.slopeSquared, proof.mul.slopeSquared) &&
    verifySecp256k1FieldMul(bundle.mul.yRelation, proof.mul.yRelation)
}

export function secp256k1AffineAddMetrics (
  proof?: Secp256k1AffineAddProofBundle
): Secp256k1AffineAddMetrics {
  return {
    linearProofs: 6,
    mulProofs: 4,
    totalProofBytes: proof === undefined
      ? undefined
      : Object.values(proof.linear)
        .concat(Object.values(proof.mul))
        .reduce((total, item) => total + serializeStarkProof(item).length, 0)
  }
}

function validateAffinePoint (point: SecpPoint, label: string): void {
  if (point.infinity === true || !isOnCurve(point)) {
    throw new Error(`Affine add ${label} point is invalid`)
  }
  if (point.x < 0n || point.x >= SECP256K1_P || point.y < 0n || point.y >= SECP256K1_P) {
    throw new Error(`Affine add ${label} point is non-canonical`)
  }
}
