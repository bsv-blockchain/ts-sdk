import { F, FieldElement, assertPowerOfTwo } from './Field.js'

export interface BoundaryConstraint {
  column: number
  row: number
  value: FieldElement
}

export interface FullBoundaryColumn {
  column: number
  values: FieldElement[]
}

export interface AirDefinition {
  traceWidth: number
  boundaryConstraints: BoundaryConstraint[]
  fullBoundaryColumns?: FullBoundaryColumn[]
  unmaskedColumns?: number[]
  transitionDegree?: number
  publicInputDigest?: number[]
  blowupFactor?: number
  cosetOffset?: FieldElement
  maskDegree?: number
  numQueries?: number
  maxRemainderSize?: number
  evaluateTransition: (
    current: FieldElement[],
    next: FieldElement[],
    step: number
  ) => FieldElement[]
}

export interface AirEvaluationResult {
  valid: boolean
  transitionFailures: Array<{
    step: number
    constraint: number
    value: FieldElement
  }>
  boundaryFailures: Array<{
    constraint: number
    actual: FieldElement
    expected: FieldElement
  }>
}

export function evaluateAirTrace (
  air: AirDefinition,
  traceRows: FieldElement[][]
): AirEvaluationResult {
  validateAirShape(air, traceRows)

  const transitionFailures: AirEvaluationResult['transitionFailures'] = []
  const boundaryFailures: AirEvaluationResult['boundaryFailures'] = []

  for (let step = 0; step < traceRows.length - 1; step++) {
    const values = air.evaluateTransition(
      traceRows[step],
      traceRows[step + 1],
      step
    )
    values.forEach((value, constraint) => {
      const normalized = F.normalize(value)
      if (normalized !== 0n) {
        transitionFailures.push({
          step,
          constraint,
          value: normalized
        })
      }
    })
  }

  air.boundaryConstraints.forEach((constraint, index) => {
    if (constraint.column < 0 || constraint.column >= air.traceWidth) {
      throw new Error('AIR boundary column out of bounds')
    }
    if (constraint.row < 0 || constraint.row >= traceRows.length) {
      throw new Error('AIR boundary row out of bounds')
    }
    const actual = F.normalize(traceRows[constraint.row][constraint.column])
    const expected = F.normalize(constraint.value)
    if (actual !== expected) {
      boundaryFailures.push({
        constraint: index,
        actual,
        expected
      })
    }
  })

  let fullBoundaryOffset = air.boundaryConstraints.length
  for (const fullColumn of air.fullBoundaryColumns ?? []) {
    if (fullColumn.column < 0 || fullColumn.column >= air.traceWidth) {
      throw new Error('AIR full boundary column out of bounds')
    }
    if (fullColumn.values.length !== traceRows.length) {
      throw new Error('AIR full boundary column length mismatch')
    }
    for (let row = 0; row < traceRows.length; row++) {
      const actual = F.normalize(traceRows[row][fullColumn.column])
      const expected = F.normalize(fullColumn.values[row])
      if (actual !== expected) {
        boundaryFailures.push({
          constraint: fullBoundaryOffset + row,
          actual,
          expected
        })
      }
    }
    fullBoundaryOffset += fullColumn.values.length
  }

  return {
    valid: transitionFailures.length === 0 && boundaryFailures.length === 0,
    transitionFailures,
    boundaryFailures
  }
}

export function assertAirTrace (
  air: AirDefinition,
  traceRows: FieldElement[][]
): void {
  const result = evaluateAirTrace(air, traceRows)
  if (!result.valid) {
    const transition = result.transitionFailures[0]
    if (transition !== undefined) {
      throw new Error(
        `AIR transition constraint ${transition.constraint} failed at step ${transition.step}`
      )
    }
    const boundary = result.boundaryFailures[0]
    if (boundary !== undefined) {
      throw new Error(
        `AIR boundary constraint ${boundary.constraint} failed`
      )
    }
  }
}

function validateAirShape (
  air: AirDefinition,
  traceRows: FieldElement[][]
): void {
  if (!Number.isInteger(air.traceWidth) || air.traceWidth < 1) {
    throw new Error('AIR traceWidth must be positive')
  }
  if (traceRows.length < 2) {
    throw new Error('AIR trace must contain at least two rows')
  }
  assertPowerOfTwo(traceRows.length)
  for (const row of traceRows) {
    if (row.length !== air.traceWidth) {
      throw new Error('AIR trace row width mismatch')
    }
  }
}
