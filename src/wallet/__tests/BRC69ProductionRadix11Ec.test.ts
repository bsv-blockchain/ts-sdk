import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  DUAL_BASE_NEGATIVE_SIGN,
  DUAL_BASE_POSITIVE_SIGN,
  assertProductionRadix11ExceptionalBranchesUnreachable,
  buildProductionEcAir,
  buildProductionEcTrace,
  buildProductionRadix11EcTrace,
  buildProductionRadix11LookupPrototype,
  evaluateAirTrace,
  productionEcMetrics,
  productionEcTracePrivateS,
  productionEcTracePublicA,
  proveProductionEc,
  proveProductionRadix11Ec,
  productionRadix11EcMetrics,
  validateProductionRadix11EcTrace,
  verifyProductionEc,
  verifyProductionRadix11Ec
} from '../brc69/stark/index'
import {
  SECP256K1_N,
  SECP256K1_P,
  compressPoint,
  scalarMultiply
} from '../brc69/circuit/index'

describe('BRC-69 production radix-11 EC segment', () => {
  it('wires positive table rows, private signs, A, S, and compressed S', () => {
    const scalar = SECP256K1_N - 123456789n
    const baseB = scalarMultiply(7n)
    const lookup = buildProductionRadix11LookupPrototype(scalar, baseB)
    const trace = buildProductionRadix11EcTrace(lookup)
    const negativeStep = trace.steps.find(step =>
      step.sign === DUAL_BASE_NEGATIVE_SIGN && step.magnitude > 0
    )
    const zeroStep = trace.steps.find(step => step.magnitude === 0)

    expect(trace.steps).toHaveLength(24)
    expect(trace.publicA).toEqual(scalarMultiply(scalar))
    expect(trace.privateS).toEqual(scalarMultiply(scalar, baseB))
    expect(trace.compressedS).toEqual(compressPoint(trace.privateS))

    expect(negativeStep).toBeDefined()
    expect(negativeStep?.g.tablePoint).toEqual(negativeStep?.tableRow.g)
    expect(negativeStep?.b.tablePoint).toEqual(negativeStep?.tableRow.b)
    expect(negativeStep?.g.selected.x).toBe(negativeStep?.tableRow.g.x)
    expect(negativeStep?.g.selected.y)
      .toBe(SECP256K1_P - (negativeStep?.tableRow.g.y ?? 0n))
    expect(negativeStep?.b.selected.x).toBe(negativeStep?.tableRow.b.x)
    expect(negativeStep?.b.selected.y)
      .toBe(SECP256K1_P - (negativeStep?.tableRow.b.y ?? 0n))

    expect(zeroStep).toBeDefined()
    expect(zeroStep?.sign).toBe(DUAL_BASE_POSITIVE_SIGN)
    expect(zeroStep?.isZero).toBe(1)
    expect(zeroStep?.g.selected.infinity).toBe(true)
    expect(zeroStep?.b.selected.infinity).toBe(true)

    expect(productionRadix11EcMetrics(trace)).toMatchObject({
      steps: 24,
      laneRows: 48,
      selectedRows: 24,
      zeroDigits: 11,
      negativeDigits: 6,
      signedPointNegations: 12,
      selectedInfinityBranches: 22,
      accumulatorInfinityBranches: 2,
      distinctAddBranches: 24,
      doublingBranches: 0,
      oppositeBranches: 0,
      fieldLinearOps: 144,
      fieldMulOps: 96,
      fieldLinearRows: 720,
      fieldMulRows: 1920,
      activeRows: 2688,
      paddedRows: 4096,
      committedWidth: 64
    })
  })

  it('rejects tampered EC wiring and public outputs', () => {
    const scalar = SECP256K1_N - 123456789n
    const lookup = buildProductionRadix11LookupPrototype(
      scalar,
      scalarMultiply(7n)
    )
    const trace = buildProductionRadix11EcTrace(lookup)
    const tamperedSelected = {
      ...trace,
      steps: trace.steps.map(step => ({
        ...step,
        g: { ...step.g },
        b: { ...step.b }
      }))
    }
    tamperedSelected.steps[0].g.selected = tamperedSelected.steps[0].tableRow.g
    expect(() => validateProductionRadix11EcTrace(tamperedSelected))
      .toThrow()

    expect(() => validateProductionRadix11EcTrace({
      ...trace,
      publicA: scalarMultiply(3n)
    })).toThrow()

    expect(() => validateProductionRadix11EcTrace({
      ...trace,
      compressedS: trace.compressedS.map((byte, index) =>
        index === 1 ? byte ^ 1 : byte
      )
    })).toThrow()
  })

  it('proves production radix-11 distinct-add rows as affine field-op bundles', () => {
    const scalar = 1n + (2n << 11n)
    const lookup = buildProductionRadix11LookupPrototype(
      scalar,
      scalarMultiply(7n)
    )
    const trace = buildProductionRadix11EcTrace(lookup)
    const metrics = productionRadix11EcMetrics(trace)

    expect(metrics).toMatchObject({
      steps: 24,
      accumulatorInfinityBranches: 2,
      distinctAddBranches: 2,
      affineAddProofs: 2,
      totalFieldLinearProofs: 12,
      totalFieldMulProofs: 8
    })

    const proof = proveProductionRadix11Ec(trace, {
      numQueries: 2,
      maskSeed: ascii('production-radix11-ec-mask')
    })

    expect(verifyProductionRadix11Ec(trace, proof, { numQueries: 2 }))
      .toBe(true)
    expect(productionRadix11EcMetrics(trace, 16, proof)).toMatchObject({
      affineAddProofs: 2,
      totalFieldLinearProofs: 12,
      totalFieldMulProofs: 8
    })
    expect(productionRadix11EcMetrics(trace, 16, proof).totalProofBytes)
      .toBeGreaterThan(0)
  })

  it('proves production radix-11 EC field operations as one aggregate AIR', () => {
    const scalar = 1n + (2n << 11n)
    const lookup = buildProductionRadix11LookupPrototype(
      scalar,
      scalarMultiply(7n)
    )
    const radixTrace = buildProductionRadix11EcTrace(lookup)
    const trace = buildProductionEcTrace(radixTrace)
    const air = buildProductionEcAir(trace)

    expect(productionEcTracePublicA(trace)).toEqual(radixTrace.publicA)
    expect(productionEcTracePrivateS(trace)).toEqual(radixTrace.privateS)
    expect(compressPoint(productionEcTracePrivateS(trace)))
      .toEqual(radixTrace.compressedS)
    expect(trace.layout.width).toBe(526)
    expect(trace.publicInput.activeRows).toBe(5280)
    expect(trace.publicInput.paddedRows).toBe(8192)
    expect(trace.publicInput.schedule).toHaveLength(480)
    expect(evaluateAirTrace(air, trace.rows).valid).toBe(true)

    const proof = proveProductionEc(trace, {
      numQueries: 2,
      maskSeed: ascii('production-ec-aggregate-mask')
    })

    expect(verifyProductionEc(trace.publicInput, proof, { numQueries: 2 }))
      .toBe(true)
    expect(verifyProductionEc({
      ...trace.publicInput,
      publicA: scalarMultiply(3n)
    }, proof, { numQueries: 2 })).toBe(false)
    expect(productionEcMetrics(trace, proof)).toMatchObject({
      activeRows: 5280,
      paddedRows: 8192,
      traceWidth: 526,
      scheduledAdditions: 48,
      distinctAddBranches: 2,
      linearOps: 288,
      mulOps: 192
    })
    expect(productionEcMetrics(trace, proof).proofBytes).toBeGreaterThan(0)
  })

  it('uses the same aggregate EC public schedule for sparse and max fixtures', () => {
    const sparse = buildProductionEcTrace(buildProductionRadix11EcTrace(
      buildProductionRadix11LookupPrototype(1n + (2n << 11n), scalarMultiply(7n))
    ))
    const scalar = SECP256K1_N - 123456789n
    const lookup = buildProductionRadix11LookupPrototype(
      scalar,
      scalarMultiply(7n)
    )
    const radixTrace = buildProductionRadix11EcTrace(lookup)
    const trace = buildProductionEcTrace(radixTrace)

    expect(trace.publicInput.schedule).toEqual(sparse.publicInput.schedule)
    expect(evaluateAirTrace(buildProductionEcAir(trace), trace.rows).valid)
      .toBe(true)
    expect(productionEcMetrics(trace)).toMatchObject({
      activeRows: 5280,
      paddedRows: 8192,
      traceWidth: 526,
      scheduledAdditions: 48,
      distinctAddBranches: 24,
      linearOps: 288,
      mulOps: 192
    })
  })

  it('rules out EC doubling/opposite branches from scalar radix bounds', () => {
    const baseB = scalarMultiply(7n)
    const scalars = [
      1n,
      1n + (2n << 11n),
      (1n << 253n) - 1n,
      SECP256K1_N - 123456789n,
      ...deterministicScalars(4)
    ]

    for (const scalar of scalars) {
      const lookup = buildProductionRadix11LookupPrototype(scalar, baseB)
      expect(() => assertProductionRadix11ExceptionalBranchesUnreachable(lookup))
        .not.toThrow()
      const trace = buildProductionRadix11EcTrace(lookup)
      const metrics = productionRadix11EcMetrics(trace)
      expect(metrics.doublingBranches).toBe(0)
      expect(metrics.oppositeBranches).toBe(0)

      const aggregate = buildProductionEcTrace(trace)
      const exceptional = aggregate.rows.filter(row =>
        row[aggregate.layout.branchDoubling] !== 0n ||
        row[aggregate.layout.branchOpposite] !== 0n
      )
      expect(exceptional).toHaveLength(0)
    }
  })

  it('fails aggregate EC AIR if an exceptional branch is selected', () => {
    const lookup = buildProductionRadix11LookupPrototype(
      1n + (2n << 11n),
      scalarMultiply(7n)
    )
    const trace = buildProductionEcTrace(buildProductionRadix11EcTrace(lookup))
    const rowIndex = trace.rows.findIndex(row =>
      row[trace.layout.branchDistinctAdd] === 1n
    )
    if (rowIndex < 0) throw new Error('distinct-add row missing')
    const tampered = trace.rows.map(row => row.slice())
    tampered[rowIndex][trace.layout.branchDistinctAdd] = 0n
    tampered[rowIndex][trace.layout.branchDoubling] = 1n

    expect(evaluateAirTrace(buildProductionEcAir(trace), tampered).valid)
      .toBe(false)
  })

  it('rejects tampered aggregate EC field-operation rows', () => {
    const scalar = 1n + (2n << 11n)
    const lookup = buildProductionRadix11LookupPrototype(
      scalar,
      scalarMultiply(7n)
    )
    const trace = buildProductionEcTrace(buildProductionRadix11EcTrace(lookup))
    const tampered = trace.rows.map(row => row.slice())
    tampered[0][trace.layout.c52] += 1n

    expect(evaluateAirTrace(buildProductionEcAir(trace), tampered).valid)
      .toBe(false)
  })

  it('rejects tampered aggregate EC carry range witnesses', () => {
    const scalar = 1n + (2n << 11n)
    const lookup = buildProductionRadix11LookupPrototype(
      scalar,
      scalarMultiply(7n)
    )
    const trace = buildProductionEcTrace(buildProductionRadix11EcTrace(lookup))
    const tampered = trace.rows.map(row => row.slice())
    tampered[0][trace.layout.carryBits] =
      tampered[0][trace.layout.carryBits] === 0n ? 1n : 0n

    expect(evaluateAirTrace(buildProductionEcAir(trace), tampered).valid)
      .toBe(false)
  })

  it('rejects tampered aggregate EC limb range witnesses', () => {
    const scalar = 1n + (2n << 11n)
    const lookup = buildProductionRadix11LookupPrototype(
      scalar,
      scalarMultiply(7n)
    )
    const trace = buildProductionEcTrace(buildProductionRadix11EcTrace(lookup))
    const tampered = trace.rows.map(row => row.slice())
    tampered[0][trace.layout.rangeBits] =
      tampered[0][trace.layout.rangeBits] === 0n ? 1n : 0n

    expect(evaluateAirTrace(buildProductionEcAir(trace), tampered).valid)
      .toBe(false)
  })

  it('rejects tampered aggregate EC canonical field witnesses', () => {
    const scalar = 1n + (2n << 11n)
    const lookup = buildProductionRadix11LookupPrototype(
      scalar,
      scalarMultiply(7n)
    )
    const trace = buildProductionEcTrace(buildProductionRadix11EcTrace(lookup))
    const tampered = trace.rows.map(row => row.slice())
    tampered[0][trace.layout.canonicalBits] =
      tampered[0][trace.layout.canonicalBits] === 0n ? 1n : 0n

    expect(evaluateAirTrace(buildProductionEcAir(trace), tampered).valid)
      .toBe(false)
  })

  it('rejects tampered EC accumulator outputs', () => {
    const scalar = 1n + (2n << 11n)
    const lookup = buildProductionRadix11LookupPrototype(
      scalar,
      scalarMultiply(7n)
    )
    const trace = buildProductionEcTrace(buildProductionRadix11EcTrace(lookup))
    const bSchedule = trace.publicInput.schedule.filter(row => row.lane === 'B')
    const finalB = bSchedule[bSchedule.length - 1]
    if (finalB === undefined) throw new Error('missing final B operation')
    const tampered = trace.rows.map(row => row.slice())
    tampered[finalB.row + finalB.rows - 1][trace.layout.afterX] += 1n

    expect(evaluateAirTrace(buildProductionEcAir(trace), tampered).valid)
      .toBe(false)
  })

  it('rejects EC proof bundles linked to the wrong production lane', () => {
    const scalar = 1n + (2n << 11n)
    const lookup = buildProductionRadix11LookupPrototype(
      scalar,
      scalarMultiply(7n)
    )
    const trace = buildProductionRadix11EcTrace(lookup)
    const proof = proveProductionRadix11Ec(trace, {
      numQueries: 2,
      maskSeed: ascii('production-radix11-ec-negative-mask')
    })
    const tampered = {
      addProofs: proof.addProofs.map((item, index) => {
        return index === 0 ? { ...item, step: item.step + 1 } : item
      })
    }

    expect(verifyProductionRadix11Ec(trace, tampered, { numQueries: 2 }))
      .toBe(false)
  })
})

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}

function deterministicScalars (count: number): bigint[] {
  let state = 0x123456789abcdefn
  const out: bigint[] = []
  for (let i = 0; i < count; i++) {
    state = (state * 6364136223846793005n + 1442695040888963407n) %
      SECP256K1_N
    out.push(state === 0n ? 1n : state)
  }
  return out
}
