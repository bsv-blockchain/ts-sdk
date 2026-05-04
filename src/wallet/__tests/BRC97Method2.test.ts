import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  computeInvoiceNumber,
  compressPoint,
  createSpecificKeyLinkageProof,
  BRC97_METHOD2_COMPOSITE_DOMAIN,
  BRC97_METHOD2_REDUCED_TEST_PROFILE,
  hmacSha256,
  normalizeSpecificKeyLinkageCounterparty,
  parseSpecificKeyLinkageProofPayload,
  pointAdd,
  pointDouble,
  scalarMultiply,
  serializeSpecificKeyLinkageProofPayload,
  serializeStarkProof,
  verifySpecificKeyLinkageProof,
  SECP256K1_G,
  SECP256K1_N,
  SECP256K1_P,
  METHOD2_SHA256_INITIAL_STATE,
  METHOD2_V2_FINAL_WINDOW_BITS,
  METHOD2_V2_FIELD_MUL_LAYOUT,
  METHOD2_V2_FULL_WINDOWS,
  METHOD2_V2_MIXED_ADD_LAYOUT,
  METHOD2_V2_WINDOW_BITS,
  METHOD2_V2_WINDOW_COUNT,
  METHOD2_VM_LAYOUT,
  Method2VmBuilder,
  Method2VmOp,
  Method2VmRegisterProgramBuilder,
  appendMethod2VmFieldAdd,
  appendMethod2VmFieldElement,
  appendMethod2VmFieldMul,
  appendMethod2VmFieldSub,
  appendMethod2VmCompressedPoint,
  appendMethod2VmFixedBaseScalarMul,
  appendMethod2VmPoint,
  appendMethod2VmPointAddDistinct,
  appendMethod2VmPointDouble,
  appendMethod2VmPointMux,
  appendMethod2VmRegisterizedFixedBaseScalarMul,
  appendMethod2VmRegisterizedScalarMulCompressedPoint,
  appendMethod2VmRegisterizedScalarMulHmacInput,
  appendMethod2VmRegisterizedScalarMul,
  appendMethod2VmScalarMul,
  buildMethod2V2ScalarCoreAir,
  buildMethod2V2ScalarCoreTrace,
  buildMethod2V2Trace,
  buildMethod2VmScalarMulProgram,
  buildMethod2VmScalarMulVerifierProgram,
  buildMethod2Sha256BlockAir,
  buildMethod2Sha256BlockTrace,
  buildMethod2VmAir,
  evaluateAirTrace,
  F,
  method2PublicInputDigest,
  method2V2FieldMulMetrics,
  method2V2ProjectedEcRows,
  method2V2ScalarCoreFeasibility,
  method2V2MixedAddMetrics,
  method2V2Metrics,
  method2V2PublicInputDigest,
  method2V2ShaHmacModel,
  proveMethod2V2ScalarCore,
  proveMethod2V2FieldMul,
  affineToJacobian,
  buildMethod2V2FieldMulAir,
  buildMethod2V2FieldMulTrace,
  evaluateMethod2V2MixedAddConstraints,
  proveMethod2Vm,
  secpFieldAdd,
  secpFieldMul,
  secpFieldSub,
  sha256CompressBlock,
  sha256Pad,
  validateMethod2V2Trace,
  validateMethod2VmProgram,
  verifyMethod2V2FieldMul,
  verifyMethod2V2ScalarCore,
  verifyMethod2Vm,
  writeMethod2V2MixedAddWitness
} from '../brc97/index'
import type { Method2VmProgram } from '../brc97/index'
import {
  METHOD2_SCALAR_LAYOUT,
  evaluateMethod2ScalarConstraints,
  writeMethod2ScalarWitness
} from '../brc97/method2/Method2Scalar'
import { METHOD2_FIELD_LAYOUT } from '../brc97/method2/Method2Field'
import {
  METHOD2_POINT_LAYOUT,
  evaluateMethod2CompressedPointConstraints,
  evaluateMethod2PointConstraints,
  writeMethod2PointWitness
} from '../brc97/method2/Method2Point'
import {
  METHOD2_POINT_ADD_DISTINCT_LAYOUT,
  METHOD2_POINT_DOUBLE_LAYOUT,
  evaluateMethod2PointAddDistinctConstraints,
  evaluateMethod2PointDoubleConstraints,
  writeMethod2PointAddDistinctWitness,
  writeMethod2PointDoubleWitness
} from '../brc97/method2/Method2PointOps'
import {
  evaluateMethod2HmacPlannerConstraints,
  method2HmacLayout,
  writeMethod2HmacWitness
} from '../brc97/method2/Method2Hmac'

describe('BRC-97 Method 2 proof type 1', () => {
  it.skip('computes invoice numbers with existing wallet normalization rules', () => {
    expect(computeInvoiceNumber([0, ' TestProtocol '], '12345')).toBe(
      '0-testprotocol-12345'
    )
    expect(() => computeInvoiceNumber([3 as 0, 'testprotocol'], 'x')).toThrow()
    expect(() => computeInvoiceNumber([0, 'bad!!'], 'x')).toThrow()
  })

  it.skip('normalizes special counterparties to concrete public keys', () => {
    const prover = hex(compressPoint(scalarMultiply(7n)))
    expect(normalizeSpecificKeyLinkageCounterparty('self', prover)).toBe(prover)
    expect(normalizeSpecificKeyLinkageCounterparty('anyone', prover)).toBe(
      hex(compressPoint(SECP256K1_G))
    )
  })

  it('builds and validates the V2 shared-digit fixed-window Method 2 core', () => {
    const scalar = 7n
    const counterpartyScalar = 11n
    const statement = statementFor(scalar, counterpartyScalar)
    const publicA = scalarMultiply(scalar)
    const counterpartyB = scalarMultiply(counterpartyScalar)
    const invoice = ascii(computeInvoiceNumber(
      statement.protocolID,
      statement.keyID
    ))
    const trace = buildMethod2V2Trace(
      scalar,
      publicA,
      counterpartyB,
      invoice,
      statement.linkage
    )

    expect(trace.digits).toHaveLength(METHOD2_V2_WINDOW_COUNT)
    expect(trace.digits[0]).toBe(7)
    expect(trace.digits.slice(1).every(digit => digit === 0)).toBe(true)
    expect(trace.rows.filter(row => row.phase === 'accumulate'))
      .toHaveLength(METHOD2_V2_WINDOW_COUNT)
    expect(trace.rows.filter(row => row.phase === 'select'))
      .toHaveLength(METHOD2_V2_FULL_WINDOWS * (1 << METHOD2_V2_WINDOW_BITS) +
        (1 << METHOD2_V2_FINAL_WINDOW_BITS))
    expect(() => validateMethod2V2Trace(trace)).not.toThrow()

    const metrics = method2V2Metrics(trace)
    expect(metrics.activeRows).toBe(2747)
    expect(metrics.paddedRows).toBe(4096)
    expect(metrics.ldeRows).toBe(65536)
    expect(metrics.innerShaBlocks).toBeGreaterThanOrEqual(2)
    expect(metrics.outerShaBlocks).toBe(2)

    const tampered = {
      ...trace,
      digits: trace.digits.slice(),
      rows: trace.rows.map(row => ({ ...row }))
    }
    tampered.digits[0] = 6
    expect(() => validateMethod2V2Trace(tampered)).toThrow()

    expect(() => buildMethod2V2Trace(
      scalar,
      publicA,
      counterpartyB,
      invoice,
      statement.linkage.map((byte, index) => index === 0 ? byte ^ 1 : byte)
    )).toThrow()
  })

  it('binds V2 profile identifiers and exact invoice bytes in the public input digest', () => {
    const statement = statementFor(7n, 11n)
    const invoice = ascii(computeInvoiceNumber(
      statement.protocolID,
      statement.keyID
    ))
    const digest = method2V2PublicInputDigest(statement, invoice)
    const changedDigest = method2V2PublicInputDigest(statement, invoice.concat([0]))

    expect(digest).toHaveLength(32)
    expect(changedDigest).toHaveLength(32)
    expect(hex(digest)).not.toBe(hex(changedDigest))
    expect(hex(method2PublicInputDigest(statement))).toBe(hex(digest))
  })

  it('enforces V2 scalar-core AIR constraints for selectors, digits, and accumulators', () => {
    const trace = v2TraceFixture()
    const coreTrace = buildMethod2V2ScalarCoreTrace(trace)
    const air = buildMethod2V2ScalarCoreAir(trace)

    expect(evaluateAirTrace(air, coreTrace.rows).valid).toBe(true)

    const selectorOffset = 8
    const selectedGOffset = 13
    const accScalarAfterOffset = 16
    const accGAfterOffset = 19

    const missingSelector = cloneTrace(coreTrace.rows)
    missingSelector[7][selectorOffset] = 0n
    expect(evaluateAirTrace(air, missingSelector).valid).toBe(false)

    const extraSelector = cloneTrace(coreTrace.rows)
    extraSelector[8][selectorOffset] = 1n
    expect(evaluateAirTrace(air, extraSelector).valid).toBe(false)

    const badSelectedPoint = cloneTrace(coreTrace.rows)
    badSelectedPoint[7][selectedGOffset] += 1n
    expect(evaluateAirTrace(air, badSelectedPoint).valid).toBe(false)

    const badScalarAccumulator = cloneTrace(coreTrace.rows)
    const firstAccumulationRow = 64
    badScalarAccumulator[firstAccumulationRow][accScalarAfterOffset] += 1n
    expect(evaluateAirTrace(air, badScalarAccumulator).valid).toBe(false)

    const badPointAccumulator = cloneTrace(coreTrace.rows)
    badPointAccumulator[firstAccumulationRow][accGAfterOffset] += 1n
    expect(evaluateAirTrace(air, badPointAccumulator).valid).toBe(false)
  })

  it('emits the V2 scalar-core feasibility proof with reduced STARK settings', () => {
    const trace = v2TraceFixture()
    const proof = proveMethod2V2ScalarCore(trace, {
      blowupFactor: 4,
      numQueries: 4,
      maxRemainderSize: 16,
      maskDegree: 1,
      cosetOffset: 3n,
      maskSeed: ascii('method2-v2-scalar-core-mask')
    })
    const feasibility = method2V2ScalarCoreFeasibility(trace, proof)

    expect(verifyMethod2V2ScalarCore(trace, proof)).toBe(true)
    expect(feasibility.activeRows).toBe(2747)
    expect(feasibility.paddedRows).toBe(4096)
    expect(feasibility.traceWidth).toBe(21)
    expect(feasibility.ldeRows).toBe(65536)
    expect(feasibility.proofBytes).toBeGreaterThan(0)
  })

  it('validates one V2 Jacobian mixed-add block with 29-bit limbs', () => {
    const accumulator = affineToJacobian(scalarMultiply(7n))
    const selected = scalarMultiply(11n)
    const witness = writeMethod2V2MixedAddWitness(accumulator, selected)

    expect(evaluateMethod2V2MixedAddConstraints(witness.row)
      .every(value => value === 0n)).toBe(true)
    expect(pointEquals(witness.affineOutput, pointAdd(
      scalarMultiply(7n),
      selected
    ))).toBe(true)

    const tampered = witness.row.slice()
    tampered[METHOD2_V2_MIXED_ADD_LAYOUT.x3] += 1n
    expect(() => evaluateMethod2V2MixedAddConstraints(tampered)).not.toThrow()
    expect(evaluateMethod2V2MixedAddConstraints(tampered)
      .every(value => value === 0n)).toBe(false)

    expect(() => writeMethod2V2MixedAddWitness(
      accumulator,
      scalarMultiply(7n)
    )).toThrow('excludes H = 0')

    expect(method2V2MixedAddMetrics()).toEqual({
      limbBits: 29,
      limbCount: 9,
      fieldElements: 26,
      oneRowWidth: 234,
      transitionDegreeEstimate: 2,
      mixedAddCountForMethod2: 86,
      naiveFullWidthColumnsFor86Adds: 234
    })
  })

  it('proves and verifies a V2 29-bit field multiplication AIR', () => {
    const a = scalarMultiply(7n).x
    const b = scalarMultiply(11n).x
    const trace = buildMethod2V2FieldMulTrace(a, b)
    const air = buildMethod2V2FieldMulAir(trace)

    expect(evaluateAirTrace(air, trace.rows).valid).toBe(true)

    const tampered = cloneTrace(trace.rows)
    tampered[0][METHOD2_V2_FIELD_MUL_LAYOUT.c] += 1n
    expect(evaluateAirTrace(air, tampered).valid).toBe(false)

    const badCarry = cloneTrace(trace.rows)
    badCarry[1][METHOD2_V2_FIELD_MUL_LAYOUT.carryIn] += 1n
    expect(evaluateAirTrace(air, badCarry).valid).toBe(false)

    const proof = proveMethod2V2FieldMul(trace, {
      blowupFactor: 4,
      numQueries: 4,
      maxRemainderSize: 16,
      maskDegree: 1,
      cosetOffset: 3n,
      maskSeed: ascii('method2-v2-field-mul-mask')
    })

    expect(verifyMethod2V2FieldMul(trace, proof)).toBe(true)
    expect(method2V2FieldMulMetrics(proof)).toMatchObject({
      limbBits: 29,
      limbCount: 9,
      activeRows: 18,
      paddedRows: 32,
      traceWidth: 95,
      carryBits: 37,
      multiplicationTermsPerRowMax: 9
    })
  })

  it('models V2 SHA/HMAC rows and width for max invoice sizes', () => {
    const typical = method2V2ShaHmacModel(
      computeInvoiceNumber([0, 'testprotocol'], 'key-1').length
    )
    const ordinaryMax = method2V2ShaHmacModel(
      computeInvoiceNumber([0, 'a'.repeat(400)], 'k'.repeat(800)).length
    )
    const absoluteMax = method2V2ShaHmacModel(
      computeInvoiceNumber([
        0,
        `specific linkage revelation ${'a'.repeat(402)}`
      ], 'k'.repeat(800)).length
    )

    expect(typical.counts).toMatchObject({
      invoiceLength: 20,
      innerBlocks: 2,
      outerBlocks: 2,
      totalBlocks: 4
    })
    expect(ordinaryMax.counts).toMatchObject({
      invoiceLength: 1203,
      innerBlocks: 20,
      outerBlocks: 2,
      totalBlocks: 22
    })
    expect(absoluteMax.counts).toMatchObject({
      invoiceLength: 1233,
      innerBlocks: 21,
      outerBlocks: 2,
      totalBlocks: 23
    })

    expect(absoluteMax.currentWideRound).toMatchObject({
      activeRows: 1495,
      paddedRows: 2048,
      privateWidth: 1616
    })
    expect(absoluteMax.bitSerial).toMatchObject({
      activeRows: 47624,
      paddedRows: 65536,
      privateWidth: 64,
      publicWidth: 18
    })
    expect(method2V2ProjectedEcRows()).toBe(20296)
    expect(absoluteMax.segmentedWithCurrentWideRound).toMatchObject({
      totalActiveRows: 24538,
      totalPaddedRows: 32768,
      maxPrivateWidth: 1616
    })
    expect(absoluteMax.segmentedWithBitSerial).toMatchObject({
      totalActiveRows: 70667,
      totalPaddedRows: 131072,
      maxPrivateWidth: 95
    })
  })

  it.skip('enforces the narrow row-serialized Method 2 VM substrate', () => {
    const program = new Method2VmBuilder()
      .assertByte(255)
      .assertU16(65535)
      .assertAdd(7n, 9n, 16n)
      .assertMul(7n, 9n, 63n)
      .copyNextA(42n)
      .assertEq(42n, 42n)
      .assertBool(1)
      .assertXorConstByteLinked(0xab, 0x36, 0x9d, 'a')
      .assertEq(0x9d, 0x9d)
      .noop()
      .build()

    expect(METHOD2_VM_LAYOUT.width).toBeLessThan(4096)
    expect(() => validateMethod2VmProgram(program)).not.toThrow()
    expect(evaluateAirTrace(buildMethod2VmAir(program), program.trace.rows).valid)
      .toBe(true)

    const proof = proveMethod2Vm(program, testStarkOptions())
    expect(verifyMethod2Vm(program, proof, testStarkOptions())).toBe(true)

    const badSelector = cloneVmProgram(program)
    badSelector.trace.rows[0][METHOD2_VM_LAYOUT.selectorStart + 4] = 0n
    expect(() => validateMethod2VmProgram(badSelector)).toThrow()

    const badByteBit = cloneVmProgram(program)
    badByteBit.trace.rows[0][METHOD2_VM_LAYOUT.auxStart] = 2n
    expect(() => validateMethod2VmProgram(badByteBit)).toThrow()

    expect(() => new Method2VmBuilder()
      .assertXorConstByteLinked(256, 0x36, 0x36, 'a'))
      .toThrow()
    expect(() => new Method2VmBuilder()
      .assertXorConstByteLinked(0xab, 0x36, 0xab, 'a'))
      .toThrow()

    const badCopy = cloneVmProgram(program)
    badCopy.trace.rows[5][METHOD2_VM_LAYOUT.a] = 41n
    expect(() => validateMethod2VmProgram(badCopy)).toThrow()

    const badPadding = cloneVmProgram(program)
    badPadding.trace.rows[badPadding.trace.rows.length - 1][METHOD2_VM_LAYOUT.a] = 1n
    expect(() => validateMethod2VmProgram(badPadding)).toThrow()

    const tamperedProof = {
      ...proof,
      traceOpenings: proof.traceOpenings.map(opening => ({
        rowIndex: opening.rowIndex,
        row: opening.row.slice(),
        path: opening.path
      }))
    }
    tamperedProof.traceOpenings[0].row[METHOD2_VM_LAYOUT.a] += 1n
    expect(verifyMethod2Vm(program, tamperedProof, testStarkOptions())).toBe(false)
  })

  it.skip('enforces explicit Method 2 VM row-to-row dataflow links', () => {
    const program = new Method2VmBuilder()
      .assertAddLinked(7n, 9n, 16n, 'a')
      .assertMulLinked(16n, 4n, 64n, 'a')
      .assertEqLinked(64n, 64n, 'a')
      .assertEq(64n, 64n)
      .assertBoolLinked(1, 'a')
      .assertEq(1n, 1n)
      .build()

    expect(() => validateMethod2VmProgram(program)).not.toThrow()
    expect(evaluateAirTrace(buildMethod2VmAir(program), program.trace.rows).valid)
      .toBe(true)

    const proof = proveMethod2Vm(program, testStarkOptions())
    expect(verifyMethod2Vm(program, proof, testStarkOptions())).toBe(true)

    const badAddLink = cloneVmProgram(program)
    badAddLink.trace.rows[1][METHOD2_VM_LAYOUT.a] = 15n
    expect(() => validateMethod2VmProgram(badAddLink)).toThrow()

    const badMulLink = cloneVmProgram(program)
    badMulLink.trace.rows[2][METHOD2_VM_LAYOUT.a] = 63n
    expect(() => validateMethod2VmProgram(badMulLink)).toThrow()

    const badEqLink = cloneVmProgram(program)
    badEqLink.trace.rows[3][METHOD2_VM_LAYOUT.a] = 0n
    expect(() => validateMethod2VmProgram(badEqLink)).toThrow()

    const badUnusedAux = cloneVmProgram(program)
    badUnusedAux.trace.rows[0][METHOD2_VM_LAYOUT.auxStart + 8] = 1n
    expect(() => validateMethod2VmProgram(badUnusedAux)).toThrow()
  })

  it.skip('enforces carry links across Method 2 VM field-limb rows', () => {
    const program = new Method2VmBuilder()
      .assertFieldAddLimbCarryLinked(65535, 1, 0, 0, 0, 0, 1)
      .assertFieldAddLimb(0, 0, 1, 0, 0, 1, 0)
      .build()

    expect(() => validateMethod2VmProgram(program)).not.toThrow()
    expect(evaluateAirTrace(buildMethod2VmAir(program), program.trace.rows).valid)
      .toBe(true)

    const badCarryLink = cloneVmProgram(program)
    badCarryLink.trace.rows[1][METHOD2_VM_LAYOUT.c] = 0n
    badCarryLink.trace.rows[1][METHOD2_VM_LAYOUT.auxStart + 2] = 0n
    expect(() => validateMethod2VmProgram(badCarryLink)).toThrow()

    const badCarryFlag = cloneVmProgram(program)
    badCarryFlag.trace.rows[0][METHOD2_VM_LAYOUT.auxStart + 7] = 0n
    expect(() => validateMethod2VmProgram(badCarryFlag)).toThrow()
  })

  it.skip('builds a registerized Method 2 VM program with fixed dataflow controls', () => {
    const registerBuilder = new Method2VmRegisterProgramBuilder()
      .seed(3n)
      .add(5n)
      .select(12n, 0)
      .mul(9n)
      .assertEq(72n)

    expect(registerBuilder.value()).toBe(72n)
    const program = registerBuilder.build()
    expect(program.fixedCells?.length).toBeGreaterThan(0)
    expect(() => validateMethod2VmProgram(program)).not.toThrow()

    const proof = proveMethod2Vm(program, testStarkOptions())
    expect(verifyMethod2Vm(program, proof, testStarkOptions())).toBe(true)

    const badRegisterLink = cloneVmProgram(program)
    badRegisterLink.trace.rows[2][METHOD2_VM_LAYOUT.a] = 71n
    expect(() => validateMethod2VmProgram(badRegisterLink)).toThrow()

    const badControlFlag = cloneVmProgram(program)
    badControlFlag.trace.rows[0][METHOD2_VM_LAYOUT.auxStart] = 0n
    expect(() => validateMethod2VmProgram(badControlFlag)).toThrow()
  })

  it.skip('enforces Method 2 VM select and point mux rows', () => {
    const left = scalarMultiply(7n)
    const right = scalarMultiply(11n)
    const builder = new Method2VmBuilder()
    builder.assertSelectLinked(4n, 9n, 1, 9n, 'a').assertEq(9n, 9n)
    const selectedLeft = appendMethod2VmPointMux(builder, 0, left, right)
    const selectedRight = appendMethod2VmPointMux(builder, 1, left, right)

    expect(pointEquals(selectedLeft, left)).toBe(true)
    expect(pointEquals(selectedRight, right)).toBe(true)
    const program = builder.build()
    expect(() => validateMethod2VmProgram(program)).not.toThrow()

    const badSelectBit = cloneVmProgram(program)
    badSelectBit.trace.rows[0][METHOD2_VM_LAYOUT.auxStart] = 2n
    expect(() => validateMethod2VmProgram(badSelectBit)).toThrow()

    const badSelectedValue = cloneVmProgram(program)
    badSelectedValue.trace.rows[0][METHOD2_VM_LAYOUT.c] = 4n
    expect(() => validateMethod2VmProgram(badSelectedValue)).toThrow()

    const badMuxCarry = cloneVmProgram(program)
    const muxRow = findVmOpRow(badMuxCarry, Method2VmOp.SelectBit)
    badMuxCarry.trace.rows[muxRow + 1][METHOD2_VM_LAYOUT.a] += 1n
    expect(() => validateMethod2VmProgram(badMuxCarry)).toThrow()
  })

  it.skip('enforces row-serialized secp256k1 field arithmetic in the Method 2 VM', () => {
    const a = 0xffffffffffffffffn
    const b = 0x123456789abcdefn
    const builder = new Method2VmBuilder()

    const maxWitness = appendMethod2VmFieldElement(builder, SECP256K1_P - 1n)
    expect(maxWitness.value).toBe(SECP256K1_P - 1n)
    expect(() => appendMethod2VmFieldElement(
      new Method2VmBuilder(),
      SECP256K1_P
    )).toThrow()

    expect(appendMethod2VmFieldAdd(builder, a, b).value)
      .toBe(secpFieldAdd(a, b))
    expect(appendMethod2VmFieldAdd(
      builder,
      SECP256K1_P - 10n,
      20n
    ).value).toBe(10n)
    expect(appendMethod2VmFieldSub(builder, a, b).value)
      .toBe(secpFieldSub(a, b))
    expect(appendMethod2VmFieldSub(builder, 7n, 11n).value)
      .toBe(secpFieldSub(7n, 11n))
    expect(appendMethod2VmFieldMul(builder, a, b).result)
      .toBe(secpFieldMul(a, b))

    const program = builder.build()
    expect(METHOD2_VM_LAYOUT.width).toBeLessThan(4096)
    expect(() => validateMethod2VmProgram(program)).not.toThrow()
    expect(evaluateAirTrace(buildMethod2VmAir(program), program.trace.rows).valid)
      .toBe(true)

    const badAddCarry = cloneVmProgram(program)
    badAddCarry.trace.rows[findVmOpRow(
      badAddCarry,
      Method2VmOp.FieldAddLimb
    )][METHOD2_VM_LAYOUT.auxStart + 3] += 1n
    expect(() => validateMethod2VmProgram(badAddCarry)).toThrow()

    const badSubWrap = cloneVmProgram(program)
    badSubWrap.trace.rows[findVmOpRow(
      badSubWrap,
      Method2VmOp.FieldSubLimb
    )][METHOD2_VM_LAYOUT.auxStart + 1] ^= 1n
    expect(() => validateMethod2VmProgram(badSubWrap)).toThrow()

    const badMulCarry = cloneVmProgram(program)
    badMulCarry.trace.rows[findVmOpRow(
      badMulCarry,
      Method2VmOp.FieldMulLimb
    )][METHOD2_VM_LAYOUT.auxStart + 1] += 1n
    expect(() => validateMethod2VmProgram(badMulCarry)).toThrow()

    const badU48Limb = cloneVmProgram(program)
    const u48Row = findVmOpRow(badU48Limb, Method2VmOp.U48)
    badU48Limb.trace.rows[u48Row][METHOD2_VM_LAYOUT.b] += 1n
    expect(() => validateMethod2VmProgram(badU48Limb)).toThrow()
  })

  it.skip('enforces row-serialized point validation and compressed encoding in the Method 2 VM', () => {
    const point = scalarMultiply(7n)
    const builder = new Method2VmBuilder()
    const witness = appendMethod2VmPoint(builder, point)
    const encoded = appendMethod2VmCompressedPoint(builder, point)

    expect(witness.compressed).toEqual(compressPoint(point))
    expect(encoded).toEqual(compressPoint(point))
    expect(() => appendMethod2VmPoint(
      new Method2VmBuilder(),
      { x: 1n, y: 1n }
    )).toThrow()

    const program = builder.build()
    expect(() => validateMethod2VmProgram(program)).not.toThrow()

    const badCurveMul = cloneVmProgram(program)
    badCurveMul.trace.rows[findVmOpRow(
      badCurveMul,
      Method2VmOp.FieldMulLimb
    )][METHOD2_VM_LAYOUT.auxStart + 1] += 1n
    expect(() => validateMethod2VmProgram(badCurveMul)).toThrow()

    const badCompressedByte = cloneVmProgram(program)
    badCompressedByte.trace.rows[findVmOpRow(
      badCompressedByte,
      Method2VmOp.Byte
    )][METHOD2_VM_LAYOUT.auxStart] ^= 1n
    expect(() => validateMethod2VmProgram(badCompressedByte)).toThrow()
  })

  it.skip('enforces row-serialized point double and distinct point add in the Method 2 VM', () => {
    const left = scalarMultiply(7n)
    const right = scalarMultiply(11n)
    const builder = new Method2VmBuilder()
    const doubled = appendMethod2VmPointDouble(builder, left)
    const added = appendMethod2VmPointAddDistinct(builder, left, right)

    expect(pointEquals(doubled, pointDouble(left))).toBe(true)
    expect(pointEquals(added, pointAdd(left, right))).toBe(true)
    expect(() => appendMethod2VmPointAddDistinct(
      new Method2VmBuilder(),
      left,
      left
    )).toThrow()

    const program = builder.build()
    expect(() => validateMethod2VmProgram(program)).not.toThrow()

    const badDoubleRelation = cloneVmProgram(program)
    badDoubleRelation.trace.rows[findVmOpRow(
      badDoubleRelation,
      Method2VmOp.FieldAddLimb
    )][METHOD2_VM_LAYOUT.auxStart + 3] += 1n
    expect(() => validateMethod2VmProgram(badDoubleRelation)).toThrow()

    const badAddRelation = cloneVmProgram(program)
    badAddRelation.trace.rows[findVmOpRow(
      badAddRelation,
      Method2VmOp.FieldSubLimb
    )][METHOD2_VM_LAYOUT.auxStart + 2] += 1n
    expect(() => validateMethod2VmProgram(badAddRelation)).toThrow()
  })

  it.skip('enforces reduced row-serialized scalar multiplication in the Method 2 VM', () => {
    const base = scalarMultiply(11n)
    const builder = new Method2VmBuilder()
    const fixed = appendMethod2VmFixedBaseScalarMul(builder, 7n, 3)
    const variable = appendMethod2VmScalarMul(builder, 7n, base, 3)

    expect(pointEquals(fixed.output, scalarMultiply(7n))).toBe(true)
    expect(pointEquals(variable.output, scalarMultiply(7n, base))).toBe(true)
    expect(fixed.scalar.bits.slice(0, 3)).toEqual([1, 1, 1])
    expect(fixed.scalar.decrementedBits.slice(0, 3)).toEqual([0, 1, 1])
    expect(fixed.activeBits).toBe(3)
    expect(variable.activeBits).toBe(3)
    expect(() => appendMethod2VmScalarMul(
      new Method2VmBuilder(),
      8n,
      base,
      3
    )).toThrow()
    expect(() => appendMethod2VmScalarMul(
      new Method2VmBuilder(),
      0n,
      base,
      3
    )).toThrow()

    const program = builder.build()
    expect(METHOD2_VM_LAYOUT.width).toBeLessThan(4096)
    expect(() => validateMethod2VmProgram(program)).not.toThrow()
    expect(evaluateAirTrace(buildMethod2VmAir(program), program.trace.rows).valid)
      .toBe(true)

    const badBorrowRelation = cloneVmProgram(program)
    badBorrowRelation.trace.rows[findVmOpRow(
      badBorrowRelation,
      Method2VmOp.ScalarBit
    )][METHOD2_VM_LAYOUT.auxStart] ^= 1n
    expect(() => validateMethod2VmProgram(badBorrowRelation)).toThrow()

    const scalarBitRow = findVmOpRow(program, Method2VmOp.ScalarBit)

    const badScalarAccumulator = cloneVmProgram(program)
    badScalarAccumulator.trace.rows[scalarBitRow][
      METHOD2_VM_LAYOUT.auxStart + 3
    ] += 1n
    expect(() => validateMethod2VmProgram(badScalarAccumulator)).toThrow()

    const badScalarCarry = cloneVmProgram(program)
    badScalarCarry.trace.rows[scalarBitRow + 1][
      METHOD2_VM_LAYOUT.auxStart + 2
    ] += 1n
    expect(() => validateMethod2VmProgram(badScalarCarry)).toThrow()

    const badInactiveBit = cloneVmProgram(program)
    badInactiveBit.trace.rows[scalarBitRow + 3][METHOD2_VM_LAYOUT.a] = 1n
    expect(() => validateMethod2VmProgram(badInactiveBit)).toThrow()

    const badLimbBinding = cloneVmProgram(program)
    badLimbBinding.trace.rows[scalarBitRow + 15][
      METHOD2_VM_LAYOUT.auxStart + 10
    ] += 1n
    expect(() => validateMethod2VmProgram(badLimbBinding)).toThrow()

    const badPointRelation = cloneVmProgram(program)
    badPointRelation.trace.rows[findVmOpRow(
      badPointRelation,
      Method2VmOp.FieldMulLimb
    )][METHOD2_VM_LAYOUT.auxStart + 1] += 1n
    expect(() => validateMethod2VmProgram(badPointRelation)).toThrow()
  })

  it.skip('carries fixed and variable scalar multiplication state through VM register rows', () => {
    const base = scalarMultiply(11n)
    const builder = new Method2VmBuilder()
    const fixed = appendMethod2VmRegisterizedFixedBaseScalarMul(builder, 3n, 2)
    const variable = appendMethod2VmRegisterizedScalarMul(builder, 3n, base, 2)

    expect(pointEquals(fixed.output, scalarMultiply(3n))).toBe(true)
    expect(pointEquals(variable.output, scalarMultiply(3n, base))).toBe(true)
    expect(fixed.stateCheckpoints).toBeGreaterThan(0)
    expect(fixed.stateCarries).toBeGreaterThan(0)
    expect(variable.stateCheckpoints).toBeGreaterThan(0)
    expect(variable.stateCarries).toBeGreaterThan(0)
    expect(fixed.branchMuxes).toBe(4)
    expect(variable.branchMuxes).toBe(4)
    expect(fixed.publicOutputBindings).toBe(0)
    expect(variable.publicOutputBindings).toBe(0)
    expect(fixed.scalarSteps).toBe(2)
    expect(variable.scalarSteps).toBe(2)
    expect(fixed.candidateAdditions).toBe(2)
    expect(variable.candidateAdditions).toBe(2)

    const program = builder.build()
    expect(program.fixedCells?.length).toBeGreaterThan(0)
    expect(() => validateMethod2VmProgram(program)).not.toThrow()
    expect(evaluateAirTrace(buildMethod2VmAir(program), program.trace.rows).valid)
      .toBe(true)

    const linkedRow = findVmLinkedOpRow(program, Method2VmOp.AssertEq)
    const badStateCarry = cloneVmProgram(program)
    badStateCarry.trace.rows[linkedRow + 1][METHOD2_VM_LAYOUT.a] += 1n
    expect(() => validateMethod2VmProgram(badStateCarry)).toThrow()

    const badControlCell = cloneVmProgram(program)
    badControlCell.trace.rows[linkedRow][METHOD2_VM_LAYOUT.auxStart] = 0n
    expect(() => validateMethod2VmProgram(badControlCell)).toThrow()

    const badPointRelation = cloneVmProgram(program)
    badPointRelation.trace.rows[findVmOpRow(
      badPointRelation,
      Method2VmOp.FieldMulLimb
    )][METHOD2_VM_LAYOUT.auxStart + 1] += 1n
    expect(() => validateMethod2VmProgram(badPointRelation)).toThrow()
  })

  it.skip('links S = aB scalar multiplication output into compressed encoding rows', () => {
    const base = scalarMultiply(11n)
    const builder = new Method2VmBuilder()
    const witness = appendMethod2VmRegisterizedScalarMulCompressedPoint(
      builder,
      7n,
      base,
      3
    )
    const shared = scalarMultiply(7n, base)

    expect(pointEquals(witness.scalarMul.output, shared)).toBe(true)
    expect(witness.compressed).toEqual(compressPoint(shared))
    expect(witness.scalarMul.compressedOutputBindings).toBeGreaterThan(32)

    const program = builder.build()
    expect(() => validateMethod2VmProgram(program)).not.toThrow()
    expect(evaluateAirTrace(buildMethod2VmAir(program), program.trace.rows).valid)
      .toBe(true)

    const badPointInputLink = cloneVmProgram(program)
    const linkedU16 = findVmLinkedNextOpRow(
      badPointInputLink,
      Method2VmOp.SelectBit,
      Method2VmOp.U16
    )
    badPointInputLink.trace.rows[linkedU16 + 1][METHOD2_VM_LAYOUT.a] += 1n
    expect(() => validateMethod2VmProgram(badPointInputLink)).toThrow()

    const badEncodedLimbLink = cloneVmProgram(program)
    const linkedAdd = findVmLinkedNextOpRow(
      badEncodedLimbLink,
      Method2VmOp.SelectBit,
      Method2VmOp.Add
    )
    badEncodedLimbLink.trace.rows[linkedAdd + 1][METHOD2_VM_LAYOUT.c] += 1n
    expect(() => validateMethod2VmProgram(badEncodedLimbLink)).toThrow()

    const badParity = cloneVmProgram(program)
    const parityAdd = findVmOpRowAfter(
      badParity,
      Method2VmOp.Bool,
      Method2VmOp.Add
    )
    badParity.trace.rows[parityAdd][METHOD2_VM_LAYOUT.a] ^= 1n
    expect(() => validateMethod2VmProgram(badParity)).toThrow()
  })

  it.skip('links encodedS into Method 2 VM HMAC input planner rows', () => {
    const base = scalarMultiply(11n)
    const invoice = ascii(computeInvoiceNumber([0, 'testprotocol'], 'key-1'))
    const shared = compressPoint(scalarMultiply(7n, base))
    const linkage = hmacSha256(shared, invoice)
    const builder = new Method2VmBuilder()
    const witness = appendMethod2VmRegisterizedScalarMulHmacInput(
      builder,
      7n,
      base,
      invoice,
      linkage,
      3
    )

    expect(witness.compressed).toEqual(shared)
    expect(witness.hmac.shared).toEqual(shared)
    expect(witness.hmac.sharedBytesLinked).toBe(33)
    expect(witness.hmac.invoiceBytesBound).toBe(invoice.length)
    expect(witness.hmac.linkageBytesBound).toBe(32)

    const program = builder.build()
    expect(() => validateMethod2VmProgram(program)).not.toThrow()
    expect(evaluateAirTrace(buildMethod2VmAir(program), program.trace.rows).valid)
      .toBe(true)

    const badSharedHandoff = cloneVmProgram(program)
    const linkedXor = findVmLinkedNextOpRow(
      badSharedHandoff,
      Method2VmOp.AssertEq,
      Method2VmOp.XorConstByte
    )
    badSharedHandoff.trace.rows[linkedXor + 1][METHOD2_VM_LAYOUT.a] ^= 1n
    expect(() => validateMethod2VmProgram(badSharedHandoff)).toThrow()

    const badInnerPad = cloneVmProgram(program)
    const xorRow = findVmOpRow(badInnerPad, Method2VmOp.XorConstByte)
    badInnerPad.trace.rows[xorRow][METHOD2_VM_LAYOUT.c] ^= 1n
    expect(() => validateMethod2VmProgram(badInnerPad)).toThrow()

    const badInvoice = cloneVmProgram(program)
    const invoiceRow = lastFixedCellForColumn(
      badInvoice,
      METHOD2_VM_LAYOUT.a
    )
    badInvoice.trace.rows[invoiceRow.row][METHOD2_VM_LAYOUT.a] ^= 1n
    expect(() => validateMethod2VmProgram(badInvoice)).toThrow()
  })

  it.skip('creates, serializes, parses, and verifies a proof payload', () => {
    const scalar = 1n
    const statement = statementFor(scalar, 11n)
    const proof = createSpecificKeyLinkageProof({
      proverPrivateKey: scalar,
      statement,
      starkOptions: method2ProofSmokeStarkOptions(),
      method2Options: {
        allowReducedProfile: true,
        fixedBaseMulBits: 1
      }
    })
    const payload = serializeSpecificKeyLinkageProofPayload(proof)
    const parsed = parseSpecificKeyLinkageProofPayload(payload)

    expect(payload[0]).toBe(1)
    expect(parsed.proofType).toBe(1)
    if (parsed.proofType === 1) {
      expect(parsed.proof.profileId).toBe(BRC97_METHOD2_REDUCED_TEST_PROFILE)
      expect(parsed.proof.vmScalarBits).toBe(1)
      expect(parsed.proof.publicInputDigest).toHaveLength(32)
      expect(parsed.proof.starkProof.traceDegreeBound)
        .toBe(proof.starkProof.traceDegreeBound)
      expect(parsed.proof.starkProof.compositionDegreeBound)
        .toBe(proof.starkProof.compositionDegreeBound)
    }
    expect(verifySpecificKeyLinkageProof(statement, payload)).toBe(false)
    expect(verifySpecificKeyLinkageProof(statement, payload, {
      allowReducedFixedBaseMulBits: true
    })).toBe(true)
    expect(verifySpecificKeyLinkageProof(statement, proof, {
      allowReducedFixedBaseMulBits: true
    })).toBe(true)

    const tamperedTraceDegree = {
      ...proof,
      starkProof: {
        ...proof.starkProof,
        traceDegreeBound: proof.starkProof.traceDegreeBound + 1
      }
    }
    expect(verifySpecificKeyLinkageProof(statement, tamperedTraceDegree, {
      allowReducedFixedBaseMulBits: true
    })).toBe(false)
    expect(() => serializeSpecificKeyLinkageProofPayload(tamperedTraceDegree))
      .toThrow('Method 2 proof degree bounds are invalid')
  })

  it.skip('verifier-enforces scalar bit decomposition, nonzero, and range witnesses', () => {
    const row = new Array<bigint>(METHOD2_SCALAR_LAYOUT.width).fill(0n)
    writeMethod2ScalarWitness(row, 0, SECP256K1_N - 1n)
    expect(method2ScalarConstraintsValid(row)).toBe(true)

    const badScalarBit = row.slice()
    badScalarBit[METHOD2_SCALAR_LAYOUT.bits] = 2n
    expect(method2ScalarConstraintsValid(badScalarBit)).toBe(false)

    const badDiffBit = row.slice()
    badDiffBit[METHOD2_SCALAR_LAYOUT.diffBits + 13] = 2n
    expect(method2ScalarConstraintsValid(badDiffBit)).toBe(false)

    const badCarry = row.slice()
    badCarry[METHOD2_SCALAR_LAYOUT.carries] ^= 1n
    expect(method2ScalarConstraintsValid(badCarry)).toBe(false)

    const badInverse = row.slice()
    badInverse[METHOD2_SCALAR_LAYOUT.nonZeroInverse] += 1n
    expect(method2ScalarConstraintsValid(badInverse)).toBe(false)

    expect(() => writeMethod2ScalarWitness(row, 0, 0n)).toThrow()
    expect(() => writeMethod2ScalarWitness(row, 0, SECP256K1_N)).toThrow()
  })

  it.skip('accepts scalar edge cases at the scalar constraint layer', () => {
    const row = new Array<bigint>(METHOD2_SCALAR_LAYOUT.width).fill(0n)
    writeMethod2ScalarWitness(row, 0, SECP256K1_N - 1n)
    expect(method2ScalarConstraintsValid(row)).toBe(true)
  })

  it.skip('verifier-enforces secp256k1 point validation and compressed binding', () => {
    const point = scalarMultiply(7n)
    const row = new Array<bigint>(METHOD2_POINT_LAYOUT.width + 33).fill(0n)
    writeMethod2PointWitness(row, 0, point)
    writeBytes(row, METHOD2_POINT_LAYOUT.width, compressPoint(point))
    expect(method2PointConstraintsValid(row)).toBe(true)

    const badXBit = row.slice()
    badXBit[METHOD2_POINT_LAYOUT.x + METHOD2_FIELD_LAYOUT.bits] = 2n
    expect(method2PointConstraintsValid(badXBit)).toBe(false)

    const badCurve = row.slice()
    badCurve[METHOD2_POINT_LAYOUT.y2 + METHOD2_FIELD_LAYOUT.limbs] += 1n
    expect(method2PointConstraintsValid(badCurve)).toBe(false)

    const badPrefix = row.slice()
    badPrefix[METHOD2_POINT_LAYOUT.width] ^= 1n
    expect(method2PointConstraintsValid(badPrefix)).toBe(false)
  })

  it.skip('verifier-enforces affine point doubling constraints', () => {
    const input = scalarMultiply(7n)
    const row = new Array<bigint>(METHOD2_POINT_DOUBLE_LAYOUT.width).fill(0n)
    const output = writeMethod2PointDoubleWitness(row, 0, input)
    expect(pointEquals(output, pointDouble(input))).toBe(true)
    expect(method2PointDoubleConstraintsValid(row)).toBe(true)

    const badSlope = row.slice()
    badSlope[
      METHOD2_POINT_DOUBLE_LAYOUT.slope + METHOD2_FIELD_LAYOUT.limbs
    ] += 1n
    expect(method2PointDoubleConstraintsValid(badSlope)).toBe(false)

    const badOutputX = row.slice()
    badOutputX[
      METHOD2_POINT_DOUBLE_LAYOUT.output +
        METHOD2_POINT_LAYOUT.x +
        METHOD2_FIELD_LAYOUT.limbs
    ] += 1n
    expect(method2PointDoubleConstraintsValid(badOutputX)).toBe(false)
  })

  it.skip('verifier-enforces distinct affine point addition constraints', () => {
    const left = scalarMultiply(7n)
    const right = scalarMultiply(11n)
    const row = new Array<bigint>(
      METHOD2_POINT_ADD_DISTINCT_LAYOUT.width
    ).fill(0n)
    const output = writeMethod2PointAddDistinctWitness(row, 0, left, right)
    expect(pointEquals(output, pointAdd(left, right))).toBe(true)
    expect(method2PointAddDistinctConstraintsValid(row)).toBe(true)

    const badInverse = row.slice()
    badInverse[
      METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffXInverse +
        METHOD2_FIELD_LAYOUT.limbs
    ] += 1n
    expect(method2PointAddDistinctConstraintsValid(badInverse)).toBe(false)

    const badOutputY = row.slice()
    badOutputY[
      METHOD2_POINT_ADD_DISTINCT_LAYOUT.output +
        METHOD2_POINT_LAYOUT.y +
        METHOD2_FIELD_LAYOUT.limbs
    ] += 1n
    expect(method2PointAddDistinctConstraintsValid(badOutputY)).toBe(false)

    expect(() => {
      writeMethod2PointAddDistinctWitness(
        new Array<bigint>(METHOD2_POINT_ADD_DISTINCT_LAYOUT.width).fill(0n),
        0,
        left,
        left
      )
    }).toThrow()
  })

  it.skip('verifier-enforces VM scalar multiplication rows for A = aG', () => {
    const expected = scalarMultiply(7n)
    const { program, witness } = buildMethod2VmScalarMulProgram(
      7n,
      SECP256K1_G,
      expected,
      3
    )
    const verifierProgram = buildMethod2VmScalarMulVerifierProgram(
      SECP256K1_G,
      expected,
      3
    )

    expect(pointEquals(witness.output, expected)).toBe(true)
    expect(witness.publicOutputBindings).toBe(1)
    expect(() => validateMethod2VmProgram(program)).not.toThrow()
    expect(evaluateAirTrace(
      buildMethod2VmAir(verifierProgram),
      program.trace.rows
    ).valid).toBe(true)

    const wrongOutputVerifier = buildMethod2VmScalarMulVerifierProgram(
      SECP256K1_G,
      scalarMultiply(5n),
      3
    )
    expect(evaluateAirTrace(
      buildMethod2VmAir(wrongOutputVerifier),
      program.trace.rows
    ).valid).toBe(false)

    const badSelector = cloneVmProgram(program)
    const selectRow = findVmOpRow(badSelector, Method2VmOp.SelectBit)
    badSelector.trace.rows[selectRow][METHOD2_VM_LAYOUT.a] ^= 1n
    expect(() => validateMethod2VmProgram(badSelector)).toThrow()

    const badLinkedPublicOutput = cloneVmProgram(program)
    const outputCell = lastFixedCellForColumn(program, METHOD2_VM_LAYOUT.b)
    badLinkedPublicOutput.trace.rows[outputCell.row][METHOD2_VM_LAYOUT.a] += 1n
    expect(() => validateMethod2VmProgram(badLinkedPublicOutput)).toThrow()
  })

  it.skip('verifier-enforces VM scalar multiplication rows for S = aB', () => {
    const base = scalarMultiply(11n)
    const expected = scalarMultiply(7n, base)
    const { program, witness } = buildMethod2VmScalarMulProgram(
      7n,
      base,
      expected,
      3
    )
    const verifierProgram = buildMethod2VmScalarMulVerifierProgram(
      base,
      expected,
      3
    )

    expect(pointEquals(witness.output, expected)).toBe(true)
    expect(witness.publicOutputBindings).toBe(1)
    expect(() => validateMethod2VmProgram(program)).not.toThrow()
    expect(evaluateAirTrace(
      buildMethod2VmAir(verifierProgram),
      program.trace.rows
    ).valid).toBe(true)

    const wrongBaseVerifier = buildMethod2VmScalarMulVerifierProgram(
      scalarMultiply(13n),
      expected,
      3
    )
    expect(evaluateAirTrace(
      buildMethod2VmAir(wrongBaseVerifier),
      program.trace.rows
    ).valid).toBe(false)

    const badPublicOutput = cloneVmProgram(program)
    const outputCell = lastFixedCellForColumn(program, METHOD2_VM_LAYOUT.b)
    badPublicOutput.trace.rows[outputCell.row][METHOD2_VM_LAYOUT.b] += 1n
    expect(() => validateMethod2VmProgram(badPublicOutput)).toThrow()
  })

  it.skip('verifier-enforces HMAC planner bytes for encode(S), invoice, and linkage', () => {
    const shared = compressPoint(scalarMultiply(7n, scalarMultiply(11n)))
    const invoice = ascii(computeInvoiceNumber([0, 'testprotocol'], 'key-1'))
    const linkage = hmacSha256(shared, invoice)
    const sharedOffset = 0
    const hmacOffset = 33
    const layout = method2HmacLayout(invoice.length)
    const row = new Array<bigint>(hmacOffset + layout.width).fill(0n)
    writeBytes(row, sharedOffset, shared)
    writeMethod2HmacWitness(row, hmacOffset, shared, invoice, linkage)
    expect(method2HmacPlannerConstraintsValid(
      row,
      hmacOffset,
      sharedOffset,
      invoice,
      linkage
    )).toBe(true)

    const badSharedBit = row.slice()
    badSharedBit[hmacOffset + layout.sharedBits] ^= 1n
    expect(method2HmacPlannerConstraintsValid(
      badSharedBit,
      hmacOffset,
      sharedOffset,
      invoice,
      linkage
    )).toBe(false)

    const badInvoiceByte = row.slice()
    badInvoiceByte[hmacOffset + layout.innerMessage + 64] ^= 1n
    expect(method2HmacPlannerConstraintsValid(
      badInvoiceByte,
      hmacOffset,
      sharedOffset,
      invoice,
      linkage
    )).toBe(false)

    const badLinkage = row.slice()
    badLinkage[hmacOffset + layout.linkage] ^= 1n
    expect(method2HmacPlannerConstraintsValid(
      badLinkage,
      hmacOffset,
      sharedOffset,
      invoice,
      linkage
    )).toBe(false)
  })

  it.skip('verifier-enforces SHA-256 compression block rounds', () => {
    const block = sha256Pad(ascii('abc')).slice(0, 64)
    const expected = sha256CompressBlock({
      words: METHOD2_SHA256_INITIAL_STATE
    }, block).words
    const trace = buildMethod2Sha256BlockTrace(
      METHOD2_SHA256_INITIAL_STATE,
      block
    )
    const air = buildMethod2Sha256BlockAir(
      METHOD2_SHA256_INITIAL_STATE,
      block,
      expected
    )

    expect(trace.outputState).toEqual(expected)
    expect(evaluateAirTrace(air, trace.traceRows).valid).toBe(true)

    const badSchedule = cloneTrace(trace.traceRows)
    badSchedule[0][trace.layout.schedule] ^= 1n
    expect(evaluateAirTrace(air, badSchedule).valid).toBe(false)

    const badCarry = cloneTrace(trace.traceRows)
    badCarry[0][trace.layout.t1Carry + 1] += 1n
    expect(evaluateAirTrace(air, badCarry).valid).toBe(false)

    const badRoundOutput = cloneTrace(trace.traceRows)
    badRoundOutput[0][trace.layout.roundA] ^= 1n
    expect(evaluateAirTrace(air, badRoundOutput).valid).toBe(false)

    const badFinal = cloneTrace(trace.traceRows)
    badFinal[64][trace.layout.state] ^= 1n
    expect(evaluateAirTrace(air, badFinal).valid).toBe(false)
  })

  it.skip('rejects legacy proof type 0 and tampered statements or proof bytes', () => {
    const statement = statementFor(1n, 11n)
    const proof = createSpecificKeyLinkageProof({
      proverPrivateKey: 1n,
      statement,
      starkOptions: method2ProofSmokeStarkOptions(),
      method2Options: {
        allowReducedProfile: true,
        fixedBaseMulBits: 1
      }
    })
    const payload = serializeSpecificKeyLinkageProofPayload(proof)
    const profileOffset = 1 + ascii(BRC97_METHOD2_COMPOSITE_DOMAIN).length
    const vmScalarBitsOffset = profileOffset + 1
    const publicDigestOffset = vmScalarBitsOffset + 1

    expect(verifySpecificKeyLinkageProof(statement, [0])).toBe(false)
    expect(verifySpecificKeyLinkageProof(
      statement,
      [1, ...serializeStarkProof(proof.starkProof)],
      { allowReducedFixedBaseMulBits: true }
    )).toBe(false)

    const badLinkage = {
      ...statement,
      linkage: statement.linkage.slice()
    }
    badLinkage.linkage[0] ^= 1
    expect(verifySpecificKeyLinkageProof(badLinkage, payload, {
      allowReducedFixedBaseMulBits: true
    })).toBe(false)

    const badProtocol = {
      ...statement,
      protocolID: [statement.protocolID[0], 'other protocol'] as [0, string]
    }
    expect(verifySpecificKeyLinkageProof(badProtocol, payload, {
      allowReducedFixedBaseMulBits: true
    })).toBe(false)

    const badCounterparty = {
      ...statement,
      counterparty: hex(compressPoint(scalarMultiply(13n)))
    }
    expect(verifySpecificKeyLinkageProof(badCounterparty, payload, {
      allowReducedFixedBaseMulBits: true
    })).toBe(false)

    const badProver = {
      ...statement,
      prover: hex(compressPoint(scalarMultiply(3n)))
    }
    expect(verifySpecificKeyLinkageProof(badProver, payload, {
      allowReducedFixedBaseMulBits: true
    })).toBe(false)

    const badPayload = payload.slice()
    badPayload[badPayload.length - 1] ^= 1
    expect(verifySpecificKeyLinkageProof(statement, badPayload, {
      allowReducedFixedBaseMulBits: true
    })).toBe(false)

    const badProfile = payload.slice()
    badProfile[profileOffset] = 42
    expect(verifySpecificKeyLinkageProof(statement, badProfile, {
      allowReducedFixedBaseMulBits: true
    })).toBe(false)
    expect(() => parseSpecificKeyLinkageProofPayload(badProfile)).toThrow()

    const falselyProductionProfile = payload.slice()
    falselyProductionProfile[profileOffset] = 1
    expect(verifySpecificKeyLinkageProof(statement, falselyProductionProfile, {
      allowReducedFixedBaseMulBits: true
    })).toBe(false)

    const badVmScalarBits = payload.slice()
    badVmScalarBits[vmScalarBitsOffset] = 0
    expect(verifySpecificKeyLinkageProof(statement, badVmScalarBits, {
      allowReducedFixedBaseMulBits: true
    })).toBe(false)
    expect(() => parseSpecificKeyLinkageProofPayload(badVmScalarBits)).toThrow()

    const badPublicDigest = payload.slice()
    badPublicDigest[publicDigestOffset] ^= 1
    expect(verifySpecificKeyLinkageProof(statement, badPublicDigest, {
      allowReducedFixedBaseMulBits: true
    })).toBe(false)

    const tamperedCompositionDegree = {
      ...proof,
      starkProof: {
        ...proof.starkProof,
        compositionDegreeBound: proof.starkProof.compositionDegreeBound + 1
      }
    }
    expect(verifySpecificKeyLinkageProof(
      statement,
      tamperedCompositionDegree,
      { allowReducedFixedBaseMulBits: true }
    )).toBe(false)
    expect(() => serializeSpecificKeyLinkageProofPayload(
      tamperedCompositionDegree
    )).toThrow('Method 2 proof degree bounds are invalid')

    expect(() => parseSpecificKeyLinkageProofPayload([0, 1])).toThrow()
    expect(() => parseSpecificKeyLinkageProofPayload([2])).toThrow()
  })

  it.skip('does not serialize the private scalar or compressed shared secret contiguously', () => {
    const scalar = 1n
    const statement = statementFor(scalar, 17n)
    const proof = createSpecificKeyLinkageProof({
      proverPrivateKey: scalar,
      statement,
      starkOptions: method2ProofSmokeStarkOptions(),
      method2Options: {
        allowReducedProfile: true,
        fixedBaseMulBits: 1
      }
    })
    const payloadHex = hex(serializeSpecificKeyLinkageProofPayload(proof))
    const scalarHex = scalar.toString(16).padStart(64, '0')
    const sharedHex = hex(compressPoint(scalarMultiply(
      scalar,
      scalarMultiply(17n)
    )))

    expect(payloadHex.includes(scalarHex)).toBe(false)
    expect(payloadHex.includes(sharedHex)).toBe(false)
    expect(scalar).toBeLessThan(SECP256K1_N)
  })
})

function statementFor (
  scalar: bigint,
  counterpartyScalar: bigint
): {
    prover: string
    counterparty: string
    protocolID: [0, string]
    keyID: string
    linkage: number[]
  } {
  const protocolID: [0, string] = [0, 'testprotocol']
  const keyID = 'key-1'
  const prover = hex(compressPoint(scalarMultiply(scalar)))
  const counterpartyPoint = scalarMultiply(counterpartyScalar)
  const counterparty = hex(compressPoint(counterpartyPoint))
  const shared = scalarMultiply(scalar, counterpartyPoint)
  return {
    prover,
    counterparty,
    protocolID,
    keyID,
    linkage: hmacSha256(
      compressPoint(shared),
      ascii(computeInvoiceNumber(protocolID, keyID))
    )
  }
}

function v2TraceFixture (): ReturnType<typeof buildMethod2V2Trace> {
  const scalar = 7n
  const counterpartyScalar = 11n
  const statement = statementFor(scalar, counterpartyScalar)
  return buildMethod2V2Trace(
    scalar,
    scalarMultiply(scalar),
    scalarMultiply(counterpartyScalar),
    ascii(computeInvoiceNumber(statement.protocolID, statement.keyID)),
    statement.linkage
  )
}

function testStarkOptions (): {
  blowupFactor: number
  numQueries: number
  maxRemainderSize: number
  maskDegree: number
  cosetOffset: bigint
  maskSeed: number[]
} {
  return {
    blowupFactor: 4,
    numQueries: 4,
    maxRemainderSize: 4,
    maskDegree: 2,
    cosetOffset: 3n,
    maskSeed: ascii('method2-test-mask-seed')
  }
}

function method2ProofSmokeStarkOptions (): {
  blowupFactor: number
  numQueries: number
  maxRemainderSize: number
  maskDegree: number
  cosetOffset: bigint
  maskSeed: number[]
} {
  return {
    blowupFactor: 2,
    numQueries: 1,
    maxRemainderSize: 8192,
    maskDegree: 1,
    cosetOffset: 3n,
    maskSeed: ascii('method2-proof-smoke-mask-seed')
  }
}

function ascii (value: string): number[] {
  return Array.from(value, char => char.charCodeAt(0))
}

function hex (bytes: number[]): string {
  return bytes.map(byte => byte.toString(16).padStart(2, '0')).join('')
}

function method2ScalarConstraintsValid (row: bigint[]): boolean {
  return evaluateMethod2ScalarConstraints(row, 0)
    .every(value => F.normalize(value) === 0n)
}

function method2PointConstraintsValid (row: bigint[]): boolean {
  return [
    ...evaluateMethod2PointConstraints(row, 0),
    ...evaluateMethod2CompressedPointConstraints(
      row,
      0,
      METHOD2_POINT_LAYOUT.width
    )
  ].every(value => F.normalize(value) === 0n)
}

function method2PointDoubleConstraintsValid (row: bigint[]): boolean {
  return evaluateMethod2PointDoubleConstraints(row, 0)
    .every(value => F.normalize(value) === 0n)
}

function method2PointAddDistinctConstraintsValid (row: bigint[]): boolean {
  return evaluateMethod2PointAddDistinctConstraints(row, 0)
    .every(value => F.normalize(value) === 0n)
}

function method2HmacPlannerConstraintsValid (
  row: bigint[],
  hmacOffset: number,
  sharedOffset: number,
  invoice: number[],
  linkage: number[]
): boolean {
  return evaluateMethod2HmacPlannerConstraints(
    row,
    hmacOffset,
    sharedOffset,
    invoice,
    linkage
  ).every(value => F.normalize(value) === 0n)
}

function pointEquals (
  left: { x: bigint, y: bigint, infinity?: boolean },
  right: { x: bigint, y: bigint, infinity?: boolean }
): boolean {
  return left.infinity === right.infinity &&
    left.x === right.x &&
    left.y === right.y
}

function cloneTrace (trace: bigint[][]): bigint[][] {
  return trace.map(row => row.slice())
}

function cloneVmProgram (program: Method2VmProgram): Method2VmProgram {
  return {
    publicInputDigest: program.publicInputDigest?.slice(),
    fixedCells: program.fixedCells?.map(cell => ({ ...cell })),
    trace: {
      rows: cloneTrace(program.trace.rows),
      layout: program.trace.layout,
      activeLength: program.trace.activeLength
    }
  }
}

function findVmOpRow (
  program: Method2VmProgram,
  op: Method2VmOp
): number {
  const row = program.trace.rows.findIndex(row =>
    row[METHOD2_VM_LAYOUT.op] === BigInt(op)
  )
  if (row < 0) throw new Error(`Method 2 VM op ${op} not found`)
  return row
}

function findVmLinkedOpRow (
  program: Method2VmProgram,
  op: Method2VmOp
): number {
  const row = program.trace.rows.findIndex(row =>
    row[METHOD2_VM_LAYOUT.op] === BigInt(op) &&
      row[METHOD2_VM_LAYOUT.auxStart] === 1n
  )
  if (row < 0) throw new Error(`Linked Method 2 VM op ${op} not found`)
  return row
}

function findVmLinkedNextOpRow (
  program: Method2VmProgram,
  op: Method2VmOp,
  nextOp: Method2VmOp
): number {
  const row = program.trace.rows.findIndex((row, index) =>
    row[METHOD2_VM_LAYOUT.op] === BigInt(op) &&
      program.trace.rows[index + 1]?.[METHOD2_VM_LAYOUT.op] === BigInt(nextOp)
  )
  if (row < 0) {
    throw new Error(`Method 2 VM op ${op} before ${nextOp} not found`)
  }
  return row
}

function findVmOpRowAfter (
  program: Method2VmProgram,
  afterOp: Method2VmOp,
  op: Method2VmOp
): number {
  const start = findVmOpRow(program, afterOp)
  const row = program.trace.rows.findIndex((row, index) =>
    index > start && row[METHOD2_VM_LAYOUT.op] === BigInt(op)
  )
  if (row < 0) {
    throw new Error(`Method 2 VM op ${op} after ${afterOp} not found`)
  }
  return row
}

function lastFixedCellForColumn (
  program: Method2VmProgram,
  column: number
): { row: number, column: number, value: bigint } {
  const cell = program.fixedCells
    ?.filter(cell => cell.column === column)
    .at(-1)
  if (cell === undefined) {
    throw new Error(`Fixed Method 2 VM column ${column} not found`)
  }
  return cell
}

function writeBytes (
  row: bigint[],
  offset: number,
  bytes: number[]
): void {
  for (let i = 0; i < bytes.length; i++) {
    row[offset + i] = BigInt(bytes[i])
  }
}
