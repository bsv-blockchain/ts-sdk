import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  F,
  FieldElement,
  FriProof,
  FriVerifierInput,
  StarkProof,
  applyVanishingMask,
  assertAirTrace,
  batchInvertFieldElements,
  buildMerkleTree,
  commitTraceLde,
  cosetLowDegreeExtend,
  degreeOfPolynomial,
  evaluateAirTrace,
  evaluatePolynomial,
  fft,
  fieldElementLeaf,
  foldFriLayer,
  getPowerOfTwoCosetDomain,
  getPowerOfTwoDomain,
  getPowerOfTwoRootOfUnity,
  ifft,
  lowDegreeExtend,
  openMerklePath,
  parseStarkProof,
  proveFri,
  proveStark,
  parseFriProof,
  serializeFriProof,
  serializeStarkProof,
  openTraceRow,
  traceCommitmentLdeRow,
  FiatShamirTranscript,
  proveMultiTraceStark,
  verifyTraceRowOpening,
  verifyFri,
  verifyMerklePath,
  verifyMultiTraceStark,
  verifyStark
} from '../brc69/stark/index'

describe('BRC-69 STARK core', () => {
  it('performs Goldilocks field arithmetic', () => {
    const p = F.p
    expect(F.add(p - 1n, 2n)).toBe(1n)
    expect(F.sub(1n, 2n)).toBe(p - 1n)
    expect(F.mul(p - 1n, p - 1n)).toBe(1n)

    const value = 123456789n
    expect(F.mul(value, F.inv(value))).toBe(1n)
    expect(F.fromBytesLE(F.toBytesLE(value))).toBe(value)
  })

  it('batch-inverts Goldilocks field elements', () => {
    const values = [
      1n,
      3n,
      5n,
      123456789n,
      F.p - 2n
    ]
    const inverses = batchInvertFieldElements(values)

    expect(inverses).toHaveLength(values.length)
    for (let i = 0; i < values.length; i++) {
      expect(F.mul(values[i], inverses[i])).toBe(1n)
      expect(inverses[i]).toBe(F.inv(values[i]))
    }
    expect(() => batchInvertFieldElements([1n, 0n, 2n])).toThrow(
      'Cannot batch-invert zero'
    )
  })

  it('rejects non-canonical field encodings and invalid domains', () => {
    expect(() => F.fromBytesLE(bigIntToBytesLE(F.p))).toThrow(
      'Non-canonical Goldilocks field encoding'
    )
    expect(() => F.fromBytesLE([0, 1, 2])).toThrow()
    expect(() => F.fromBytesLE([0, 1, 2, 3, 4, 5, 6, 256])).toThrow()
    expect(() => F.normalize(1.5)).toThrow()
    expect(() => F.normalize(Number.MAX_SAFE_INTEGER + 1)).toThrow()
    expect(() => getPowerOfTwoRootOfUnity(3)).toThrow()
    expect(() => getPowerOfTwoRootOfUnity(2 ** 33)).toThrow()
    expect(() => getPowerOfTwoCosetDomain(4, 0n)).toThrow()
  })

  it('constructs two-adic roots of unity', () => {
    const root = getPowerOfTwoRootOfUnity(16)
    expect(F.pow(root, 16n)).toBe(1n)
    expect(F.pow(root, 8n)).not.toBe(1n)
  })

  it('round-trips FFT interpolation and matches direct evaluation', () => {
    const coefficients: FieldElement[] = [3n, 2n, 5n, 7n]
    const evaluations = fft(coefficients)
    const domain = getPowerOfTwoDomain(coefficients.length)
    expect(evaluations).toEqual(
      domain.map(point => evaluatePolynomial(coefficients, point))
    )

    const interpolated = ifft(evaluations)
    expect(interpolated).toEqual(coefficients)
    expect(degreeOfPolynomial(interpolated)).toBe(3)
  })

  it('produces low-degree extensions on a larger domain', () => {
    const coefficients: FieldElement[] = [9n, 1n, 4n]
    const extended = lowDegreeExtend(coefficients, 8)
    expect(extended).toHaveLength(32)

    const domain = getPowerOfTwoDomain(32)
    expect(extended[7]).toBe(evaluatePolynomial(coefficients, domain[7]))
  })

  it('evaluates polynomials on explicit cosets', () => {
    const coefficients: FieldElement[] = [7n, 2n, 9n]
    const coset = getPowerOfTwoCosetDomain(8, 5n)
    const evaluations = cosetLowDegreeExtend(coefficients, 4, 5n)

    expect(evaluations).toHaveLength(16)
    expect(evaluations[3]).toBe(
      evaluatePolynomial(coefficients, getPowerOfTwoCosetDomain(16, 5n)[3])
    )
    expect(coset[0]).toBe(5n)
  })

  it('applies vanishing masks without changing trace-domain values', () => {
    const coefficients: FieldElement[] = [4n, 1n, 9n]
    const masked = applyVanishingMask(coefficients, 4, [7n, 11n])
    const traceDomain = getPowerOfTwoDomain(4)

    for (const point of traceDomain) {
      expect(evaluatePolynomial(masked, point)).toBe(
        evaluatePolynomial(coefficients, point)
      )
    }

    const originalCoset = cosetLowDegreeExtend(coefficients, 4, 3n)
    const maskedCoset = cosetLowDegreeExtend(masked, 4, 3n)
    expect(maskedCoset).not.toEqual(originalCoset)
  })

  it('builds and verifies SHA-256 Merkle openings', () => {
    const values = [1n, 2n, 3n, 4n].map(fieldElementLeaf)
    const tree = buildMerkleTree(values)

    for (let i = 0; i < values.length; i++) {
      const path = openMerklePath(tree, i)
      expect(verifyMerklePath(values[i], i, tree.root, path)).toBe(true)

      const tampered = values[i].slice()
      tampered[0] ^= 1
      expect(verifyMerklePath(tampered, i, tree.root, path)).toBe(false)
    }
  })

  it('rejects tampered Merkle paths strictly', () => {
    const values = [10n, 20n, 30n, 40n].map(fieldElementLeaf)
    const tree = buildMerkleTree(values)
    const path = openMerklePath(tree, 2)

    expect(verifyMerklePath(values[2], 2, tree.root, path, values.length)).toBe(true)

    const badSibling = path.map(item => ({
      sibling: item.sibling.slice(),
      siblingOnLeft: item.siblingOnLeft
    }))
    badSibling[0].sibling[0] ^= 1
    expect(verifyMerklePath(values[2], 2, tree.root, badSibling, values.length)).toBe(false)

    const badDirection = path.map(item => ({
      sibling: item.sibling.slice(),
      siblingOnLeft: item.siblingOnLeft
    }))
    badDirection[0].siblingOnLeft = !badDirection[0].siblingOnLeft
    expect(verifyMerklePath(values[2], 2, tree.root, badDirection, values.length)).toBe(false)

    expect(verifyMerklePath(values[2], 5, tree.root, path, values.length)).toBe(false)
    expect(verifyMerklePath(values[2], 2, tree.root.slice(1), path, values.length)).toBe(false)
    expect(verifyMerklePath(values[2], 2, tree.root, path.slice(1), values.length)).toBe(false)
    expect(verifyMerklePath(values[2], 2, tree.root, [...path, path[0]], values.length)).toBe(false)
  })

  it('derives deterministic domain-separated transcript challenges', () => {
    const first = new FiatShamirTranscript('transcript-test')
    first.absorb('payload', [1, 2, 3])
    const second = new FiatShamirTranscript('transcript-test')
    second.absorb('payload', [1, 2, 3])
    const other = new FiatShamirTranscript('transcript-test-other')
    other.absorb('payload', [1, 2, 3])

    expect(first.challengeFieldElement('alpha')).toBe(
      second.challengeFieldElement('alpha')
    )
    expect(first.challengeIndex('idx', 17)).toBeLessThan(17)
    expect(first.challengeBytes('bytes', 16)).toHaveLength(16)
    expect(first.challengeFieldElement('beta')).not.toBe(
      other.challengeFieldElement('beta')
    )
  })

  it('commits to masked trace LDE rows and verifies openings', () => {
    const rows: FieldElement[][] = [
      [1n, 1n],
      [2n, 4n],
      [3n, 9n],
      [4n, 16n]
    ]
    const commitment = commitTraceLde(rows, {
      blowupFactor: 4,
      cosetOffset: 3n,
      maskCoefficients: [
        [7n, 8n],
        [9n, 10n]
      ]
    })

    expect(commitment.ldeRows).toBeUndefined()
    expect(commitment.typedLdeColumns).toHaveLength(2)
    expect(commitment.typedLdeColumns?.[0].lo).toHaveLength(16)
    expect(traceCommitmentLdeRow(commitment, 0)).toHaveLength(2)

    const opening = openTraceRow(commitment, 5)
    expect(verifyTraceRowOpening(commitment.tree.root, opening)).toBe(true)

    const tampered = {
      ...opening,
      row: opening.row.slice()
    }
    tampered.row[0] = F.add(tampered.row[0], 1n)
    expect(verifyTraceRowOpening(commitment.tree.root, tampered)).toBe(false)
  })

  it('evaluates AIR transition and boundary constraints', () => {
    const trace: FieldElement[][] = [
      [1n, 1n],
      [1n, 2n],
      [2n, 3n],
      [3n, 5n]
    ]
    const air = {
      traceWidth: 2,
      boundaryConstraints: [
        { column: 0, row: 0, value: 1n },
        { column: 1, row: 3, value: 5n }
      ],
      evaluateTransition: (current: FieldElement[], next: FieldElement[]) => [
        F.sub(next[0], current[1]),
        F.sub(next[1], F.add(current[0], current[1]))
      ]
    }

    expect(evaluateAirTrace(air, trace).valid).toBe(true)
    expect(() => assertAirTrace(air, trace)).not.toThrow()

    const invalid = trace.map(row => row.slice())
    invalid[2][1] = 99n
    const result = evaluateAirTrace(air, invalid)
    expect(result.valid).toBe(false)
    expect(result.transitionFailures.length).toBeGreaterThan(0)
  })

  it('folds FRI layers deterministically', () => {
    const coefficients: FieldElement[] = [5n, 3n, 2n]
    const evaluations = lowDegreeExtend(coefficients, 4)
    const foldedA = foldFriLayer(evaluations, 11n)
    const foldedB = foldFriLayer(evaluations, 11n)
    expect(foldedA).toEqual(foldedB)
    expect(foldedA).toHaveLength(evaluations.length / 2)
  })

  it('proves and verifies FRI folding consistency', () => {
    const coefficients: FieldElement[] = [3n, 1n, 4n, 1n]
    const evaluations = lowDegreeExtend(coefficients, 8)
    const proof = proveFri(evaluations, {
      degreeBound: 4,
      numQueries: 6,
      maxRemainderSize: 4
    })

    expect(verifyFri(proof, friVerifierInput(proof))).toBe(true)
    expect(verifyFri(proof)).toBe(false)
  })

  it('binds FRI challenges to an optional transcript context', () => {
    const coefficients: FieldElement[] = [3n, 1n, 4n, 1n]
    const evaluations = lowDegreeExtend(coefficients, 8)
    const transcriptContext = new Array(32).fill(7)
    const proof = proveFri(evaluations, {
      degreeBound: 4,
      numQueries: 6,
      maxRemainderSize: 4,
      transcriptContext
    })

    expect(verifyFri(proof, {
      ...friVerifierInput(proof),
      transcriptContext
    })).toBe(true)
    expect(verifyFri(proof, {
      ...friVerifierInput(proof),
      transcriptContext: transcriptContext.map((byte, index) =>
        index === 0 ? byte ^ 1 : byte
      )
    })).toBe(false)
  })

  it('proves and verifies FRI on a non-trivial coset', () => {
    const coefficients: FieldElement[] = [9n, 2n, 6n, 5n]
    const evaluations = cosetLowDegreeExtend(coefficients, 8, 5n)
    const proof = proveFri(evaluations, {
      degreeBound: 4,
      numQueries: 6,
      maxRemainderSize: 4,
      domainOffset: 5n
    })

    expect(verifyFri(proof, friVerifierInput(proof))).toBe(true)
    expect(verifyFri(proof, {
      ...friVerifierInput(proof),
      domainOffset: 7n
    })).toBe(false)
  })

  it('serializes and parses FRI proofs', () => {
    const coefficients: FieldElement[] = [6n, 2n, 8n, 3n]
    const proof = proveFri(lowDegreeExtend(coefficients, 8), {
      degreeBound: 4,
      numQueries: 4,
      maxRemainderSize: 4
    })
    const serialized = serializeFriProof(proof)
    const parsed = parseFriProof(serialized)

    expect(parsed).toEqual(proof)
    expect(verifyFri(parsed, friVerifierInput(parsed))).toBe(true)

    serialized[10] ^= 1
    expect(verifyParsedFri(serialized, friVerifierInput(proof))).toBe(false)
  })

  it('rejects tampered FRI commitments, openings, and remainders', () => {
    const coefficients: FieldElement[] = [2n, 7n, 1n]
    const evaluations = lowDegreeExtend(coefficients, 8)
    const proof = proveFri(evaluations, {
      degreeBound: 4,
      numQueries: 6,
      maxRemainderSize: 4
    })
    const input = friVerifierInput(proof)

    const badRoot = cloneFriProof(proof)
    badRoot.roots[0][0] ^= 1
    expect(verifyFri(badRoot, input)).toBe(false)

    const badOpening = cloneFriProof(proof)
    badOpening.queries[0].layers[0].leftValue = F.add(
      badOpening.queries[0].layers[0].leftValue,
      1n
    )
    expect(verifyFri(badOpening, input)).toBe(false)

    const badFinal = cloneFriProof(proof)
    badFinal.finalValues[0] = F.add(badFinal.finalValues[0], 1n)
    expect(verifyFri(badFinal, input)).toBe(false)
  })

  it('rejects FRI wrong parameters, duplicate indexes, and malformed bytes', () => {
    const lowDegreeProof = proveFri(lowDegreeExtend([1n, 2n, 3n], 8), {
      degreeBound: 4,
      numQueries: 6,
      maxRemainderSize: 4
    })
    const input = friVerifierInput(lowDegreeProof)
    expect(verifyFri(lowDegreeProof, {
      ...input,
      expectedRoot: input.expectedRoot.map((byte, index) => index === 0 ? byte ^ 1 : byte)
    })).toBe(false)
    expect(verifyFri(lowDegreeProof, {
      ...input,
      degreeBound: 3
    })).toBe(false)

    const duplicate = cloneFriProof(lowDegreeProof)
    duplicate.queries[1].initialIndex = duplicate.queries[0].initialIndex
    expect(verifyFri(duplicate, input)).toBe(false)

    const invalidIndex = cloneFriProof(lowDegreeProof)
    invalidIndex.queries[0].initialIndex = invalidIndex.domainSize
    expect(verifyFri(invalidIndex, input)).toBe(false)

    const highDegree = proveFri(lowDegreeExtend(new Array(20).fill(0n).map((_, i) => BigInt(i + 1)), 2), {
      degreeBound: 4,
      numQueries: 12,
      maxRemainderSize: 4
    })
    expect(verifyFri(highDegree, friVerifierInput(highDegree))).toBe(false)

    const serialized = serializeFriProof(lowDegreeProof)
    expect(() => parseFriProof([...serialized, 0])).toThrow()
    expect(() => parseFriProof(serialized.slice(0, -1))).toThrow()
  })

  it('proves and verifies a small one-step AIR STARK wrapper', () => {
    const trace: FieldElement[][] = [[5n], [5n], [5n], [5n]]
    const air = {
      traceWidth: 1,
      boundaryConstraints: [
        { column: 0, row: 0, value: 5n }
      ],
      evaluateTransition: (current: FieldElement[], next: FieldElement[]) => [
        F.sub(next[0], current[0])
      ]
    }
    const options = {
      blowupFactor: 4,
      numQueries: 4,
      maxRemainderSize: 4,
      maskDegree: 0,
      cosetOffset: 3n
    }
    const proof = proveStark(air, trace, options)

    expect(verifyStark(air, proof, options)).toBe(true)

    const parsed = parseStarkProof(serializeStarkProof(proof))
    expect(verifyStark(air, parsed, options)).toBe(true)

    const badTrace = cloneStarkProof(proof)
    badTrace.traceOpenings[0].row[0] = F.add(badTrace.traceOpenings[0].row[0], 1n)
    expect(verifyStark(air, badTrace, options)).toBe(false)

    const badComposition = cloneStarkProof(proof)
    badComposition.compositionOpenings[0].row[0] = F.add(
      badComposition.compositionOpenings[0].row[0],
      1n
    )
    expect(verifyStark(air, badComposition, options)).toBe(false)

    const badTraceLowDegree = cloneStarkProof(proof)
    badTraceLowDegree.traceLowDegreeOpenings[0].row[0] = F.add(
      badTraceLowDegree.traceLowDegreeOpenings[0].row[0],
      1n
    )
    expect(verifyStark(air, badTraceLowDegree, options)).toBe(false)

    const badTraceCombinationRoot = cloneStarkProof(proof)
    badTraceCombinationRoot.traceCombinationRoot[0] ^= 1
    expect(verifyStark(air, badTraceCombinationRoot, options)).toBe(false)

    expect(verifyStark(air, proof, {
      ...options,
      traceDegreeBound: proof.traceDegreeBound + 1
    })).toBe(false)

    expect(verifyStark(air, proof, {
      ...options,
      publicInputDigest: new Array(32).fill(1)
    })).toBe(false)
  })

  it('binds multiple traces into one shared transcript context', () => {
    const leftTrace: FieldElement[][] = [[2n], [3n], [5n], [8n]]
    const rightTrace: FieldElement[][] = [[7n], [7n], [7n], [7n]]
    const leftAir = {
      traceWidth: 1,
      boundaryConstraints: [
        { column: 0, row: 0, value: 2n },
        { column: 0, row: 3, value: 8n }
      ],
      evaluateTransition: (_current: FieldElement[], _next: FieldElement[]) => [
        0n
      ]
    }
    const rightAir = {
      traceWidth: 1,
      boundaryConstraints: [
        { column: 0, row: 0, value: 7n }
      ],
      evaluateTransition: (current: FieldElement[], next: FieldElement[]) => [
        F.sub(next[0], current[0])
      ]
    }
    const options = {
      blowupFactor: 4,
      numQueries: 4,
      maxRemainderSize: 4,
      maskDegree: 0,
      cosetOffset: 3n,
      transcriptDomain: 'BRC69_TEST_MULTI_TRACE'
    }
    const proof = proveMultiTraceStark([
      { name: 'left', air: leftAir, traceRows: leftTrace },
      { name: 'right', air: rightAir, traceRows: rightTrace }
    ], options)

    expect(proof.contextDigest).toHaveLength(32)
    expect(verifyMultiTraceStark([
      { name: 'left', air: leftAir },
      { name: 'right', air: rightAir }
    ], proof, options)).toBe(true)

    const tampered = {
      ...proof,
      contextDigest: proof.contextDigest.map((byte, index) =>
        index === 0 ? byte ^ 1 : byte
      )
    }
    expect(verifyMultiTraceStark([
      { name: 'left', air: leftAir },
      { name: 'right', air: rightAir }
    ], tampered, options)).toBe(false)

    const segmentTampered = {
      ...proof,
      segments: proof.segments.map(segment => segment.name === 'right'
        ? {
            ...segment,
            proof: {
              ...segment.proof,
              traceRoot: segment.proof.traceRoot.map((byte, index) =>
                index === 0 ? byte ^ 1 : byte
              )
            }
          }
        : segment)
    }
    expect(verifyMultiTraceStark([
      { name: 'left', air: leftAir },
      { name: 'right', air: rightAir }
    ], segmentTampered, options)).toBe(false)
  })

  it('rejects multi-trace proofs that select FRI degree bounds', () => {
    const trace: FieldElement[][] = [[1n], [1n], [1n], [1n]]
    const air = {
      traceWidth: 1,
      boundaryConstraints: [],
      evaluateTransition: (current: FieldElement[], next: FieldElement[]) => [
        F.sub(next[0], current[0])
      ]
    }
    const verifierOptions = {
      blowupFactor: 4,
      numQueries: 4,
      maxRemainderSize: 4,
      maskDegree: 0,
      cosetOffset: 3n,
      transcriptDomain: 'BRC69_TEST_MULTI_TRACE_PROOF_SELECTED_DEGREE'
    }
    const proofSelectedOptions = {
      ...verifierOptions,
      traceDegreeBound: 15,
      compositionDegreeBound: 15
    }
    const proof = proveMultiTraceStark([
      { name: 'segment', air, traceRows: trace }
    ], proofSelectedOptions)

    expect(verifyMultiTraceStark([
      { name: 'segment', air }
    ], proof, verifierOptions)).toBe(false)
    expect(verifyMultiTraceStark([
      { name: 'segment', air }
    ], proof, proofSelectedOptions)).toBe(true)
  })

  it('rejects multi-trace proofs that select the public-input digest', () => {
    const trace: FieldElement[][] = [[3n], [3n], [3n], [3n]]
    const air = {
      traceWidth: 1,
      boundaryConstraints: [],
      evaluateTransition: (current: FieldElement[], next: FieldElement[]) => [
        F.sub(next[0], current[0])
      ]
    }
    const verifierOptions = {
      blowupFactor: 4,
      numQueries: 4,
      maxRemainderSize: 4,
      maskDegree: 0,
      cosetOffset: 3n,
      transcriptDomain: 'BRC69_TEST_MULTI_TRACE_PROOF_SELECTED_DIGEST'
    }
    const proofDigest = new Array(32).fill(7)
    const proof = proveMultiTraceStark([
      { name: 'segment', air, traceRows: trace }
    ], {
      ...verifierOptions,
      publicInputDigest: proofDigest
    })

    expect(verifyMultiTraceStark([
      { name: 'segment', air }
    ], proof, verifierOptions)).toBe(false)
    expect(verifyMultiTraceStark([
      { name: 'segment', air }
    ], proof, {
      ...verifierOptions,
      publicInputDigest: proofDigest
    })).toBe(true)
  })

  it('proves cross-trace constraints over committed masked traces', () => {
    const leftTrace: FieldElement[][] = [[2n], [3n], [5n], [8n]]
    const rightTrace: FieldElement[][] = [[2n], [3n], [5n], [8n]]
    const air = {
      traceWidth: 1,
      boundaryConstraints: [],
      evaluateTransition: () => [0n]
    }
    const options = {
      blowupFactor: 4,
      numQueries: 4,
      maxRemainderSize: 4,
      maskDegree: 0,
      cosetOffset: 3n,
      transcriptDomain: 'BRC69_TEST_MULTI_TRACE_CROSS'
    }
    const crossConstraints = [{
      name: 'left-equals-right',
      refs: [
        { alias: 'left', segment: 'left' },
        { alias: 'right', segment: 'right' }
      ],
      evaluate: ({ rows }: { rows: Record<string, FieldElement[]> }) => [
        F.sub(rows.left[0], rows.right[0])
      ]
    }]
    const proof = proveMultiTraceStark([
      { name: 'left', air, traceRows: leftTrace },
      { name: 'right', air, traceRows: rightTrace }
    ], options, crossConstraints)

    expect(proof.crossProofs).toHaveLength(1)
    expect(verifyMultiTraceStark([
      { name: 'left', air },
      { name: 'right', air }
    ], proof, options, crossConstraints)).toBe(true)

    const withoutCrossProof = { ...proof, crossProofs: [] }
    expect(verifyMultiTraceStark([
      { name: 'left', air },
      { name: 'right', air }
    ], withoutCrossProof, options, crossConstraints)).toBe(false)
  })

  it('links hidden constant columns over a shared equality domain', () => {
    const leftTrace: FieldElement[][] = [[9n], [9n], [9n], [9n]]
    const rightTrace: FieldElement[][] = [
      [9n],
      [9n],
      [9n],
      [9n]
    ]
    const air = {
      traceWidth: 1,
      boundaryConstraints: [],
      evaluateTransition: (current: FieldElement[], next: FieldElement[]) => [
        F.sub(next[0], current[0])
      ]
    }
    const options = {
      blowupFactor: 4,
      numQueries: 4,
      maxRemainderSize: 4,
      maskDegree: 2,
      cosetOffset: 3n,
      maskSeed: [1, 2, 3, 4],
      transcriptDomain: 'BRC69_TEST_MULTI_TRACE_CONSTANT_LINK'
    }
    const links = [{
      name: 'constant-equality',
      left: { segment: 'left', column: 0 },
      right: { segment: 'right', column: 0 },
      numQueries: 3
    }]
    const proof = proveMultiTraceStark([
      { name: 'left', air, traceRows: leftTrace },
      { name: 'right', air, traceRows: rightTrace }
    ], options, [], links)

    expect(proof.constantColumnProofs).toHaveLength(1)
    expect(verifyMultiTraceStark([
      { name: 'left', air },
      { name: 'right', air }
    ], proof, options, [], links)).toBe(true)

    const tampered = {
      ...proof,
      constantColumnProofs: proof.constantColumnProofs?.map(item => ({
        ...item,
        queries: item.queries.map((query, index) => index === 0
          ? {
              ...query,
              right: {
                ...query.right,
                row: [F.add(query.right.row[0], 1n)]
              }
            }
          : query)
      }))
    }
    expect(verifyMultiTraceStark([
      { name: 'left', air },
      { name: 'right', air }
    ], tampered, options, [], links)).toBe(false)

    const withoutConstantProof = { ...proof, constantColumnProofs: [] }
    expect(verifyMultiTraceStark([
      { name: 'left', air },
      { name: 'right', air }
    ], withoutConstantProof, options, [], links)).toBe(false)
  })

  it('rejects hidden constant links without a shared equality domain', () => {
    const leftTrace: FieldElement[][] = [[9n], [9n], [9n], [9n]]
    const rightTrace: FieldElement[][] = [
      [9n],
      [9n],
      [9n],
      [9n],
      [9n],
      [9n],
      [9n],
      [9n]
    ]
    const air = {
      traceWidth: 1,
      boundaryConstraints: [],
      evaluateTransition: (current: FieldElement[], next: FieldElement[]) => [
        F.sub(next[0], current[0])
      ]
    }
    const options = {
      blowupFactor: 4,
      numQueries: 4,
      maxRemainderSize: 4,
      maskDegree: 2,
      cosetOffset: 3n,
      maskSeed: [1, 2, 3, 4],
      transcriptDomain: 'BRC69_TEST_MULTI_TRACE_CONSTANT_LINK_DOMAIN'
    }
    const links = [{
      name: 'constant-equality',
      left: { segment: 'left', column: 0 },
      right: { segment: 'right', column: 0 },
      numQueries: 3
    }]

    expect(() => proveMultiTraceStark([
      { name: 'left', air, traceRows: leftTrace },
      { name: 'right', air, traceRows: rightTrace }
    ], options, [], links)).toThrow('requires a shared equality domain')
  })
})

function friVerifierInput (proof: FriProof): FriVerifierInput {
  return {
    expectedRoot: proof.roots[0],
    domainSize: proof.domainSize,
    degreeBound: proof.degreeBound,
    numQueries: proof.numQueries,
    maxRemainderSize: proof.maxRemainderSize,
    domainOffset: proof.domainOffset
  }
}

function verifyParsedFri (
  serialized: number[],
  input: FriVerifierInput
): boolean {
  try {
    return verifyFri(parseFriProof(serialized), input)
  } catch {
    return false
  }
}

function cloneFriProof (proof: FriProof): FriProof {
  return {
    ...proof,
    roots: proof.roots.map(root => root.slice()),
    finalValues: proof.finalValues.slice(),
    queries: proof.queries.map(query => ({
      ...query,
      layers: query.layers.map(layer => ({
        ...layer,
        leftPath: layer.leftPath.map(item => ({
          sibling: item.sibling.slice(),
          siblingOnLeft: item.siblingOnLeft
        })),
        rightPath: layer.rightPath.map(item => ({
          sibling: item.sibling.slice(),
          siblingOnLeft: item.siblingOnLeft
        }))
      }))
    }))
  }
}

function cloneStarkProof (proof: StarkProof): StarkProof {
  return {
    ...proof,
    publicInputDigest: proof.publicInputDigest.slice(),
    traceRoot: proof.traceRoot.slice(),
    traceCombinationRoot: proof.traceCombinationRoot.slice(),
    compositionRoot: proof.compositionRoot.slice(),
    traceLowDegreeOpenings: cloneTraceOpenings(proof.traceLowDegreeOpenings),
    traceOpenings: cloneTraceOpenings(proof.traceOpenings),
    nextTraceOpenings: cloneTraceOpenings(proof.nextTraceOpenings),
    compositionOpenings: cloneTraceOpenings(proof.compositionOpenings),
    traceFriProof: cloneFriProof(proof.traceFriProof),
    friProof: cloneFriProof(proof.friProof)
  }
}

function cloneTraceOpenings (
  openings: StarkProof['traceOpenings']
): StarkProof['traceOpenings'] {
  return openings.map(opening => ({
    rowIndex: opening.rowIndex,
    row: opening.row.slice(),
    path: opening.path.map(item => ({
      sibling: item.sibling.slice(),
      siblingOnLeft: item.siblingOnLeft
    }))
  }))
}

function bigIntToBytesLE (value: bigint): number[] {
  const bytes: number[] = []
  for (let i = 0; i < 8; i++) {
    bytes.push(Number(value & 0xffn))
    value >>= 8n
  }
  return bytes
}
