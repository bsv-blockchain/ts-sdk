import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  BRC69_METHOD2_WHOLE_STATEMENT_PRODUCTION_PROFILE,
  parseSpecificKeyLinkageProofPayload,
  serializeBRC69SpecificKeyLinkageProof,
  serializeSpecificKeyLinkageProofPayload,
  verifySpecificKeyLinkageProof
} from '../brc69/index'
import {
  BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS,
  brc69Method2WholeStatementDeterministicFixture
} from '../brc69/method2/index'
import {
  MultiTraceStarkProof,
  StarkProof
} from '../brc69/stark/index'
import { compressPoint } from '../brc69/circuit/index'

describe('BRC-69 key linkage proof payload', () => {
  it('serializes and parses the whole-statement payload envelope', () => {
    const fixture = brc69Method2WholeStatementDeterministicFixture()
    const proof = {
      profileId: BRC69_METHOD2_WHOLE_STATEMENT_PRODUCTION_PROFILE,
      publicInput: fixture.publicInput,
      proof: dummyWholeStatementProof()
    }

    const payload = serializeSpecificKeyLinkageProofPayload(proof)
    const parsed = parseSpecificKeyLinkageProofPayload(payload)

    expect(parsed.proofType).toBe(1)
    if (parsed.proofType !== 1) throw new Error('unexpected proof type')
    expect(parsed.proof.profileId)
      .toBe(BRC69_METHOD2_WHOLE_STATEMENT_PRODUCTION_PROFILE)
    expect(parsed.proof.publicInput.hmacMode).toBe('lookup')
    expect(parsed.proof.proof.segments.map(segment => segment.name))
      .toEqual(['scalar', 'lookup', 'ec', 'compression', 'hmac', 'bridge'])
  })

  it('keeps legacy proof type 0 isolated', () => {
    expect(parseSpecificKeyLinkageProofPayload([0])).toEqual({ proofType: 0 })
    expect(() => parseSpecificKeyLinkageProofPayload([0, 1]))
      .toThrow('Proof type 0 payload must not contain proof bytes')
  })

  it('rejects old, malformed, and trailing proof payload bytes', () => {
    const fixture = brc69Method2WholeStatementDeterministicFixture()
    const payload = serializeSpecificKeyLinkageProofPayload({
      profileId: BRC69_METHOD2_WHOLE_STATEMENT_PRODUCTION_PROFILE,
      publicInput: fixture.publicInput,
      proof: dummyWholeStatementProof()
    })
    const badProfile = payload.slice()
    badProfile[1 + ascii('BRC69_METHOD2_WHOLE_STATEMENT_PROOF_V1').length] = 99

    const oldMagic = ascii('BRC69_METHOD2_COMPOSITE_V1')
    expect(() => parseSpecificKeyLinkageProofPayload([
      1,
      ...oldMagic,
      ...new Array(
        ascii('BRC69_METHOD2_WHOLE_STATEMENT_PROOF_V1').length -
        oldMagic.length
      ).fill(0)
    ])).toThrow('Invalid BRC69 Method 2 whole-statement proof magic')
    expect(() => parseSpecificKeyLinkageProofPayload(badProfile))
      .toThrow('Unsupported BRC69 Method 2 proof profile')
    expect(() => parseSpecificKeyLinkageProofPayload([...payload, 0]))
      .toThrow('Unexpected trailing bytes in BRC69 proof payload')
  })

  it('rejects non-lookup HMAC public inputs before serialization', () => {
    const fixture = brc69Method2WholeStatementDeterministicFixture()
    const publicInput = {
      ...fixture.publicInput,
      hmacMode: 'compact'
    } as typeof fixture.publicInput

    expect(() => serializeBRC69SpecificKeyLinkageProof({
      profileId: BRC69_METHOD2_WHOLE_STATEMENT_PRODUCTION_PROFILE,
      publicInput,
      proof: dummyWholeStatementProof()
    })).toThrow('HMAC mode must be lookup')
  })

  it('rejects statement/public-input mismatches', () => {
    const fixture = brc69Method2WholeStatementDeterministicFixture()
    const statement = {
      prover: compressPoint(fixture.publicInput.publicA)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join(''),
      counterparty: compressPoint(fixture.publicInput.baseB)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join(''),
      protocolID: [0, 'tests'] as [0, string],
      keyID: 'test key',
      linkage: fixture.publicInput.linkage
    }

    expect(verifySpecificKeyLinkageProof(statement, {
      profileId: BRC69_METHOD2_WHOLE_STATEMENT_PRODUCTION_PROFILE,
      publicInput: fixture.publicInput,
      proof: dummyWholeStatementProof()
    })).toBe(false)
  })
})

function dummyWholeStatementProof (): MultiTraceStarkProof {
  return {
    transcriptDomain: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.transcriptDomain,
    contextDigest: new Array(32).fill(0),
    segments: ['scalar', 'lookup', 'ec', 'compression', 'hmac', 'bridge']
      .map(name => ({
        name,
        proof: dummyStarkProof()
      })),
    crossProofs: [{
      name: 'segment-bus',
      compositionRoot: new Array(32).fill(0),
      friProof: dummyStarkProof().friProof,
      openings: []
    }],
    constantColumnProofs: []
  }
}

function dummyStarkProof (): StarkProof {
  const traceLength = 64
  const blowupFactor = BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.blowupFactor
  const ldeSize = traceLength * blowupFactor
  return {
    traceLength,
    traceWidth: 1,
    blowupFactor,
    numQueries: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.numQueries,
    maxRemainderSize:
      BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maxRemainderSize,
    maskDegree: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maskDegree,
    traceDegreeBound: traceLength +
      BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maskDegree,
    compositionDegreeBound: traceLength + 16,
    cosetOffset: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.cosetOffset,
    publicInputDigest: new Array(32).fill(0),
    traceRoot: new Array(32).fill(0),
    traceCombinationRoot: new Array(32).fill(0),
    compositionRoot: new Array(32).fill(0),
    traceLowDegreeOpenings: [],
    traceOpenings: [],
    nextTraceOpenings: [],
    compositionOpenings: [],
    traceFriProof: dummyFriProof(ldeSize, traceLength + 2),
    friProof: dummyFriProof(ldeSize, traceLength + 16)
  }
}

function dummyFriProof (domainSize: number, degreeBound: number): StarkProof['friProof'] {
  return {
    domainSize,
    degreeBound,
    numQueries: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.numQueries,
    maxRemainderSize:
      BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maxRemainderSize,
    domainOffset: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.cosetOffset,
    roots: [new Array(32).fill(0)],
    finalValues: [0n],
    queries: []
  }
}

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}
