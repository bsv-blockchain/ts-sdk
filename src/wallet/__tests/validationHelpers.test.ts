/**
 * Tests for src/wallet/validationHelpers.ts
 *
 * validationHelpers.ts is at ~20% coverage (215 missed lines).
 * All exported functions are covered here.  Private helpers are exercised
 * indirectly through the exported functions that call them.
 */

import WERR_INVALID_PARAMETER from '../WERR_INVALID_PARAMETER'
import {
  parseWalletOutpoint,
  validateSatoshis,
  validateOptionalInteger,
  validateInteger,
  validatePositiveIntegerOrZero,
  validateStringLength,
  validateBase64String,
  isHexString,
  validateCreateActionInput,
  validateCreateActionOutput,
  validateCreateActionOptions,
  validateCreateActionArgs,
  validateSignActionOptions,
  validateSignActionArgs,
  validateAbortActionArgs,
  validateWalletPayment,
  validateBasketInsertion,
  validateInternalizeOutput,
  validateOriginator,
  validateOptionalOutpointString,
  validateOutpointString,
  validateRelinquishOutputArgs,
  validateRelinquishCertificateArgs,
  validateListCertificatesArgs,
  validateAcquireIssuanceCertificateArgs,
  validateAcquireDirectCertificateArgs,
  validateProveCertificateArgs,
  validateDiscoverByIdentityKeyArgs,
  validateDiscoverByAttributesArgs,
  validateListOutputsArgs,
  validateListActionsArgs,
  specOpThrowReviewActions
} from '../validationHelpers'

// ---------------------------------------------------------------------------
// Shared test data
// ---------------------------------------------------------------------------

// Valid 64-char hex txid
const VALID_TXID = 'a'.repeat(64)
// Valid outpoint string
const VALID_OUTPOINT = `${VALID_TXID}.0`
// Valid compressed pubkey hex (66 chars)
const VALID_PUBKEY_HEX = '02' + 'ab'.repeat(32)
// Valid base64 strings
const VALID_BASE64 = 'SGVsbG8='          // "Hello" in base64
const VALID_BASE64_NOPAD = 'SGVsbG8'     // without padding (valid 4n+3)

// ============================================================================
// parseWalletOutpoint
// ============================================================================

describe('parseWalletOutpoint', () => {
  it('splits "txid.vout" into txid string and numeric vout', () => {
    const result = parseWalletOutpoint(`${VALID_TXID}.3`)
    expect(result.txid).toBe(VALID_TXID)
    expect(result.vout).toBe(3)
  })

  it('handles vout 0', () => {
    expect(parseWalletOutpoint(`${VALID_TXID}.0`).vout).toBe(0)
  })
})

// ============================================================================
// validateSatoshis
// ============================================================================

describe('validateSatoshis', () => {
  it('accepts 0 satoshis', () => {
    expect(validateSatoshis(0, 'amount')).toBe(0)
  })

  it('accepts maximum satoshis (21e14)', () => {
    expect(validateSatoshis(21e14, 'amount')).toBe(21e14)
  })

  it('throws for undefined', () => {
    expect(() => validateSatoshis(undefined, 'amount')).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws for a float', () => {
    expect(() => validateSatoshis(1.5, 'amount')).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws for a negative value', () => {
    expect(() => validateSatoshis(-1, 'amount')).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when value exceeds 21e14', () => {
    expect(() => validateSatoshis(21e14 + 1, 'amount')).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when below optional min', () => {
    expect(() => validateSatoshis(5, 'amount', 10)).toThrow(WERR_INVALID_PARAMETER)
  })

  it('accepts when exactly at optional min', () => {
    expect(validateSatoshis(10, 'amount', 10)).toBe(10)
  })
})

// ============================================================================
// validateInteger
// ============================================================================

describe('validateInteger', () => {
  it('returns the value when valid', () => {
    expect(validateInteger(5, 'n')).toBe(5)
  })

  it('returns defaultValue when v is undefined', () => {
    expect(validateInteger(undefined, 'n', 42)).toBe(42)
  })

  it('throws when undefined and no defaultValue', () => {
    expect(() => validateInteger(undefined, 'n')).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws for a non-integer', () => {
    expect(() => validateInteger(1.5, 'n')).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when below min', () => {
    expect(() => validateInteger(0, 'n', undefined, 1)).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when above max', () => {
    expect(() => validateInteger(11, 'n', undefined, undefined, 10)).toThrow(WERR_INVALID_PARAMETER)
  })

  it('accepts value at min boundary', () => {
    expect(validateInteger(1, 'n', undefined, 1)).toBe(1)
  })

  it('accepts value at max boundary', () => {
    expect(validateInteger(10, 'n', undefined, undefined, 10)).toBe(10)
  })
})

// ============================================================================
// validateOptionalInteger
// ============================================================================

describe('validateOptionalInteger', () => {
  it('returns undefined when v is undefined', () => {
    expect(validateOptionalInteger(undefined, 'n')).toBeUndefined()
  })

  it('returns the value when valid', () => {
    expect(validateOptionalInteger(5, 'n')).toBe(5)
  })

  it('throws for an invalid value', () => {
    expect(() => validateOptionalInteger(1.5, 'n')).toThrow(WERR_INVALID_PARAMETER)
  })
})

// ============================================================================
// validatePositiveIntegerOrZero
// ============================================================================

describe('validatePositiveIntegerOrZero', () => {
  it('accepts 0', () => {
    expect(validatePositiveIntegerOrZero(0, 'n')).toBe(0)
  })

  it('accepts positive integers', () => {
    expect(validatePositiveIntegerOrZero(100, 'n')).toBe(100)
  })

  it('throws for negative integers', () => {
    expect(() => validatePositiveIntegerOrZero(-1, 'n')).toThrow(WERR_INVALID_PARAMETER)
  })
})

// ============================================================================
// validateStringLength
// ============================================================================

describe('validateStringLength', () => {
  it('returns the string when within bounds', () => {
    expect(validateStringLength('hello', 's', 1, 10)).toBe('hello')
  })

  it('throws when string is too short', () => {
    expect(() => validateStringLength('hi', 's', 5)).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when string is too long', () => {
    expect(() => validateStringLength('hello world', 's', 1, 5)).toThrow(WERR_INVALID_PARAMETER)
  })

  it('accepts when no bounds provided', () => {
    expect(validateStringLength('any string at all', 's')).toBe('any string at all')
  })

  it('handles multi-byte UTF-8 characters correctly', () => {
    // '€' is 3 UTF-8 bytes
    const euro = '€'
    expect(() => validateStringLength(euro, 's', 1, 2)).toThrow(WERR_INVALID_PARAMETER)
    expect(validateStringLength(euro, 's', 1, 3)).toBe(euro)
  })
})

// ============================================================================
// validateBase64String
// ============================================================================

describe('validateBase64String', () => {
  it('accepts a valid padded base64 string', () => {
    expect(validateBase64String(VALID_BASE64, 's')).toBe(VALID_BASE64)
  })

  it('trims whitespace before validation', () => {
    expect(validateBase64String(`  ${VALID_BASE64}  `, 's')).toBe(VALID_BASE64)
  })

  it('throws for an empty string', () => {
    expect(() => validateBase64String('', 's')).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws for a string with invalid characters', () => {
    expect(() => validateBase64String('abc!', 's')).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when padding appears within the last 2 chars boundary', () => {
    // '=' at position i is only valid when i >= length - 2
    // 'a=bc' has '=' at i=1, length=4, so i < length-2 (1 < 2) → throws
    expect(() => validateBase64String('a=bc', 's')).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws for more than 2 padding characters', () => {
    expect(() => validateBase64String('a===', 's')).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when bytes are below min', () => {
    // VALID_BASE64 = "SGVsbG8=" → 5 decoded bytes
    expect(() => validateBase64String(VALID_BASE64, 's', 6)).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when bytes exceed max', () => {
    expect(() => validateBase64String(VALID_BASE64, 's', undefined, 3)).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws for unpadded base64 where length % 4 == 3 (not accepted by this validator)', () => {
    // This validator requires explicit padding or length % 4 == 0.
    // 'SGVsbG8' has 7 chars, 7 % 4 == 3. Since paddingCount=0, mod(3) != 4-0(4), so it throws.
    expect(() => validateBase64String(VALID_BASE64_NOPAD, 's')).toThrow(WERR_INVALID_PARAMETER)
  })

  it('accepts all valid base64 characters (A-Z, a-z, 0-9, +, /)', () => {
    const valid = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    // length 64 → multiple of 4, no padding needed
    expect(() => validateBase64String(valid, 's')).not.toThrow()
  })
})

// ============================================================================
// isHexString
// ============================================================================

describe('isHexString', () => {
  it('returns true for a valid lowercase hex string', () => {
    expect(isHexString('deadbeef')).toBe(true)
  })

  it('returns true for a valid uppercase hex string', () => {
    expect(isHexString('DEADBEEF')).toBe(true)
  })

  it('returns false for an odd-length string', () => {
    expect(isHexString('abc')).toBe(false)
  })

  it('returns false for a string with non-hex characters', () => {
    expect(isHexString('gg')).toBe(false)
  })

  it('trims whitespace before checking', () => {
    expect(isHexString('  deadbeef  ')).toBe(true)
  })
})

// ============================================================================
// validateOutpointString / validateOptionalOutpointString
// ============================================================================

describe('validateOutpointString', () => {
  it('returns "txid.vout" for a valid outpoint', () => {
    const result = validateOutpointString(VALID_OUTPOINT, 'output')
    expect(result).toContain('.')
    const [txid, vout] = result.split('.')
    expect(txid).toHaveLength(64)
    expect(Number(vout)).toBe(0)
  })

  it('throws when there is no dot separator', () => {
    expect(() => validateOutpointString('notanoutpoint', 'output')).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when vout is not numeric', () => {
    expect(() => validateOutpointString(`${VALID_TXID}.abc`, 'output')).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when txid is not valid hex', () => {
    expect(() => validateOutpointString('zzzzzzzz.0', 'output')).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when vout is negative', () => {
    expect(() => validateOutpointString(`${VALID_TXID}.-1`, 'output')).toThrow(WERR_INVALID_PARAMETER)
  })
})

describe('validateOptionalOutpointString', () => {
  it('returns undefined for undefined input', () => {
    expect(validateOptionalOutpointString(undefined, 'output')).toBeUndefined()
  })

  it('validates when a value is provided', () => {
    expect(validateOptionalOutpointString(VALID_OUTPOINT, 'output')).toBeDefined()
  })
})

// ============================================================================
// validateCreateActionInput
// ============================================================================

describe('validateCreateActionInput', () => {
  const validBase = {
    outpoint: VALID_OUTPOINT,
    inputDescription: 'A valid input description',
    sequenceNumber: 0xffffffff
  }

  it('accepts input with unlockingScript only', () => {
    const result = validateCreateActionInput({
      ...validBase,
      unlockingScript: 'aabb' // 2 bytes (4 hex chars / 2)
    })
    expect(result.unlockingScriptLength).toBe(2)
    expect(result.unlockingScript).toBe('aabb')
  })

  it('accepts input with unlockingScriptLength only', () => {
    const result = validateCreateActionInput({
      ...validBase,
      unlockingScriptLength: 107
    })
    expect(result.unlockingScriptLength).toBe(107)
    expect(result.unlockingScript).toBeUndefined()
  })

  it('throws when neither unlockingScript nor unlockingScriptLength is provided', () => {
    expect(() =>
      validateCreateActionInput({ ...validBase })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when unlockingScriptLength does not match actual script length', () => {
    expect(() =>
      validateCreateActionInput({
        ...validBase,
        unlockingScript: 'aabb', // 1 byte
        unlockingScriptLength: 5 // mismatch
      })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('uses default sequenceNumber 0xffffffff when not provided', () => {
    const result = validateCreateActionInput({
      ...validBase,
      sequenceNumber: undefined as any,
      unlockingScriptLength: 10
    })
    expect(result.sequenceNumber).toBe(0xffffffff)
  })

  it('throws for too-short inputDescription', () => {
    expect(() =>
      validateCreateActionInput({
        ...validBase,
        inputDescription: 'ab',
        unlockingScriptLength: 10
      })
    ).toThrow(WERR_INVALID_PARAMETER)
  })
})

// ============================================================================
// validateCreateActionOutput
// ============================================================================

describe('validateCreateActionOutput', () => {
  const validBase = {
    lockingScript: 'aabbcc',
    satoshis: 1000,
    outputDescription: 'A valid output description'
  }

  it('accepts a minimal valid output', () => {
    const result = validateCreateActionOutput(validBase)
    expect(result.satoshis).toBe(1000)
    expect(result.lockingScript).toBe('aabbcc')
  })

  it('normalises tags via validateTag (trim + lowercase)', () => {
    const result = validateCreateActionOutput({
      ...validBase,
      tags: ['  MyTag  ', 'ANOTHER']
    })
    expect(result.tags).toEqual(['mytag', 'another'])
  })

  it('accepts optional basket', () => {
    const result = validateCreateActionOutput({
      ...validBase,
      basket: 'my-basket'
    })
    expect(result.basket).toBe('my-basket')
  })

  it('throws for invalid satoshis', () => {
    expect(() =>
      validateCreateActionOutput({ ...validBase, satoshis: -1 })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws for invalid locking script (odd hex length)', () => {
    expect(() =>
      validateCreateActionOutput({ ...validBase, lockingScript: 'abc' })
    ).toThrow(WERR_INVALID_PARAMETER)
  })
})

// ============================================================================
// validateCreateActionOptions
// ============================================================================

describe('validateCreateActionOptions', () => {
  it('applies all defaults when options is undefined', () => {
    const v = validateCreateActionOptions(undefined)
    expect(v.signAndProcess).toBe(true)
    expect(v.acceptDelayedBroadcast).toBe(true)
    expect(v.returnTXIDOnly).toBe(false)
    expect(v.noSend).toBe(false)
    expect(v.randomizeOutputs).toBe(true)
    expect(v.knownTxids).toEqual([])
    expect(v.sendWith).toEqual([])
    expect(v.noSendChange).toEqual([])
  })

  it('applies all defaults when options is an empty object', () => {
    const v = validateCreateActionOptions({})
    expect(v.signAndProcess).toBe(true)
    expect(v.randomizeOutputs).toBe(true)
  })

  it('preserves explicit boolean overrides', () => {
    const v = validateCreateActionOptions({
      signAndProcess: false,
      returnTXIDOnly: true,
      noSend: true,
      randomizeOutputs: false
    })
    expect(v.signAndProcess).toBe(false)
    expect(v.returnTXIDOnly).toBe(true)
    expect(v.noSend).toBe(true)
    expect(v.randomizeOutputs).toBe(false)
  })

  it('parses noSendChange outpoint strings', () => {
    const v = validateCreateActionOptions({
      noSendChange: [VALID_OUTPOINT]
    })
    expect(v.noSendChange).toHaveLength(1)
    expect(v.noSendChange[0].txid).toHaveLength(64)
  })
})

// ============================================================================
// validateCreateActionArgs
// ============================================================================

describe('validateCreateActionArgs', () => {
  const minimalArgs = {
    description: 'A valid action description'
  }

  it('validates a minimal args object with just a description', () => {
    const v = validateCreateActionArgs(minimalArgs as any)
    expect(v.description).toBe('A valid action description')
    expect(v.inputs).toEqual([])
    expect(v.outputs).toEqual([])
  })

  it('sets isRemixChange = true when no inputs and no outputs and no sendWith', () => {
    const v = validateCreateActionArgs(minimalArgs as any)
    expect(v.isRemixChange).toBe(true)
    expect(v.isNewTx).toBe(true)
  })

  it('sets isSignAction = true when input lacks an unlockingScript', () => {
    const v = validateCreateActionArgs({
      ...minimalArgs,
      inputs: [
        {
          outpoint: VALID_OUTPOINT,
          inputDescription: 'An input with no unlock',
          unlockingScriptLength: 107
        }
      ]
    } as any)
    expect(v.isSignAction).toBe(true)
  })

  it('sets isSignAction = false when all inputs have compiled unlocking scripts and signAndProcess = true', () => {
    const v = validateCreateActionArgs({
      ...minimalArgs,
      inputs: [
        {
          outpoint: VALID_OUTPOINT,
          inputDescription: 'An input with unlock',
          unlockingScript: 'aabb',
          unlockingScriptLength: 2
        }
      ],
      options: { signAndProcess: true }
    } as any)
    expect(v.isSignAction).toBe(false)
  })

  it('sets isTestWerrReviewActions when the specOp label is present', () => {
    const v = validateCreateActionArgs({
      ...minimalArgs,
      labels: [specOpThrowReviewActions]
    } as any)
    expect(v.isTestWerrReviewActions).toBe(true)
  })

  it('throws for a description that is too short', () => {
    expect(() =>
      validateCreateActionArgs({ description: 'hi' } as any)
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('validates labels via validateLabel (trim + lowercase)', () => {
    const v = validateCreateActionArgs({
      ...minimalArgs,
      labels: ['  MyLabel  ']
    } as any)
    expect(v.labels).toEqual(['mylabel'])
  })
})

// ============================================================================
// validateSignActionOptions
// ============================================================================

describe('validateSignActionOptions', () => {
  it('applies defaults when options is undefined', () => {
    const v = validateSignActionOptions(undefined)
    expect(v.acceptDelayedBroadcast).toBe(true)
    expect(v.returnTXIDOnly).toBe(false)
    expect(v.noSend).toBe(false)
    expect(v.sendWith).toEqual([])
  })

  it('preserves explicit values', () => {
    const v = validateSignActionOptions({ noSend: true, returnTXIDOnly: true })
    expect(v.noSend).toBe(true)
    expect(v.returnTXIDOnly).toBe(true)
  })
})

// ============================================================================
// validateSignActionArgs
// ============================================================================

describe('validateSignActionArgs', () => {
  const minimalSignArgs = {
    spends: {},
    reference: VALID_BASE64
  }

  it('returns a valid object with flags set', () => {
    const v = validateSignActionArgs(minimalSignArgs as any)
    expect(v.isNewTx).toBe(true)
    expect(v.isSendWith).toBe(false)
  })

  it('sets isSendWith when sendWith is non-empty', () => {
    const v = validateSignActionArgs({
      ...minimalSignArgs,
      options: { sendWith: [VALID_TXID] }
    } as any)
    expect(v.isSendWith).toBe(true)
  })
})

// ============================================================================
// validateAbortActionArgs
// ============================================================================

describe('validateAbortActionArgs', () => {
  it('accepts a valid base64 reference', () => {
    const v = validateAbortActionArgs({ reference: VALID_BASE64 })
    expect(v.reference).toBe(VALID_BASE64)
  })

  it('throws for an invalid reference', () => {
    expect(() =>
      validateAbortActionArgs({ reference: '!invalid!' })
    ).toThrow(WERR_INVALID_PARAMETER)
  })
})

// ============================================================================
// validateWalletPayment
// ============================================================================

describe('validateWalletPayment', () => {
  it('returns undefined when called with undefined', () => {
    expect(validateWalletPayment(undefined)).toBeUndefined()
  })

  it('validates a complete wallet payment structure', () => {
    const v = validateWalletPayment({
      derivationPrefix: VALID_BASE64,
      derivationSuffix: VALID_BASE64,
      senderIdentityKey: VALID_PUBKEY_HEX
    })
    expect(v).toBeDefined()
    expect(v!.senderIdentityKey).toBe(VALID_PUBKEY_HEX.toLowerCase())
  })

  it('throws for an invalid derivationPrefix', () => {
    expect(() =>
      validateWalletPayment({
        derivationPrefix: '!!!',
        derivationSuffix: VALID_BASE64,
        senderIdentityKey: VALID_PUBKEY_HEX
      })
    ).toThrow(WERR_INVALID_PARAMETER)
  })
})

// ============================================================================
// validateBasketInsertion
// ============================================================================

describe('validateBasketInsertion', () => {
  it('returns undefined when called with undefined', () => {
    expect(validateBasketInsertion(undefined)).toBeUndefined()
  })

  it('validates a basket insertion with basket and tags', () => {
    const v = validateBasketInsertion({
      basket: 'my-basket',
      tags: ['tag1', 'TAG2']
    })
    expect(v).toBeDefined()
    expect(v!.basket).toBe('my-basket')
    expect(v!.tags).toEqual(['tag1', 'tag2'])
  })

  it('throws for an empty basket name', () => {
    expect(() =>
      validateBasketInsertion({ basket: '' })
    ).toThrow(WERR_INVALID_PARAMETER)
  })
})

// ============================================================================
// validateInternalizeOutput
// ============================================================================

describe('validateInternalizeOutput', () => {
  it('accepts a "wallet payment" output', () => {
    const v = validateInternalizeOutput({
      outputIndex: 0,
      protocol: 'wallet payment',
      paymentRemittance: {
        derivationPrefix: VALID_BASE64,
        derivationSuffix: VALID_BASE64,
        senderIdentityKey: VALID_PUBKEY_HEX
      }
    })
    expect(v.protocol).toBe('wallet payment')
    expect(v.outputIndex).toBe(0)
  })

  it('accepts a "basket insertion" output', () => {
    const v = validateInternalizeOutput({
      outputIndex: 1,
      protocol: 'basket insertion',
      insertionRemittance: { basket: 'default' }
    })
    expect(v.protocol).toBe('basket insertion')
  })

  it('throws for an unknown protocol', () => {
    expect(() =>
      validateInternalizeOutput({
        outputIndex: 0,
        protocol: 'unknown' as any
      })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws for a negative outputIndex', () => {
    expect(() =>
      validateInternalizeOutput({
        outputIndex: -1,
        protocol: 'basket insertion'
      })
    ).toThrow(WERR_INVALID_PARAMETER)
  })
})

// ============================================================================
// validateOriginator
// ============================================================================

describe('validateOriginator', () => {
  it('returns undefined for undefined input', () => {
    expect(validateOriginator(undefined)).toBeUndefined()
  })

  it('normalises to lowercase and trims whitespace', () => {
    expect(validateOriginator('  Example.COM  ')).toBe('example.com')
  })

  it('accepts a simple domain name', () => {
    expect(validateOriginator('example.com')).toBe('example.com')
  })

  it('throws for an empty originator after trimming', () => {
    expect(() => validateOriginator('   ')).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws for a domain part exceeding 63 bytes', () => {
    const longPart = 'a'.repeat(64)
    expect(() => validateOriginator(`${longPart}.com`)).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws for an originator exceeding 250 total bytes', () => {
    const longOriginator = 'a'.repeat(251)
    expect(() => validateOriginator(longOriginator)).toThrow(WERR_INVALID_PARAMETER)
  })
})

// ============================================================================
// validateRelinquishOutputArgs
// ============================================================================

describe('validateRelinquishOutputArgs', () => {
  it('validates a complete set of args', () => {
    const v = validateRelinquishOutputArgs({
      basket: 'default',
      output: VALID_OUTPOINT
    })
    expect(v.basket).toBe('default')
    expect(v.output).toContain('.')
  })

  it('throws for invalid basket', () => {
    expect(() =>
      validateRelinquishOutputArgs({ basket: '', output: VALID_OUTPOINT })
    ).toThrow(WERR_INVALID_PARAMETER)
  })
})

// ============================================================================
// validateRelinquishCertificateArgs
// ============================================================================

describe('validateRelinquishCertificateArgs', () => {
  it('validates a valid certificate reference', () => {
    const v = validateRelinquishCertificateArgs({
      type: VALID_BASE64,
      serialNumber: VALID_BASE64,
      certifier: VALID_PUBKEY_HEX
    })
    expect(v.type).toBe(VALID_BASE64)
  })

  it('throws for an invalid type', () => {
    expect(() =>
      validateRelinquishCertificateArgs({
        type: '!!!',
        serialNumber: VALID_BASE64,
        certifier: VALID_PUBKEY_HEX
      })
    ).toThrow(WERR_INVALID_PARAMETER)
  })
})

// ============================================================================
// validateListCertificatesArgs
// ============================================================================

describe('validateListCertificatesArgs', () => {
  const validArgs = {
    certifiers: [VALID_PUBKEY_HEX],
    types: [VALID_BASE64],
    limit: 10,
    offset: 0
  }

  it('validates a minimal set of args with defaults', () => {
    const v = validateListCertificatesArgs(validArgs as any)
    expect(v.limit).toBe(10)
    expect(v.offset).toBe(0)
    expect(v.privileged).toBe(false)
  })

  it('applies default limit of 10 when limit is undefined', () => {
    const v = validateListCertificatesArgs({ ...validArgs, limit: undefined } as any)
    expect(v.limit).toBe(10)
  })

  it('throws when limit exceeds 10000', () => {
    expect(() =>
      validateListCertificatesArgs({ ...validArgs, limit: 10001 } as any)
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when limit is below 1', () => {
    expect(() =>
      validateListCertificatesArgs({ ...validArgs, limit: 0 } as any)
    ).toThrow(WERR_INVALID_PARAMETER)
  })
})

// ============================================================================
// validateAcquireIssuanceCertificateArgs
// ============================================================================

describe('validateAcquireIssuanceCertificateArgs', () => {
  const validIssuanceArgs: any = {
    acquisitionProtocol: 'issuance',
    type: VALID_BASE64,
    certifier: VALID_PUBKEY_HEX,
    certifierUrl: 'https://example.com/certify',
    fields: { name: 'Alice' },
    privileged: false
  }

  it('validates a valid issuance request', () => {
    const v = validateAcquireIssuanceCertificateArgs(validIssuanceArgs)
    expect(v.certifierUrl).toBe('https://example.com/certify')
    expect(v.subject).toBe('')
  })

  it('throws when acquisitionProtocol is not "issuance"', () => {
    expect(() =>
      validateAcquireIssuanceCertificateArgs({ ...validIssuanceArgs, acquisitionProtocol: 'direct' })
    ).toThrow('Only acquire certificate via issuance requests allowed here.')
  })

  it('throws when serialNumber is present (not valid for issuance)', () => {
    expect(() =>
      validateAcquireIssuanceCertificateArgs({ ...validIssuanceArgs, serialNumber: VALID_BASE64 })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when signature is present', () => {
    expect(() =>
      validateAcquireIssuanceCertificateArgs({ ...validIssuanceArgs, signature: VALID_PUBKEY_HEX })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when revocationOutpoint is present', () => {
    expect(() =>
      validateAcquireIssuanceCertificateArgs({ ...validIssuanceArgs, revocationOutpoint: VALID_OUTPOINT })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when keyringRevealer is present', () => {
    expect(() =>
      validateAcquireIssuanceCertificateArgs({ ...validIssuanceArgs, keyringRevealer: 'certifier' })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when keyringForSubject is present', () => {
    expect(() =>
      validateAcquireIssuanceCertificateArgs({ ...validIssuanceArgs, keyringForSubject: {} })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when certifierUrl is missing', () => {
    expect(() =>
      validateAcquireIssuanceCertificateArgs({ ...validIssuanceArgs, certifierUrl: undefined })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when privileged is true but privilegedReason is absent', () => {
    expect(() =>
      validateAcquireIssuanceCertificateArgs({ ...validIssuanceArgs, privileged: true })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('accepts privileged=true with a valid privilegedReason', () => {
    const v = validateAcquireIssuanceCertificateArgs({
      ...validIssuanceArgs,
      privileged: true,
      privilegedReason: 'A valid reason'
    })
    expect(v.privileged).toBe(true)
  })
})

// ============================================================================
// validateAcquireDirectCertificateArgs
// ============================================================================

describe('validateAcquireDirectCertificateArgs', () => {
  const validDirectArgs: any = {
    acquisitionProtocol: 'direct',
    type: VALID_BASE64,
    serialNumber: VALID_BASE64,
    certifier: VALID_PUBKEY_HEX,
    revocationOutpoint: VALID_OUTPOINT,
    fields: { name: 'Bob' },
    signature: VALID_PUBKEY_HEX,
    keyringRevealer: 'certifier',
    keyringForSubject: { fieldA: VALID_BASE64 },
    privileged: false
  }

  it('validates a valid direct acquisition request', () => {
    const v = validateAcquireDirectCertificateArgs(validDirectArgs)
    expect(v.subject).toBe('')
    expect(v.keyringRevealer).toBe('certifier')
  })

  it('throws when acquisitionProtocol is not "direct"', () => {
    expect(() =>
      validateAcquireDirectCertificateArgs({ ...validDirectArgs, acquisitionProtocol: 'issuance' })
    ).toThrow('Only acquire direct certificate requests allowed here.')
  })

  it('throws when serialNumber is missing', () => {
    expect(() =>
      validateAcquireDirectCertificateArgs({ ...validDirectArgs, serialNumber: undefined })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when signature is missing', () => {
    expect(() =>
      validateAcquireDirectCertificateArgs({ ...validDirectArgs, signature: undefined })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when revocationOutpoint is missing', () => {
    expect(() =>
      validateAcquireDirectCertificateArgs({ ...validDirectArgs, revocationOutpoint: undefined })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when keyringRevealer is missing', () => {
    expect(() =>
      validateAcquireDirectCertificateArgs({ ...validDirectArgs, keyringRevealer: undefined })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when keyringForSubject is null/undefined', () => {
    expect(() =>
      validateAcquireDirectCertificateArgs({ ...validDirectArgs, keyringForSubject: undefined })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('throws when privileged is true but privilegedReason is absent', () => {
    expect(() =>
      validateAcquireDirectCertificateArgs({ ...validDirectArgs, privileged: true, privilegedReason: undefined })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('validates a keyringRevealer hex string (non-"certifier")', () => {
    const v = validateAcquireDirectCertificateArgs({
      ...validDirectArgs,
      keyringRevealer: VALID_PUBKEY_HEX
    })
    expect(v.keyringRevealer).toBe(VALID_PUBKEY_HEX.toLowerCase())
  })
})

// ============================================================================
// validateProveCertificateArgs
// ============================================================================

describe('validateProveCertificateArgs', () => {
  const validArgs: any = {
    certificate: {
      type: VALID_BASE64,
      serialNumber: VALID_BASE64,
      certifier: VALID_PUBKEY_HEX,
      subject: VALID_PUBKEY_HEX
    },
    fieldsToReveal: ['fieldA', 'fieldB'],
    verifier: VALID_PUBKEY_HEX,
    privileged: false
  }

  it('validates a complete prove certificate request', () => {
    const v = validateProveCertificateArgs(validArgs)
    expect(v.verifier).toBeDefined()
    expect(v.fieldsToReveal).toEqual(['fieldA', 'fieldB'])
    expect(v.privileged).toBe(false)
  })

  it('throws when privileged is true but privilegedReason is absent', () => {
    expect(() =>
      validateProveCertificateArgs({ ...validArgs, privileged: true })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('accepts privileged=true with a valid reason', () => {
    const v = validateProveCertificateArgs({
      ...validArgs,
      privileged: true,
      privilegedReason: 'A good reason'
    })
    expect(v.privileged).toBe(true)
  })

  it('handles undefined optional certificate fields', () => {
    const v = validateProveCertificateArgs({
      ...validArgs,
      certificate: {}
    })
    expect(v.type).toBeUndefined()
    expect(v.certifier).toBeUndefined()
  })
})

// ============================================================================
// validateDiscoverByIdentityKeyArgs
// ============================================================================

describe('validateDiscoverByIdentityKeyArgs', () => {
  const validArgs: any = {
    identityKey: VALID_PUBKEY_HEX,
    limit: 10,
    offset: 0
  }

  it('validates a valid request', () => {
    const v = validateDiscoverByIdentityKeyArgs(validArgs)
    expect(v.identityKey).toBe(VALID_PUBKEY_HEX.toLowerCase())
    expect(v.seekPermission).toBe(false)
  })

  it('applies default limit of 10', () => {
    const v = validateDiscoverByIdentityKeyArgs({ ...validArgs, limit: undefined })
    expect(v.limit).toBe(10)
  })

  it('throws for identity key that is not 66 chars', () => {
    expect(() =>
      validateDiscoverByIdentityKeyArgs({ ...validArgs, identityKey: '0234' })
    ).toThrow(WERR_INVALID_PARAMETER)
  })
})

// ============================================================================
// validateDiscoverByAttributesArgs
// ============================================================================

describe('validateDiscoverByAttributesArgs', () => {
  const validArgs: any = {
    attributes: { name: 'Alice' },
    limit: 10,
    offset: 0
  }

  it('validates a valid request', () => {
    const v = validateDiscoverByAttributesArgs(validArgs)
    expect(v.attributes).toEqual({ name: 'Alice' })
    expect(v.seekPermission).toBe(false)
  })

  it('applies default limit of 10', () => {
    const v = validateDiscoverByAttributesArgs({ ...validArgs, limit: undefined })
    expect(v.limit).toBe(10)
  })

  it('throws for a field name that is too long', () => {
    const longName = 'a'.repeat(51)
    expect(() =>
      validateDiscoverByAttributesArgs({ ...validArgs, attributes: { [longName]: 'value' } })
    ).toThrow(WERR_INVALID_PARAMETER)
  })
})

// ============================================================================
// validateListOutputsArgs
// ============================================================================

describe('validateListOutputsArgs', () => {
  const validArgs: any = {
    basket: 'default',
    limit: 10,
    offset: 0
  }

  it('validates minimal args', () => {
    const v = validateListOutputsArgs(validArgs)
    expect(v.basket).toBe('default')
    expect(v.tagQueryMode).toBe('any')
    expect(v.includeLockingScripts).toBe(false)
    expect(v.includeTransactions).toBe(false)
  })

  it('sets includeLockingScripts = true when include = "locking scripts"', () => {
    const v = validateListOutputsArgs({ ...validArgs, include: 'locking scripts' })
    expect(v.includeLockingScripts).toBe(true)
    expect(v.includeTransactions).toBe(false)
  })

  it('sets includeTransactions = true when include = "entire transactions"', () => {
    const v = validateListOutputsArgs({ ...validArgs, include: 'entire transactions' })
    expect(v.includeTransactions).toBe(true)
    expect(v.includeLockingScripts).toBe(false)
  })

  it('accepts tagQueryMode "all"', () => {
    const v = validateListOutputsArgs({ ...validArgs, tagQueryMode: 'all' })
    expect(v.tagQueryMode).toBe('all')
  })

  it('throws for invalid tagQueryMode', () => {
    expect(() =>
      validateListOutputsArgs({ ...validArgs, tagQueryMode: 'none' })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('applies default limit', () => {
    const v = validateListOutputsArgs({ ...validArgs, limit: undefined })
    expect(v.limit).toBe(10)
  })
})

// ============================================================================
// validateListActionsArgs
// ============================================================================

describe('validateListActionsArgs', () => {
  const validArgs: any = {
    labels: ['my-label'],
    limit: 10,
    offset: 0
  }

  it('validates minimal args', () => {
    const v = validateListActionsArgs(validArgs)
    expect(v.labels).toEqual(['my-label'])
    expect(v.labelQueryMode).toBe('any')
    expect(v.includeInputs).toBe(false)
    expect(v.includeOutputs).toBe(false)
  })

  it('accepts labelQueryMode "all"', () => {
    const v = validateListActionsArgs({ ...validArgs, labelQueryMode: 'all' })
    expect(v.labelQueryMode).toBe('all')
  })

  it('throws for invalid labelQueryMode', () => {
    expect(() =>
      validateListActionsArgs({ ...validArgs, labelQueryMode: 'none' })
    ).toThrow(WERR_INVALID_PARAMETER)
  })

  it('applies default limit of 10', () => {
    const v = validateListActionsArgs({ ...validArgs, limit: undefined })
    expect(v.limit).toBe(10)
  })

  it('applies boolean include flags', () => {
    const v = validateListActionsArgs({
      ...validArgs,
      includeInputs: true,
      includeOutputs: true,
      includeLabels: true,
      includeInputSourceLockingScripts: true,
      includeInputUnlockingScripts: true,
      includeOutputLockingScripts: true
    })
    expect(v.includeInputs).toBe(true)
    expect(v.includeOutputs).toBe(true)
    expect(v.includeLabels).toBe(true)
    expect(v.includeInputSourceLockingScripts).toBe(true)
    expect(v.includeInputUnlockingScripts).toBe(true)
    expect(v.includeOutputLockingScripts).toBe(true)
  })
})

// ============================================================================
// specOpThrowReviewActions constant
// ============================================================================

describe('specOpThrowReviewActions', () => {
  it('is a non-empty string constant', () => {
    expect(typeof specOpThrowReviewActions).toBe('string')
    expect(specOpThrowReviewActions.length).toBeGreaterThan(0)
  })
})
