/**
 * Additional WalletClient tests focusing on:
 *  1. Constructor substrate selection (string aliases)
 *  2. Parameter validation that fires BEFORE connectToSubstrate() is called
 *
 * None of the tests below make real network connections.
 * The validation helpers throw WERR_INVALID_PARAMETER synchronously, so the
 * async methods reject immediately without ever reaching the substrate.
 */

import WalletClient from '../WalletClient'
import HTTPWalletJSON from '../substrates/HTTPWalletJSON'
import WalletWireTransceiver from '../substrates/WalletWireTransceiver'
import { WERR_INVALID_PARAMETER } from '../WERR_INVALID_PARAMETER'
import type { WalletInterface } from '../Wallet.interfaces'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Expect `fn` to throw (or reject) with WERR_INVALID_PARAMETER and the given
 * parameter name.  Works for both sync throws and async rejections.
 */
async function expectInvalidParam(fn: () => Promise<unknown>, expectedParam: string): Promise<void> {
  try {
    await fn()
    throw new Error('Expected WERR_INVALID_PARAMETER but nothing was thrown')
  } catch (e: unknown) {
    const err = e as WERR_INVALID_PARAMETER
    expect(err.name).toBe('WERR_INVALID_PARAMETER')
    expect(err.parameter).toBe(expectedParam)
  }
}

// ---------------------------------------------------------------------------
// 1. Constructor – substrate string aliases
// ---------------------------------------------------------------------------

describe('WalletClient – constructor substrate aliases', () => {
  it('stores "auto" as the substrate when given "auto"', () => {
    const client = new WalletClient('auto', 'my.app.com')
    expect(client.substrate).toBe('auto')
  })

  it('creates a WalletWireTransceiver for "Cicada"', () => {
    const client = new WalletClient('Cicada', 'my.app.com')
    expect(client.substrate).toBeInstanceOf(WalletWireTransceiver)
  })

  it('creates an HTTPWalletJSON instance for "json-api"', () => {
    const client = new WalletClient('json-api', 'my.app.com')
    expect(client.substrate).toBeInstanceOf(HTTPWalletJSON)
  })

  it('creates an HTTPWalletJSON instance for "secure-json-api"', () => {
    const client = new WalletClient('secure-json-api', 'my.app.com')
    expect(client.substrate).toBeInstanceOf(HTTPWalletJSON)
  })

  it('accepts a pre-built WalletInterface object as substrate', () => {
    const mockWallet: WalletInterface = {
      createAction: jest.fn(),
      signAction: jest.fn(),
      abortAction: jest.fn(),
      listActions: jest.fn(),
      internalizeAction: jest.fn(),
      listOutputs: jest.fn(),
      relinquishOutput: jest.fn(),
      getPublicKey: jest.fn(),
      revealCounterpartyKeyLinkage: jest.fn(),
      revealSpecificKeyLinkage: jest.fn(),
      encrypt: jest.fn(),
      decrypt: jest.fn(),
      createHmac: jest.fn(),
      verifyHmac: jest.fn(),
      createSignature: jest.fn(),
      verifySignature: jest.fn(),
      acquireCertificate: jest.fn(),
      listCertificates: jest.fn(),
      proveCertificate: jest.fn(),
      relinquishCertificate: jest.fn(),
      discoverByIdentityKey: jest.fn(),
      discoverByAttributes: jest.fn(),
      isAuthenticated: jest.fn(),
      waitForAuthentication: jest.fn(),
      getHeight: jest.fn(),
      getHeaderForHeight: jest.fn(),
      getNetwork: jest.fn(),
      getVersion: jest.fn(),
    }
    const client = new WalletClient(mockWallet)
    expect(client.substrate).toBe(mockWallet)
  })

  it('stores the originator on the instance', () => {
    const client = new WalletClient('auto', 'example.com')
    expect(client.originator).toBe('example.com')
  })

  it('originator is undefined when not provided', () => {
    const client = new WalletClient('auto')
    expect(client.originator).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// 2. connectToSubstrate – skips when substrate is already a WalletInterface
// ---------------------------------------------------------------------------

describe('WalletClient – connectToSubstrate', () => {
  it('does not attempt discovery when substrate is already an object', async () => {
    const mockWallet: Partial<WalletInterface> = {
      getVersion: jest.fn().mockResolvedValue({ version: '1.0.0.0.0.0.0' }),
    }
    const client = new WalletClient(mockWallet as WalletInterface)
    // connectToSubstrate should return immediately
    await expect(client.connectToSubstrate()).resolves.toBeUndefined()
    // getVersion was NOT called by connectToSubstrate
    expect(mockWallet.getVersion).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// 3. createAction – validation
// ---------------------------------------------------------------------------

describe('WalletClient – createAction validation', () => {
  let client: WalletClient

  beforeEach(() => {
    client = new WalletClient('auto', '0.WalletClient.additional.test')
  })

  it('throws WERR_INVALID_PARAMETER for description shorter than 5 bytes', async () => {
    await expectInvalidParam(
      () => client.createAction({ description: 'hi' }),
      'description'
    )
  })

  it('throws WERR_INVALID_PARAMETER for description longer than 2000 bytes', async () => {
    await expectInvalidParam(
      () => client.createAction({ description: 'x'.repeat(2001) }),
      'description'
    )
  })

  it('throws WERR_INVALID_PARAMETER when output has an empty lockingScript', async () => {
    await expectInvalidParam(
      () => client.createAction({
        description: 'hello world',
        outputs: [{ lockingScript: '', satoshis: 1000, outputDescription: 'my output' }],
      }),
      'lockingScript'
    )
  })

  it('throws WERR_INVALID_PARAMETER when output lockingScript is odd-length hex', async () => {
    await expectInvalidParam(
      () => client.createAction({
        description: 'hello world',
        outputs: [{ lockingScript: 'abc', satoshis: 1000, outputDescription: 'my output' }],
      }),
      'lockingScript'
    )
  })

  it('throws WERR_INVALID_PARAMETER when output has no outputDescription', async () => {
    await expectInvalidParam(
      () => client.createAction({
        description: 'hello world',
        outputs: [{ lockingScript: '1234', satoshis: 1000, outputDescription: '' }],
      }),
      'outputDescription'
    )
  })

  it('throws WERR_INVALID_PARAMETER when output description is shorter than 5 bytes', async () => {
    await expectInvalidParam(
      () => client.createAction({
        description: 'hello world',
        outputs: [{ lockingScript: '1234', satoshis: 1000, outputDescription: 'hi' }],
      }),
      'outputDescription'
    )
  })

  it('throws WERR_INVALID_PARAMETER when satoshis is negative', async () => {
    await expectInvalidParam(
      () => client.createAction({
        description: 'hello world',
        outputs: [{ lockingScript: '1234', satoshis: -1, outputDescription: 'my output' }],
      }),
      'satoshis'
    )
  })

  it('throws WERR_INVALID_PARAMETER when satoshis is a float', async () => {
    await expectInvalidParam(
      () => client.createAction({
        description: 'hello world',
        outputs: [{ lockingScript: '1234', satoshis: 1.5, outputDescription: 'my output' }],
      }),
      'satoshis'
    )
  })

  it('throws WERR_INVALID_PARAMETER when input has neither unlockingScript nor unlockingScriptLength', async () => {
    await expectInvalidParam(
      () => client.createAction({
        description: 'hello world',
        inputs: [{
          outpoint: 'a'.repeat(64) + '.0',
          inputDescription: 'my input',
        }],
      }),
      'unlockingScript, unlockingScriptLength'
    )
  })

  it('throws WERR_INVALID_PARAMETER when input unlockingScript is odd-length', async () => {
    await expectInvalidParam(
      () => client.createAction({
        description: 'hello world',
        inputs: [{
          outpoint: 'a'.repeat(64) + '.0',
          inputDescription: 'my input',
          unlockingScript: 'abc',
        }],
      }),
      'unlockingScript'
    )
  })

  it('throws WERR_INVALID_PARAMETER when input inputDescription is too short', async () => {
    await expectInvalidParam(
      () => client.createAction({
        description: 'hello world',
        inputs: [{
          outpoint: 'a'.repeat(64) + '.0',
          inputDescription: 'hi',
          unlockingScriptLength: 10,
        }],
      }),
      'inputDescription'
    )
  })

  it('throws WERR_INVALID_PARAMETER when label is an empty string', async () => {
    await expectInvalidParam(
      () => client.createAction({
        description: 'hello world',
        labels: [''],
      }),
      'label'
    )
  })
})

// ---------------------------------------------------------------------------
// 4. signAction – validation (mostly structural, no network needed)
// ---------------------------------------------------------------------------

describe('WalletClient – signAction validation', () => {
  let client: WalletClient

  beforeEach(() => {
    client = new WalletClient('auto', '0.WalletClient.additional.test')
  })

  it('does NOT throw for a minimal valid signAction call structure (gets past validation)', async () => {
    // signAction validation is very permissive – it just normalises options.
    // Any rejection here would be a network/substrate error, not validation.
    const promise = client.signAction({ spends: {}, reference: 'cmVm' })
    // We expect it to eventually fail due to no substrate, NOT due to validation.
    await expect(promise).rejects.not.toMatchObject({ name: 'WERR_INVALID_PARAMETER' })
  })
})

// ---------------------------------------------------------------------------
// 5. abortAction – validation
// ---------------------------------------------------------------------------

describe('WalletClient – abortAction validation', () => {
  let client: WalletClient

  beforeEach(() => {
    client = new WalletClient('auto', '0.WalletClient.additional.test')
  })

  it('throws WERR_INVALID_PARAMETER when reference is empty', async () => {
    await expectInvalidParam(
      () => client.abortAction({ reference: '' }),
      'reference'
    )
  })

  it('throws WERR_INVALID_PARAMETER when reference contains invalid base64 characters', async () => {
    await expectInvalidParam(
      () => client.abortAction({ reference: '!!!not-base64!!!' }),
      'reference'
    )
  })
})

// ---------------------------------------------------------------------------
// 6. listActions – validation
// ---------------------------------------------------------------------------

describe('WalletClient – listActions validation', () => {
  let client: WalletClient

  beforeEach(() => {
    client = new WalletClient('auto', '0.WalletClient.additional.test')
  })

  it('throws WERR_INVALID_PARAMETER for invalid labelQueryMode', async () => {
    await expectInvalidParam(
      () => client.listActions({ labels: [], labelQueryMode: 'invalid' as any }),
      'labelQueryMode'
    )
  })

  it('throws WERR_INVALID_PARAMETER when limit exceeds 10000', async () => {
    await expectInvalidParam(
      () => client.listActions({ labels: [], limit: 10001 }),
      'limit'
    )
  })

  it('throws WERR_INVALID_PARAMETER when limit is zero', async () => {
    await expectInvalidParam(
      () => client.listActions({ labels: [], limit: 0 }),
      'limit'
    )
  })

  it('throws WERR_INVALID_PARAMETER when limit is a float', async () => {
    await expectInvalidParam(
      () => client.listActions({ labels: [], limit: 1.5 }),
      'limit'
    )
  })

  it('throws WERR_INVALID_PARAMETER when offset is negative', async () => {
    await expectInvalidParam(
      () => client.listActions({ labels: [], offset: -1 }),
      'offset'
    )
  })

  it('throws WERR_INVALID_PARAMETER when a label is empty', async () => {
    await expectInvalidParam(
      () => client.listActions({ labels: [''] }),
      'label'
    )
  })

  it('throws WERR_INVALID_PARAMETER when a label is too long (>300 bytes)', async () => {
    await expectInvalidParam(
      () => client.listActions({ labels: ['x'.repeat(301)] }),
      'label'
    )
  })
})

// ---------------------------------------------------------------------------
// 7. listOutputs – validation
// ---------------------------------------------------------------------------

describe('WalletClient – listOutputs validation', () => {
  let client: WalletClient

  beforeEach(() => {
    client = new WalletClient('auto', '0.WalletClient.additional.test')
  })

  it('throws WERR_INVALID_PARAMETER when basket is empty', async () => {
    await expectInvalidParam(
      () => client.listOutputs({ basket: '' }),
      'basket'
    )
  })

  it('throws WERR_INVALID_PARAMETER for invalid tagQueryMode', async () => {
    await expectInvalidParam(
      () => client.listOutputs({ basket: 'default', tagQueryMode: 'none' as any }),
      'tagQueryMode'
    )
  })

  it('throws WERR_INVALID_PARAMETER when limit exceeds 10000', async () => {
    await expectInvalidParam(
      () => client.listOutputs({ basket: 'default', limit: 10001 }),
      'limit'
    )
  })
})

// ---------------------------------------------------------------------------
// 8. relinquishOutput – validation
// ---------------------------------------------------------------------------

describe('WalletClient – relinquishOutput validation', () => {
  let client: WalletClient

  beforeEach(() => {
    client = new WalletClient('auto', '0.WalletClient.additional.test')
  })

  it('throws WERR_INVALID_PARAMETER when basket is empty', async () => {
    await expectInvalidParam(
      () => client.relinquishOutput({ basket: '', output: 'a'.repeat(64) + '.0' }),
      'basket'
    )
  })

  it('throws WERR_INVALID_PARAMETER when output is not a valid outpoint', async () => {
    await expectInvalidParam(
      () => client.relinquishOutput({ basket: 'default', output: 'not-an-outpoint' }),
      'output'
    )
  })
})

// ---------------------------------------------------------------------------
// 9. acquireCertificate – validation
// ---------------------------------------------------------------------------

describe('WalletClient – acquireCertificate validation', () => {
  let client: WalletClient

  beforeEach(() => {
    client = new WalletClient('auto', '0.WalletClient.additional.test')
  })

  it('throws WERR_INVALID_PARAMETER for unrecognised acquisitionProtocol', async () => {
    await expectInvalidParam(
      () => client.acquireCertificate({
        acquisitionProtocol: 'unknown' as any,
        type: 'dHlwZQ==',
        certifier: 'aa',
        fields: {},
      }),
      'acquisitionProtocol'
    )
  })

  it('throws WERR_INVALID_PARAMETER for direct acquisition missing serialNumber', async () => {
    await expectInvalidParam(
      () => client.acquireCertificate({
        acquisitionProtocol: 'direct',
        type: 'dHlwZQ==',
        certifier: 'aabb',
        fields: {},
        // missing serialNumber, signature, revocationOutpoint, keyringRevealer, keyringForSubject
      } as any),
      'serialNumber'
    )
  })

  it('throws WERR_INVALID_PARAMETER for issuance acquisition missing certifierUrl', async () => {
    await expectInvalidParam(
      () => client.acquireCertificate({
        acquisitionProtocol: 'issuance',
        type: 'dHlwZQ==',
        certifier: 'aabb',
        fields: {},
        // certifierUrl deliberately omitted
      } as any),
      'certifierUrl'
    )
  })

  it('throws WERR_INVALID_PARAMETER for issuance with serialNumber (not allowed)', async () => {
    await expectInvalidParam(
      () => client.acquireCertificate({
        acquisitionProtocol: 'issuance',
        type: 'dHlwZQ==',
        certifier: 'aabb',
        certifierUrl: 'https://certifier.example.com',
        fields: {},
        serialNumber: 'c2VyaWFs',
      }),
      'serialNumber'
    )
  })
})

// ---------------------------------------------------------------------------
// 10. listCertificates – validation
// ---------------------------------------------------------------------------

describe('WalletClient – listCertificates validation', () => {
  let client: WalletClient

  beforeEach(() => {
    client = new WalletClient('auto', '0.WalletClient.additional.test')
  })

  it('throws WERR_INVALID_PARAMETER when limit exceeds 10000', async () => {
    await expectInvalidParam(
      () => client.listCertificates({ certifiers: [], types: [], limit: 99999 }),
      'limit'
    )
  })

  it('throws WERR_INVALID_PARAMETER when limit is zero', async () => {
    await expectInvalidParam(
      () => client.listCertificates({ certifiers: [], types: [], limit: 0 }),
      'limit'
    )
  })

  it('throws WERR_INVALID_PARAMETER when offset is negative', async () => {
    await expectInvalidParam(
      () => client.listCertificates({ certifiers: [], types: [], offset: -1 }),
      'offset'
    )
  })
})

// ---------------------------------------------------------------------------
// 11. relinquishCertificate – validation
// ---------------------------------------------------------------------------

describe('WalletClient – relinquishCertificate validation', () => {
  let client: WalletClient

  beforeEach(() => {
    client = new WalletClient('auto', '0.WalletClient.additional.test')
  })

  it('throws WERR_INVALID_PARAMETER when type is empty', async () => {
    await expectInvalidParam(
      () => client.relinquishCertificate({ type: '', serialNumber: 'c2Vy', certifier: 'aabb' }),
      'type'
    )
  })

  it('throws WERR_INVALID_PARAMETER when type is not valid base64', async () => {
    await expectInvalidParam(
      () => client.relinquishCertificate({ type: '!!!', serialNumber: 'c2Vy', certifier: 'aabb' }),
      'type'
    )
  })

  it('throws WERR_INVALID_PARAMETER when serialNumber is empty', async () => {
    await expectInvalidParam(
      () => client.relinquishCertificate({ type: 'dHlwZQ==', serialNumber: '', certifier: 'aabb' }),
      'serialNumber'
    )
  })

  it('throws WERR_INVALID_PARAMETER when certifier is odd-length hex', async () => {
    await expectInvalidParam(
      () => client.relinquishCertificate({ type: 'dHlwZQ==', serialNumber: 'c2Vy', certifier: 'aab' }),
      'certifier'
    )
  })
})

// ---------------------------------------------------------------------------
// 12. discoverByIdentityKey – validation
// ---------------------------------------------------------------------------

describe('WalletClient – discoverByIdentityKey validation', () => {
  let client: WalletClient

  beforeEach(() => {
    client = new WalletClient('auto', '0.WalletClient.additional.test')
  })

  it('throws WERR_INVALID_PARAMETER when identityKey is not 66 hex chars', async () => {
    await expectInvalidParam(
      () => client.discoverByIdentityKey({ identityKey: 'aabb' }),
      'identityKey'
    )
  })

  it('throws WERR_INVALID_PARAMETER when identityKey is empty', async () => {
    await expectInvalidParam(
      () => client.discoverByIdentityKey({ identityKey: '' }),
      'identityKey'
    )
  })

  it('throws WERR_INVALID_PARAMETER when limit exceeds 10000', async () => {
    await expectInvalidParam(
      () => client.discoverByIdentityKey({ identityKey: 'aa'.repeat(33), limit: 10001 }),
      'limit'
    )
  })
})

// ---------------------------------------------------------------------------
// 13. discoverByAttributes – validation
// ---------------------------------------------------------------------------

describe('WalletClient – discoverByAttributes validation', () => {
  let client: WalletClient

  beforeEach(() => {
    client = new WalletClient('auto', '0.WalletClient.additional.test')
  })

  it('throws WERR_INVALID_PARAMETER when limit is zero', async () => {
    await expectInvalidParam(
      () => client.discoverByAttributes({ attributes: {}, limit: 0 }),
      'limit'
    )
  })

  it('throws WERR_INVALID_PARAMETER when limit exceeds 10000', async () => {
    await expectInvalidParam(
      () => client.discoverByAttributes({ attributes: {}, limit: 20000 }),
      'limit'
    )
  })
})

// ---------------------------------------------------------------------------
// 14. proveCertificate – validation
// ---------------------------------------------------------------------------

describe('WalletClient – proveCertificate validation', () => {
  let client: WalletClient

  beforeEach(() => {
    client = new WalletClient('auto', '0.WalletClient.additional.test')
  })

  it('throws WERR_INVALID_PARAMETER when privileged is true but privilegedReason is missing', async () => {
    await expectInvalidParam(
      () => client.proveCertificate({
        certificate: {} as any,
        fieldsToReveal: [],
        verifier: 'aa'.repeat(33),
        privileged: true,
        // privilegedReason intentionally omitted
      }),
      'privilegedReason'
    )
  })

  it('throws WERR_INVALID_PARAMETER when verifier is not valid hex', async () => {
    await expectInvalidParam(
      () => client.proveCertificate({
        certificate: {} as any,
        fieldsToReveal: [],
        verifier: 'not-hex!',
      }),
      'verifier'
    )
  })
})

// ---------------------------------------------------------------------------
// 15. WERR_INVALID_PARAMETER error class contract
// ---------------------------------------------------------------------------

describe('WERR_INVALID_PARAMETER – class contract', () => {
  it('sets name to WERR_INVALID_PARAMETER', () => {
    const err = new WERR_INVALID_PARAMETER('foo')
    expect(err.name).toBe('WERR_INVALID_PARAMETER')
  })

  it('sets code to 6', () => {
    const err = new WERR_INVALID_PARAMETER('foo')
    expect(err.code).toBe(6)
  })

  it('sets isError to true', () => {
    const err = new WERR_INVALID_PARAMETER('foo')
    expect(err.isError).toBe(true)
  })

  it('stores the parameter name', () => {
    const err = new WERR_INVALID_PARAMETER('myParam')
    expect(err.parameter).toBe('myParam')
  })

  it('uses "valid." as the default mustBe message', () => {
    const err = new WERR_INVALID_PARAMETER('myParam')
    expect(err.message).toContain('myParam')
    expect(err.message).toContain('valid.')
  })

  it('includes the mustBe string in message when provided', () => {
    const err = new WERR_INVALID_PARAMETER('myParam', 'a positive integer')
    expect(err.message).toContain('a positive integer')
  })

  it('is an instance of Error', () => {
    const err = new WERR_INVALID_PARAMETER('x')
    expect(err).toBeInstanceOf(Error)
  })
})
