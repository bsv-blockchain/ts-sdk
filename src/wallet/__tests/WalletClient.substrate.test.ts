/**
 * WalletClient substrate delegation tests.
 *
 * These tests exercise every public method that ultimately delegates to the
 * substrate object (lines 215-370 and 446-499 of WalletClient.ts).  Each test
 * bypasses the real `connectToSubstrate()` logic by pre-injecting a mock
 * substrate directly onto the instance, which avoids any real network I/O.
 */

import WalletClient from '../WalletClient'
import type { WalletInterface } from '../Wallet.interfaces'

// ---------------------------------------------------------------------------
// Helper: create a fully-mocked substrate and an already-connected WalletClient
// ---------------------------------------------------------------------------

function buildMockSubstrate (): jest.Mocked<WalletInterface> {
  return {
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
  } as jest.Mocked<WalletInterface>
}

/** Creates a WalletClient whose substrate is already the given mock object. */
function clientWith (mock: jest.Mocked<WalletInterface>, originator = 'test.origin'): WalletClient {
  const client = new WalletClient(mock, originator)
  return client
}

// ---------------------------------------------------------------------------
// relinquishOutput
// ---------------------------------------------------------------------------

describe('WalletClient.relinquishOutput – substrate delegation', () => {
  it('delegates to substrate.relinquishOutput and returns its result', async () => {
    const mock = buildMockSubstrate()
    mock.relinquishOutput.mockResolvedValue({ relinquished: true })
    const client = clientWith(mock)

    const result = await client.relinquishOutput({
      basket: 'default',
      output: 'a'.repeat(64) + '.0',
    })

    expect(result).toEqual({ relinquished: true })
    expect(mock.relinquishOutput).toHaveBeenCalledTimes(1)
    expect(mock.relinquishOutput).toHaveBeenCalledWith(
      { basket: 'default', output: 'a'.repeat(64) + '.0' },
      'test.origin'
    )
  })

  it('propagates errors thrown by the substrate', async () => {
    const mock = buildMockSubstrate()
    mock.relinquishOutput.mockRejectedValue(new Error('substrate error'))
    const client = clientWith(mock)

    await expect(
      client.relinquishOutput({ basket: 'default', output: 'a'.repeat(64) + '.0' })
    ).rejects.toThrow('substrate error')
  })
})

// ---------------------------------------------------------------------------
// getPublicKey
// ---------------------------------------------------------------------------

describe('WalletClient.getPublicKey – substrate delegation', () => {
  it('returns the public key from the substrate', async () => {
    const mock = buildMockSubstrate()
    const expectedKey = 'aa'.repeat(33)
    mock.getPublicKey.mockResolvedValue({ publicKey: expectedKey })
    const client = clientWith(mock)

    const result = await client.getPublicKey({ identityKey: true })

    expect(result).toEqual({ publicKey: expectedKey })
    expect(mock.getPublicKey).toHaveBeenCalledWith({ identityKey: true }, 'test.origin')
  })

  it('passes protocolID and keyID through to the substrate', async () => {
    const mock = buildMockSubstrate()
    mock.getPublicKey.mockResolvedValue({ publicKey: 'bb'.repeat(33) })
    const client = clientWith(mock)

    await client.getPublicKey({
      protocolID: [2, 'my-protocol'],
      keyID: '1',
      counterparty: 'self',
    })

    expect(mock.getPublicKey).toHaveBeenCalledWith(
      { protocolID: [2, 'my-protocol'], keyID: '1', counterparty: 'self' },
      'test.origin'
    )
  })
})

// ---------------------------------------------------------------------------
// revealCounterpartyKeyLinkage
// ---------------------------------------------------------------------------

describe('WalletClient.revealCounterpartyKeyLinkage – substrate delegation', () => {
  it('delegates and returns the linkage result', async () => {
    const mock = buildMockSubstrate()
    const fakeResult = {
      prover: 'aa'.repeat(33),
      verifier: 'bb'.repeat(33),
      counterparty: 'cc'.repeat(33),
      revelationTime: '2024-01-01T00:00:00.000Z',
      encryptedLinkage: [1, 2, 3],
      encryptedLinkageProof: [4, 5, 6],
    }
    mock.revealCounterpartyKeyLinkage.mockResolvedValue(fakeResult)
    const client = clientWith(mock)

    const args = {
      counterparty: 'cc'.repeat(33),
      verifier: 'bb'.repeat(33),
    }
    const result = await client.revealCounterpartyKeyLinkage(args)

    expect(result).toEqual(fakeResult)
    expect(mock.revealCounterpartyKeyLinkage).toHaveBeenCalledWith(args, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// revealSpecificKeyLinkage
// ---------------------------------------------------------------------------

describe('WalletClient.revealSpecificKeyLinkage – substrate delegation', () => {
  it('delegates and returns the specific linkage result', async () => {
    const mock = buildMockSubstrate()
    const fakeResult = {
      prover: 'aa'.repeat(33),
      verifier: 'bb'.repeat(33),
      counterparty: 'cc'.repeat(33),
      protocolID: [1, 'proto'] as [0 | 1 | 2, string],
      keyID: '1',
      encryptedLinkage: [1],
      encryptedLinkageProof: [2],
      proofType: 1,
    }
    mock.revealSpecificKeyLinkage.mockResolvedValue(fakeResult)
    const client = clientWith(mock)

    const args = {
      counterparty: 'cc'.repeat(33),
      verifier: 'bb'.repeat(33),
      protocolID: [1, 'proto'] as [0 | 1 | 2, string],
      keyID: '1',
    }
    const result = await client.revealSpecificKeyLinkage(args)

    expect(result).toEqual(fakeResult)
    expect(mock.revealSpecificKeyLinkage).toHaveBeenCalledWith(args, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// encrypt / decrypt
// ---------------------------------------------------------------------------

describe('WalletClient.encrypt – substrate delegation', () => {
  it('returns ciphertext from the substrate', async () => {
    const mock = buildMockSubstrate()
    mock.encrypt.mockResolvedValue({ ciphertext: [9, 8, 7] })
    const client = clientWith(mock)

    const args = {
      plaintext: [1, 2, 3],
      protocolID: [1, 'enc-proto'] as [0 | 1 | 2, string],
      keyID: '1',
    }
    const result = await client.encrypt(args)

    expect(result).toEqual({ ciphertext: [9, 8, 7] })
    expect(mock.encrypt).toHaveBeenCalledWith(args, 'test.origin')
  })
})

describe('WalletClient.decrypt – substrate delegation', () => {
  it('returns plaintext from the substrate', async () => {
    const mock = buildMockSubstrate()
    mock.decrypt.mockResolvedValue({ plaintext: [42] })
    const client = clientWith(mock)

    const args = {
      ciphertext: [9, 8, 7],
      protocolID: [1, 'enc-proto'] as [0 | 1 | 2, string],
      keyID: '1',
    }
    const result = await client.decrypt(args)

    expect(result).toEqual({ plaintext: [42] })
    expect(mock.decrypt).toHaveBeenCalledWith(args, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// createHmac / verifyHmac
// ---------------------------------------------------------------------------

describe('WalletClient.createHmac – substrate delegation', () => {
  it('returns hmac bytes from the substrate', async () => {
    const mock = buildMockSubstrate()
    mock.createHmac.mockResolvedValue({ hmac: [0, 1, 2, 3] })
    const client = clientWith(mock)

    const args = {
      data: [10, 20],
      protocolID: [2, 'hmac-proto'] as [0 | 1 | 2, string],
      keyID: '1',
    }
    const result = await client.createHmac(args)

    expect(result).toEqual({ hmac: [0, 1, 2, 3] })
    expect(mock.createHmac).toHaveBeenCalledWith(args, 'test.origin')
  })
})

describe('WalletClient.verifyHmac – substrate delegation', () => {
  it('returns { valid: true } from the substrate', async () => {
    const mock = buildMockSubstrate()
    mock.verifyHmac.mockResolvedValue({ valid: true })
    const client = clientWith(mock)

    const args = {
      data: [10, 20],
      hmac: [0, 1, 2, 3],
      protocolID: [2, 'hmac-proto'] as [0 | 1 | 2, string],
      keyID: '1',
    }
    const result = await client.verifyHmac(args)

    expect(result).toEqual({ valid: true })
    expect(mock.verifyHmac).toHaveBeenCalledWith(args, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// createSignature / verifySignature
// ---------------------------------------------------------------------------

describe('WalletClient.createSignature – substrate delegation', () => {
  it('returns signature bytes from the substrate', async () => {
    const mock = buildMockSubstrate()
    mock.createSignature.mockResolvedValue({ signature: [5, 6, 7] })
    const client = clientWith(mock)

    const args = {
      data: [1, 2],
      protocolID: [1, 'sig-proto'] as [0 | 1 | 2, string],
      keyID: '1',
    }
    const result = await client.createSignature(args)

    expect(result).toEqual({ signature: [5, 6, 7] })
    expect(mock.createSignature).toHaveBeenCalledWith(args, 'test.origin')
  })
})

describe('WalletClient.verifySignature – substrate delegation', () => {
  it('returns { valid: true } from the substrate', async () => {
    const mock = buildMockSubstrate()
    mock.verifySignature.mockResolvedValue({ valid: true })
    const client = clientWith(mock)

    const args = {
      data: [1, 2],
      signature: [5, 6, 7],
      protocolID: [1, 'sig-proto'] as [0 | 1 | 2, string],
      keyID: '1',
    }
    const result = await client.verifySignature(args)

    expect(result).toEqual({ valid: true })
    expect(mock.verifySignature).toHaveBeenCalledWith(args, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// acquireCertificate
// ---------------------------------------------------------------------------

describe('WalletClient.acquireCertificate – substrate delegation', () => {
  const baseCert = {
    type: 'dHlwZQ==',
    certifier: 'aa'.repeat(33),
    fields: { name: 'alice' },
    acquisitionProtocol: 'direct' as const,
    serialNumber: 'c2VyaWFs',
    revocationOutpoint: 'a'.repeat(64) + '.0',
    signature: 'aabb',
    keyringRevealer: 'certifier' as const,
    keyringForSubject: {},
  }

  it('delegates direct acquisition to substrate and returns result', async () => {
    const mock = buildMockSubstrate()
    mock.acquireCertificate.mockResolvedValue({ ...baseCert } as any)
    const client = clientWith(mock)

    const result = await client.acquireCertificate(baseCert)

    expect(result).toMatchObject({ type: 'dHlwZQ==' })
    expect(mock.acquireCertificate).toHaveBeenCalledWith(baseCert, 'test.origin')
  })

  it('delegates issuance acquisition to substrate', async () => {
    const mock = buildMockSubstrate()
    const issuanceCert = {
      type: 'dHlwZQ==',
      certifier: 'aa'.repeat(33),
      fields: {},
      acquisitionProtocol: 'issuance' as const,
      certifierUrl: 'https://certifier.example.com',
    }
    mock.acquireCertificate.mockResolvedValue(issuanceCert as any)
    const client = clientWith(mock)

    const result = await client.acquireCertificate(issuanceCert)

    expect(mock.acquireCertificate).toHaveBeenCalledWith(issuanceCert, 'test.origin')
    expect(result).toMatchObject({ acquisitionProtocol: 'issuance' })
  })
})

// ---------------------------------------------------------------------------
// listCertificates
// ---------------------------------------------------------------------------

describe('WalletClient.listCertificates – substrate delegation', () => {
  it('delegates to substrate and returns the certificate list', async () => {
    const mock = buildMockSubstrate()
    const fakeList = { certificates: [], totalCertificates: 0 }
    mock.listCertificates.mockResolvedValue(fakeList)
    const client = clientWith(mock)

    const args = { certifiers: ['aa'.repeat(33)], types: ['dHlwZQ=='] }
    const result = await client.listCertificates(args)

    expect(result).toEqual(fakeList)
    expect(mock.listCertificates).toHaveBeenCalledWith(args, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// proveCertificate
// ---------------------------------------------------------------------------

describe('WalletClient.proveCertificate – substrate delegation', () => {
  it('delegates to substrate and returns prove result', async () => {
    const mock = buildMockSubstrate()
    const fakeResult = { keyringForVerifier: {} }
    mock.proveCertificate.mockResolvedValue(fakeResult as any)
    const client = clientWith(mock)

    const args = {
      certificate: {
        type: 'dHlwZQ==',
        certifier: 'aa'.repeat(33),
        serialNumber: 'c2VyaWFs',
        fields: {},
        subject: 'bb'.repeat(33),
        revocationOutpoint: 'a'.repeat(64) + '.0',
        signature: 'aabb',
      } as any,
      fieldsToReveal: ['name'],
      verifier: 'cc'.repeat(33),
    }
    const result = await client.proveCertificate(args)

    expect(result).toEqual(fakeResult)
    expect(mock.proveCertificate).toHaveBeenCalledWith(args, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// relinquishCertificate
// ---------------------------------------------------------------------------

describe('WalletClient.relinquishCertificate – substrate delegation', () => {
  it('delegates to substrate and returns relinquished result', async () => {
    const mock = buildMockSubstrate()
    mock.relinquishCertificate.mockResolvedValue({ relinquished: true })
    const client = clientWith(mock)

    const args = {
      type: 'dHlwZQ==',
      serialNumber: 'c2VyaWFs',
      certifier: 'aa'.repeat(33),
    }
    const result = await client.relinquishCertificate(args)

    expect(result).toEqual({ relinquished: true })
    expect(mock.relinquishCertificate).toHaveBeenCalledWith(args, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// discoverByIdentityKey
// ---------------------------------------------------------------------------

describe('WalletClient.discoverByIdentityKey – substrate delegation', () => {
  it('delegates to substrate and returns discovered certificates', async () => {
    const mock = buildMockSubstrate()
    const fakeResult = { certificates: [], totalCertificates: 0 }
    mock.discoverByIdentityKey.mockResolvedValue(fakeResult)
    const client = clientWith(mock)

    const args = { identityKey: 'aa'.repeat(33) }
    const result = await client.discoverByIdentityKey(args)

    expect(result).toEqual(fakeResult)
    expect(mock.discoverByIdentityKey).toHaveBeenCalledWith(args, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// discoverByAttributes
// ---------------------------------------------------------------------------

describe('WalletClient.discoverByAttributes – substrate delegation', () => {
  it('delegates to substrate and returns discovered certificates', async () => {
    const mock = buildMockSubstrate()
    const fakeResult = { certificates: [], totalCertificates: 0 }
    mock.discoverByAttributes.mockResolvedValue(fakeResult)
    const client = clientWith(mock)

    const args = { attributes: { name: 'alice' } }
    const result = await client.discoverByAttributes(args)

    expect(result).toEqual(fakeResult)
    expect(mock.discoverByAttributes).toHaveBeenCalledWith(args, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// isAuthenticated
// ---------------------------------------------------------------------------

describe('WalletClient.isAuthenticated – substrate delegation', () => {
  it('delegates to substrate and returns authenticated status', async () => {
    const mock = buildMockSubstrate()
    mock.isAuthenticated.mockResolvedValue({ authenticated: true })
    const client = clientWith(mock)

    const result = await client.isAuthenticated({})

    expect(result).toEqual({ authenticated: true })
    expect(mock.isAuthenticated).toHaveBeenCalledWith({}, 'test.origin')
  })

  it('uses default empty object when no args provided', async () => {
    const mock = buildMockSubstrate()
    mock.isAuthenticated.mockResolvedValue({ authenticated: false } as any)
    const client = clientWith(mock)

    const result = await client.isAuthenticated()

    expect(result).toEqual({ authenticated: false })
    expect(mock.isAuthenticated).toHaveBeenCalledWith({}, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// waitForAuthentication
// ---------------------------------------------------------------------------

describe('WalletClient.waitForAuthentication – substrate delegation', () => {
  it('delegates to substrate and resolves when authenticated', async () => {
    const mock = buildMockSubstrate()
    mock.waitForAuthentication.mockResolvedValue({ authenticated: true })
    const client = clientWith(mock)

    const result = await client.waitForAuthentication({})

    expect(result).toEqual({ authenticated: true })
    expect(mock.waitForAuthentication).toHaveBeenCalledWith({}, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// getHeight
// ---------------------------------------------------------------------------

describe('WalletClient.getHeight – substrate delegation', () => {
  it('returns current block height from substrate', async () => {
    const mock = buildMockSubstrate()
    mock.getHeight.mockResolvedValue({ height: 800000 })
    const client = clientWith(mock)

    const result = await client.getHeight({})

    expect(result).toEqual({ height: 800000 })
    expect(mock.getHeight).toHaveBeenCalledWith({}, 'test.origin')
  })

  it('uses default empty object when no args provided', async () => {
    const mock = buildMockSubstrate()
    mock.getHeight.mockResolvedValue({ height: 1 })
    const client = clientWith(mock)

    await client.getHeight()

    expect(mock.getHeight).toHaveBeenCalledWith({}, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// getHeaderForHeight
// ---------------------------------------------------------------------------

describe('WalletClient.getHeaderForHeight – substrate delegation', () => {
  it('returns block header hex from substrate', async () => {
    const mock = buildMockSubstrate()
    mock.getHeaderForHeight.mockResolvedValue({ header: 'deadbeef' })
    const client = clientWith(mock)

    const result = await client.getHeaderForHeight({ height: 800000 })

    expect(result).toEqual({ header: 'deadbeef' })
    expect(mock.getHeaderForHeight).toHaveBeenCalledWith({ height: 800000 }, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// getNetwork
// ---------------------------------------------------------------------------

describe('WalletClient.getNetwork – substrate delegation', () => {
  it('returns mainnet from substrate', async () => {
    const mock = buildMockSubstrate()
    mock.getNetwork.mockResolvedValue({ network: 'mainnet' })
    const client = clientWith(mock)

    const result = await client.getNetwork({})

    expect(result).toEqual({ network: 'mainnet' })
    expect(mock.getNetwork).toHaveBeenCalledWith({}, 'test.origin')
  })

  it('returns testnet from substrate', async () => {
    const mock = buildMockSubstrate()
    mock.getNetwork.mockResolvedValue({ network: 'testnet' })
    const client = clientWith(mock)

    const result = await client.getNetwork()

    expect(result).toEqual({ network: 'testnet' })
    expect(mock.getNetwork).toHaveBeenCalledWith({}, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// getVersion
// ---------------------------------------------------------------------------

describe('WalletClient.getVersion – substrate delegation', () => {
  it('returns version string from substrate', async () => {
    const mock = buildMockSubstrate()
    mock.getVersion.mockResolvedValue({ version: '1.0.0.0.0.0.0' })
    const client = clientWith(mock)

    const result = await client.getVersion({})

    expect(result).toEqual({ version: '1.0.0.0.0.0.0' })
    expect(mock.getVersion).toHaveBeenCalledWith({}, 'test.origin')
  })

  it('uses default empty object when no args provided', async () => {
    const mock = buildMockSubstrate()
    mock.getVersion.mockResolvedValue({ version: '2.0.0.0.0.0.0' })
    const client = clientWith(mock)

    await client.getVersion()

    expect(mock.getVersion).toHaveBeenCalledWith({}, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// createAction – successful delegation
// ---------------------------------------------------------------------------

describe('WalletClient.createAction – substrate delegation', () => {
  it('delegates a valid createAction call to the substrate', async () => {
    const mock = buildMockSubstrate()
    const fakeResult = { txid: 'abc123', tx: [1, 2, 3] }
    mock.createAction.mockResolvedValue(fakeResult as any)
    const client = clientWith(mock)

    const args = { description: 'hello world' }
    const result = await client.createAction(args)

    expect(result).toEqual(fakeResult)
    expect(mock.createAction).toHaveBeenCalledWith(args, 'test.origin')
  })

  it('passes originator undefined when no originator was set', async () => {
    const mock = buildMockSubstrate()
    mock.createAction.mockResolvedValue({ txid: 'xyz' } as any)
    // Create the client by passing the mock object directly (no originator)
    const client = new WalletClient(mock)

    await client.createAction({ description: 'hello world' })

    expect(mock.createAction).toHaveBeenCalledWith({ description: 'hello world' }, undefined)
  })
})

// ---------------------------------------------------------------------------
// signAction – successful delegation
// ---------------------------------------------------------------------------

describe('WalletClient.signAction – substrate delegation', () => {
  it('delegates a valid signAction call to the substrate', async () => {
    const mock = buildMockSubstrate()
    const fakeResult = { txid: 'signed123', tx: [1, 2, 3] }
    mock.signAction.mockResolvedValue(fakeResult as any)
    const client = clientWith(mock)

    const args = { spends: {}, reference: 'cmVm' }
    const result = await client.signAction(args)

    expect(result).toEqual(fakeResult)
    expect(mock.signAction).toHaveBeenCalledWith(args, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// abortAction – successful delegation
// ---------------------------------------------------------------------------

describe('WalletClient.abortAction – substrate delegation', () => {
  it('delegates a valid abortAction call to the substrate', async () => {
    const mock = buildMockSubstrate()
    mock.abortAction.mockResolvedValue({ aborted: true })
    const client = clientWith(mock)

    const result = await client.abortAction({ reference: 'cmVm' })

    expect(result).toEqual({ aborted: true })
    expect(mock.abortAction).toHaveBeenCalledWith({ reference: 'cmVm' }, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// listActions – successful delegation
// ---------------------------------------------------------------------------

describe('WalletClient.listActions – substrate delegation', () => {
  it('delegates to substrate and returns action list', async () => {
    const mock = buildMockSubstrate()
    const fakeResult = { actions: [], totalActions: 0 }
    mock.listActions.mockResolvedValue(fakeResult)
    const client = clientWith(mock)

    const args = { labels: ['my-label'] }
    const result = await client.listActions(args)

    expect(result).toEqual(fakeResult)
    expect(mock.listActions).toHaveBeenCalledWith(args, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// internalizeAction – successful delegation
// ---------------------------------------------------------------------------

describe('WalletClient.internalizeAction – substrate delegation', () => {
  it('delegates to substrate and returns accepted result', async () => {
    const mock = buildMockSubstrate()
    mock.internalizeAction.mockResolvedValue({ accepted: true })
    const client = clientWith(mock)

    // Minimal valid AtomicBEEF: BEEF_V2 header + 0 bumps + 1 txid-only tx
    // BEEF_V2 = 4022206466 (0xEFBE0002) in little-endian = [2, 0, 190, 239]
    // TX_DATA_FORMAT.TXID_ONLY = 2, followed by 32-byte txid
    const minimalBeef: number[] = [
      2, 0, 190, 239,          // BEEF_V2 version LE
      0,                        // 0 bumps (varint)
      1,                        // 1 tx (varint)
      2,                        // TX_DATA_FORMAT.TXID_ONLY
      ...new Array(32).fill(0)  // 32-byte zero txid
    ]
    const args = {
      tx: minimalBeef,
      outputs: [{ outputIndex: 0, protocol: 'wallet payment' as const }],
      description: 'Internalize tx',
    }
    const result = await client.internalizeAction(args)

    expect(result).toEqual({ accepted: true })
    expect(mock.internalizeAction).toHaveBeenCalledWith(args, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// listOutputs – successful delegation
// ---------------------------------------------------------------------------

describe('WalletClient.listOutputs – substrate delegation', () => {
  it('delegates to substrate and returns output list', async () => {
    const mock = buildMockSubstrate()
    const fakeResult = { outputs: [], totalOutputs: 0 }
    mock.listOutputs.mockResolvedValue(fakeResult as any)
    const client = clientWith(mock)

    const args = { basket: 'default' }
    const result = await client.listOutputs(args)

    expect(result).toEqual(fakeResult)
    expect(mock.listOutputs).toHaveBeenCalledWith(args, 'test.origin')
  })
})

// ---------------------------------------------------------------------------
// connectToSubstrate – auto-selection error path
// ---------------------------------------------------------------------------

describe('WalletClient.connectToSubstrate – error when no substrate available', () => {
  it('throws a descriptive error when auto-substrate fails to connect', async () => {
    // The 'auto' substrate string means connectToSubstrate will try real substrates.
    // All of them will fail in a test environment, so an error should be thrown.
    const client = new WalletClient('auto', 'test.origin')
    await expect(client.connectToSubstrate()).rejects.toThrow(
      'No wallet available over any communication substrate'
    )
  }, 10000)
})
