import { PrivateKey, Utils } from '../../../primitives/index'
import { WalletInterface } from '../../../wallet/Wallet.interfaces'
import { createNonce } from '../../../auth/utils/createNonce'
import { verifyNonce } from '../../../auth/utils/verifyNonce'
import { CompletedProtoWallet } from '../../../auth/certificates/__tests/CompletedProtoWallet'

describe('createNonce', () => {
  let mockWallet: WalletInterface

  beforeEach(() => {
    mockWallet = {
      createHmac: jest.fn().mockResolvedValue({ hmac: new Uint8Array(16) })
    } as unknown as WalletInterface
  })

  afterEach(() => {
    jest.clearAllMocks()
  })

  it('throws an error if wallet fails to create HMAC', async () => {
    // Mock failure of HMAC creation
    (mockWallet.createHmac as jest.Mock).mockRejectedValue(
      new Error('Failed to create HMAC')
    )

    await expect(createNonce(mockWallet)).rejects.toThrow(
      'Failed to create HMAC'
    )
  })

  it('creates a 256-bit nonce', async () => {
    const nonce = await createNonce(mockWallet)
    expect(Buffer.from(nonce, 'base64').byteLength).toEqual(32)
  })
})

describe('verifyNonce', () => {
  let mockWallet: WalletInterface

  beforeEach(() => {
    mockWallet = {
      createHmac: jest.fn().mockResolvedValue({ hmac: new Uint8Array(16) }),
      verifyHmac: jest.fn().mockResolvedValue({ valid: true })
    } as unknown as WalletInterface
  })

  afterEach(() => {
    jest.clearAllMocks()
  })

  it('does not verify an invalid nonce', async () => {
    (mockWallet.verifyHmac as jest.Mock).mockResolvedValue({ valid: false })

    const nonce = await createNonce(mockWallet)
    await expect(verifyNonce(nonce + 'ABC', mockWallet)).rejects.toThrow(
    /Invalid base64 padding|Invalid base64/i
  )
    await expect(verifyNonce(nonce + '=', mockWallet)).resolves.toEqual(false)
    await expect(
      verifyNonce(
        Buffer.from(
          nonce + Buffer.from('extra').toString('base64'),
          'base64'
        ).toString('base64'),
        mockWallet
      )
    ).resolves.toEqual(false)
  })

  it('returns false for an invalid HMAC verification', async () => {
    (mockWallet.verifyHmac as jest.Mock).mockResolvedValue({ valid: false })

    const nonce = await createNonce(mockWallet)
    await expect(verifyNonce(nonce, mockWallet)).resolves.toEqual(false)
  })

  it('verifies a 256-bit nonce', async () => {
    (mockWallet.verifyHmac as jest.Mock).mockResolvedValue({ valid: true })

    const nonce1 = await createNonce(mockWallet)
    const nonce2 = await createNonce(mockWallet)

    expect(Buffer.from(nonce1, 'base64').byteLength).toEqual(32)
    expect(Buffer.from(nonce2, 'base64').byteLength).toEqual(32)

    await expect(verifyNonce(nonce1, mockWallet)).resolves.toEqual(true)
    await expect(verifyNonce(nonce2, mockWallet)).resolves.toEqual(true)
  })

  it('verifies nonce using real createHmac and verifyHmac', async () => {
    const realWallet = new CompletedProtoWallet(PrivateKey.fromRandom())

    const nonce = await createNonce(realWallet)
    const isValid = await verifyNonce(nonce, realWallet)

    expect(isValid).toEqual(true)
  })

  it('SerialNumber use-case', async () => {
    const clientWallet = new CompletedProtoWallet(PrivateKey.fromRandom())
    const serverWallet = new CompletedProtoWallet(PrivateKey.fromRandom())

    // Client creates a random nonce that the server can verify
    const clientNonce = await createNonce(
      clientWallet,
      (await serverWallet.getPublicKey({ identityKey: true })).publicKey
    )
    // The server verifies the client created the nonce provided
    await verifyNonce(
      clientNonce,
      serverWallet,
      (await clientWallet.getPublicKey({ identityKey: true })).publicKey
    )
    // Server creates a random nonce that the client can verify
    const serverNonce = await createNonce(
      serverWallet,
      (await clientWallet.getPublicKey({ identityKey: true })).publicKey
    )
    // The server compute a serial number from the client and server nonce
    const { hmac: serialNumber } = await serverWallet.createHmac({
      data: Utils.toArray(clientNonce + serverNonce, 'utf8'),
      protocolID: [2, 'certificate creation'],
      keyID: serverNonce + clientNonce,
      counterparty: (await clientWallet.getPublicKey({ identityKey: true }))
        .publicKey
    })

    // Client verifies server's nonce
    await verifyNonce(
      serverNonce,
      clientWallet,
      (await serverWallet.getPublicKey({ identityKey: true })).publicKey
    )

    // Client verifies the server included their nonce
    const { valid } = await clientWallet.verifyHmac({
      hmac: serialNumber,
      data: Utils.toArray(clientNonce + serverNonce, 'utf8'),
      protocolID: [2, 'certificate creation'],
      keyID: serverNonce + clientNonce,
      counterparty: (await serverWallet.getPublicKey({ identityKey: true }))
        .publicKey
    })
    expect(valid).toEqual(true)
  })
})
