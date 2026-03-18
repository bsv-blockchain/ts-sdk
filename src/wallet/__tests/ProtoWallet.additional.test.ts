import ProtoWallet from '../../wallet/ProtoWallet'
import PrivateKey from '../../primitives/PrivateKey'

function walletWithNullKeyDeriver (): ProtoWallet {
  const wallet = new ProtoWallet(PrivateKey.fromRandom())
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ;(wallet as any).keyDeriver = undefined
  return wallet
}

describe('ProtoWallet – additional coverage', () => {
  describe('getPublicKey', () => {
    it('throws when identityKey is true and keyDeriver is null', async () => {
      const wallet = walletWithNullKeyDeriver()
      await expect(wallet.getPublicKey({ identityKey: true })).rejects.toThrow(
        'keyDeriver is undefined'
      )
    })

    it('throws when protocolID and keyID are missing (non-identityKey path)', async () => {
      const wallet = new ProtoWallet(PrivateKey.fromRandom())
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await expect(wallet.getPublicKey({} as any)).rejects.toThrow(
        'protocolID and keyID are required'
      )
    })

    it('throws when keyDeriver is null and identityKey is false', async () => {
      const wallet = walletWithNullKeyDeriver()
      await expect(
        wallet.getPublicKey({
          protocolID: [1, 'test'],
          keyID: 'key1'
        })
      ).rejects.toThrow('keyDeriver is undefined')
    })
  })

  describe('encrypt', () => {
    it('throws when keyDeriver is null', async () => {
      const wallet = walletWithNullKeyDeriver()
      await expect(
        wallet.encrypt({
          plaintext: [1, 2, 3],
          protocolID: [1, 'test'],
          keyID: 'k1'
        })
      ).rejects.toThrow('keyDeriver is undefined')
    })
  })

  describe('decrypt', () => {
    it('throws when keyDeriver is null', async () => {
      const wallet = walletWithNullKeyDeriver()
      await expect(
        wallet.decrypt({
          ciphertext: [1, 2, 3],
          protocolID: [1, 'test'],
          keyID: 'k1'
        })
      ).rejects.toThrow('keyDeriver is undefined')
    })
  })

  describe('createHmac', () => {
    it('throws when keyDeriver is null', async () => {
      const wallet = walletWithNullKeyDeriver()
      await expect(
        wallet.createHmac({
          data: [1, 2, 3],
          protocolID: [1, 'test'],
          keyID: 'k1'
        })
      ).rejects.toThrow('keyDeriver is undefined')
    })
  })

  describe('verifyHmac', () => {
    it('throws when keyDeriver is null', async () => {
      const wallet = walletWithNullKeyDeriver()
      await expect(
        wallet.verifyHmac({
          data: [1, 2, 3],
          hmac: new Array(32).fill(0),
          protocolID: [1, 'test'],
          keyID: 'k1'
        })
      ).rejects.toThrow('keyDeriver is undefined')
    })
  })

  describe('createSignature', () => {
    it('throws when both data and hashToDirectlySign are missing', async () => {
      const wallet = new ProtoWallet(PrivateKey.fromRandom())
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await expect(wallet.createSignature({} as any)).rejects.toThrow(
        'args.data or args.hashToDirectlySign must be valid'
      )
    })

    it('throws when keyDeriver is null', async () => {
      const wallet = walletWithNullKeyDeriver()
      await expect(
        wallet.createSignature({
          data: [1, 2, 3],
          protocolID: [1, 'test'],
          keyID: 'k1'
        })
      ).rejects.toThrow('keyDeriver is undefined')
    })
  })

  describe('verifySignature', () => {
    it('throws when both data and hashToDirectlyVerify are missing', async () => {
      const wallet = new ProtoWallet(PrivateKey.fromRandom())
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await expect(wallet.verifySignature({} as any)).rejects.toThrow(
        'args.data or args.hashToDirectlyVerify must be valid'
      )
    })

    it('throws when keyDeriver is null', async () => {
      const wallet = walletWithNullKeyDeriver()
      await expect(
        wallet.verifySignature({
          data: [1, 2, 3],
          signature: [1, 2, 3],
          protocolID: [1, 'test'],
          keyID: 'k1'
        })
      ).rejects.toThrow('keyDeriver is undefined')
    })
  })
})
