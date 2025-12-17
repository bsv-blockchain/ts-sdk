import ProtoWallet from '../../wallet/ProtoWallet'
import { Utils, PrivateKey, Hash, Random } from '../../primitives/index'
import { createNonce, verifyNonce } from '../../auth/utils'

const sampleData = [3, 1, 4, 1, 5, 9]

let userKey: PrivateKey
let counterpartyKey: PrivateKey
let user: ProtoWallet
let counterparty: ProtoWallet

beforeEach(() => {
  userKey = PrivateKey.fromRandom()
  counterpartyKey = PrivateKey.fromRandom()
  user = new ProtoWallet(userKey)
  counterparty = new ProtoWallet(counterpartyKey)
})


describe('ProtoWallet', () => {
  it('Throws when unsupported functions are called', async () => {
    const wallet = new ProtoWallet('anyone')

    // Example: Call a method that doesn't exist or should be unsupported
    expect(() => (wallet as unknown as { nonExistentFunction: () => void }).nonExistentFunction()).toThrow()

    // Example: Ensure it throws when calling a method incorrectly
    expect(() => (wallet as unknown as { derivePrivateKey: () => void }).derivePrivateKey()).toThrow()
  })

  it('Validates the BRC-3 compliance vector', async () => {
    const wallet = new ProtoWallet('anyone')
    const { valid } = await wallet.verifySignature({
      data: Utils.toArray('BRC-3 Compliance Validated!', 'utf8'),
      signature: [
        48, 68, 2, 32, 43, 34, 58, 156, 219, 32, 50, 70, 29, 240, 155, 137, 88,
        60, 200, 95, 243, 198, 201, 21, 56, 82, 141, 112, 69, 196, 170, 73, 156,
        6, 44, 48, 2, 32, 118, 125, 254, 201, 44, 87, 177, 170, 93, 11, 193,
        134, 18, 70, 9, 31, 234, 27, 170, 177, 54, 96, 181, 140, 166, 196, 144,
        14, 230, 118, 106, 105
      ],
      protocolID: [2, 'BRC3 Test'],
      keyID: '42',
      counterparty:
        '0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1'
    })
    expect(valid).toBe(true)
  })
  it('Validates the BRC-2 HMAC compliance vector', async () => {
    const wallet = new ProtoWallet(
      new PrivateKey(
        '6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8',
        'hex'
      )
    )
    const { valid } = await wallet.verifyHmac({
      data: Utils.toArray('BRC-2 HMAC Compliance Validated!', 'utf8'),
      hmac: [
        81, 240, 18, 153, 163, 45, 174, 85, 9, 246, 142, 125, 209, 133, 82, 76,
        254, 103, 46, 182, 86, 59, 219, 61, 126, 30, 176, 232, 233, 100, 234,
        14
      ],
      protocolID: [2, 'BRC2 Test'],
      keyID: '42',
      counterparty:
        '0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1'
    })
    expect(valid).toBe(true)
  })
  it('Validates the BRC-2 Encryption compliance vector', async () => {
    const wallet = new ProtoWallet(
      new PrivateKey(
        '6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8',
        'hex'
      )
    )
    const { plaintext } = await wallet.decrypt({
      ciphertext: [
        252, 203, 216, 184, 29, 161, 223, 212, 16, 193, 94, 99, 31, 140, 99, 43,
        61, 236, 184, 67, 54, 105, 199, 47, 11, 19, 184, 127, 2, 165, 125, 9,
        188, 195, 196, 39, 120, 130, 213, 95, 186, 89, 64, 28, 1, 80, 20, 213,
        159, 133, 98, 253, 128, 105, 113, 247, 197, 152, 236, 64, 166, 207, 113,
        134, 65, 38, 58, 24, 127, 145, 140, 206, 47, 70, 146, 84, 186, 72, 95,
        35, 154, 112, 178, 55, 72, 124
      ],
      protocolID: [2, 'BRC2 Test'],
      keyID: '42',
      counterparty:
        '0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1'
    })
    expect(Utils.toUTF8(plaintext)).toEqual(
      'BRC-2 Encryption Compliance Validated!'
    )
  })
  it('Encrypts messages decryptable by the counterparty', async () => {
    const { ciphertext } = await user.encrypt({
      plaintext: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: counterpartyKey.toPublicKey().toString()
    })
    const { plaintext } = await counterparty.decrypt({
      ciphertext,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: userKey.toPublicKey().toString()
    })
    expect(plaintext).toEqual(sampleData)
    expect(ciphertext).not.toEqual(plaintext)
  })
  it('Fails to decryupt messages for the wrong protocol, key, and counterparty', async () => {
    const { ciphertext } = await user.encrypt({
      plaintext: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: counterpartyKey.toPublicKey().toString()
    })
    await expect(
      async () =>
        await counterparty.decrypt({
          ciphertext,
          protocolID: [1, 'tests'],
          keyID: '4',
          counterparty: userKey.toPublicKey().toString()
        })
    ).rejects.toThrow()
    await expect(
      async () =>
        await counterparty.decrypt({
          ciphertext,
          protocolID: [2, 'tests'],
          keyID: '5',
          counterparty: userKey.toPublicKey().toString()
        })
    ).rejects.toThrow()
    await expect(
      async () =>
        await counterparty.decrypt({
          ciphertext,
          protocolID: [2, 'tests'],
          keyID: '4',
          counterparty: counterpartyKey.toPublicKey().toString()
        })
    ).rejects.toThrow()
  })
  it('Correctly derives keys for a counterparty', async () => {
    const { publicKey: identityKey } = await user.getPublicKey({
      identityKey: true
    })
    expect(identityKey).toEqual(userKey.toPublicKey().toString())
    const { publicKey: derivedForCounterparty } = await user.getPublicKey({
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: counterpartyKey.toPublicKey().toString()
    })
    const { publicKey: derivedByCounterparty } =
      await counterparty.getPublicKey({
        protocolID: [2, 'tests'],
        keyID: '4',
        counterparty: userKey.toPublicKey().toString(),
        forSelf: true
      })
    expect(derivedForCounterparty).toEqual(derivedByCounterparty)
  })
  it('Signs messages verifiable by the counterparty', async () => {
    const { signature } = await user.createSignature({
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: counterpartyKey.toPublicKey().toString()
    })
    const { valid } = await counterparty.verifySignature({
      signature,
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: userKey.toPublicKey().toString()
    })
    expect(valid).toEqual(true)
    expect(signature.length).not.toEqual(0)
  })
  it('Directly signs hash of message verifiable by the counterparty', async () => {
    const { signature } = await user.createSignature({
      hashToDirectlySign: Hash.sha256(sampleData),
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: counterpartyKey.toPublicKey().toString()
    })
    const { valid } = await counterparty.verifySignature({
      signature,
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: userKey.toPublicKey().toString()
    })
    expect(valid).toEqual(true)
    const { valid: hashValid } = await counterparty.verifySignature({
      signature,
      hashToDirectlyVerify: Hash.sha256(sampleData),
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: userKey.toPublicKey().toString()
    })
    expect(hashValid).toEqual(true)
    expect(signature.length).not.toEqual(0)
  })
  it('Fails to verify signature for the wrong data, protocol, key, and counterparty', async () => {
    const { signature } = await user.createSignature({
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: counterpartyKey.toPublicKey().toString()
    })
    await expect(
      async () =>
        await counterparty.verifySignature({
          signature,
          data: [0, ...sampleData],
          protocolID: [2, 'tests'],
          keyID: '4',
          counterparty: userKey.toPublicKey().toString()
        })
    ).rejects.toThrow()
    await expect(
      async () =>
        await counterparty.verifySignature({
          signature,
          data: sampleData,
          protocolID: [2, 'wrong'],
          keyID: '4',
          counterparty: userKey.toPublicKey().toString()
        })
    ).rejects.toThrow()
    await expect(
      async () =>
        await counterparty.verifySignature({
          signature,
          data: sampleData,
          protocolID: [2, 'tests'],
          keyID: '2',
          counterparty: userKey.toPublicKey().toString()
        })
    ).rejects.toThrow()
    await expect(
      async () =>
        await counterparty.verifySignature({
          signature,
          data: sampleData,
          protocolID: [2, 'tests'],
          keyID: '4',
          counterparty: counterpartyKey.toPublicKey().toString()
        })
    ).rejects.toThrow()
  })
  it('Computes HMAC over messages verifiable by the counterparty', async () => {
    const { hmac } = await user.createHmac({
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: counterpartyKey.toPublicKey().toString()
    })
    const { valid } = await counterparty.verifyHmac({
      hmac,
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: userKey.toPublicKey().toString()
    })
    expect(valid).toEqual(true)
    expect(hmac.length).toEqual(32)
  })
  it('Fails to verify HMAC for the wrong data, protocol, key, and counterparty', async () => {
    const { hmac } = await user.createHmac({
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: counterpartyKey.toPublicKey().toString()
    })
    await expect(
      async () =>
        await counterparty.verifyHmac({
          hmac,
          data: [0, ...sampleData],
          protocolID: [2, 'tests'],
          keyID: '4',
          counterparty: userKey.toPublicKey().toString()
        })
    ).rejects.toThrow()
    await expect(
      async () =>
        await counterparty.verifyHmac({
          hmac,
          data: sampleData,
          protocolID: [2, 'wrong'],
          keyID: '4',
          counterparty: userKey.toPublicKey().toString()
        })
    ).rejects.toThrow()
    await expect(
      async () =>
        await counterparty.verifyHmac({
          hmac,
          data: sampleData,
          protocolID: [2, 'tests'],
          keyID: '2',
          counterparty: userKey.toPublicKey().toString()
        })
    ).rejects.toThrow()
    await expect(
      async () =>
        await counterparty.verifyHmac({
          hmac,
          data: sampleData,
          protocolID: [2, 'tests'],
          keyID: '4',
          counterparty: counterpartyKey.toPublicKey().toString()
        })
    ).rejects.toThrow()
  })
  it('Uses anyone for creating signatures and self for other operations if no counterparty is provided', async () => {
    const { hmac } = await user.createHmac({
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4'
    })
    const { valid: hmacValid } = await user.verifyHmac({
      hmac,
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4'
    })
    expect(hmacValid).toEqual(true)
    const { valid: explicitSelfHmacValid } = await user.verifyHmac({
      hmac,
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: 'self'
    })
    expect(explicitSelfHmacValid).toEqual(true)
    expect(hmac.length).toEqual(32)
    const { signature: anyoneSig } = await user.createSignature({
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4'
      // counterparty=anyone is implicit for creating signatures
    })
    const anyone = new ProtoWallet('anyone')
    const { valid: anyoneSigValid } = await anyone.verifySignature({
      signature: anyoneSig,
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: userKey.toPublicKey().toString()
    })
    expect(anyoneSigValid).toEqual(true)
    const { signature: selfSig } = await user.createSignature({
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: 'self'
    })
    const { valid: selfSigValid } = await user.verifySignature({
      signature: selfSig,
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4'
      // Self is implicit when verifying signatures
    })
    expect(selfSigValid).toEqual(true)
    const { valid: explicitSelfSigValid } = await user.verifySignature({
      signature: selfSig,
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: 'self'
    })
    expect(explicitSelfSigValid).toEqual(true)
    const { publicKey } = await user.getPublicKey({
      protocolID: [2, 'tests'],
      keyID: '4'
    })
    const { publicKey: explicitSelfPublicKey } = await user.getPublicKey({
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: 'self'
    })
    expect(publicKey).toEqual(explicitSelfPublicKey)
    const { ciphertext } = await user.encrypt({
      plaintext: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4'
    })
    const { plaintext } = await user.decrypt({
      ciphertext,
      protocolID: [2, 'tests'],
      keyID: '4'
    })
    const { plaintext: explicitSelfPlaintext } = await user.decrypt({
      ciphertext,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: 'self'
    })
    expect(plaintext).toEqual(explicitSelfPlaintext)
    expect(plaintext).toEqual(sampleData)
  })
  it('Efficiently executes hot code paths', async () => {
    const alicePriv = PrivateKey.fromRandom()
    const alice = new ProtoWallet(alicePriv)

    const bobPriv = PrivateKey.fromRandom()
    const bob = new ProtoWallet(bobPriv)

    const ad1 = Random(200)
    const bd1 = Random(100)

    const an1 = await createNonce((alice as any), bobPriv.toPublicKey().toString())
    const { signature: as1 } = await alice.createSignature({
      data: ad1,
      protocolID: [0, 'tests'],
      keyID: '1',
      counterparty: bobPriv.toPublicKey().toString()
    })

    await verifyNonce(an1, (bob as any), alicePriv.toPublicKey().toString())
    await bob.verifySignature({
      signature: as1,
      data: ad1,
      protocolID: [0, 'tests'],
      keyID: '1',
      counterparty: alicePriv.toPublicKey().toString()
    })

    const bn1 = await createNonce((bob as any), alicePriv.toPublicKey().toString())
    const { signature: bs1 } = await bob.createSignature({
      data: bd1,
      protocolID: [0, 'tests'],
      keyID: '1',
      counterparty: alicePriv.toPublicKey().toString()
    })

    await verifyNonce(bn1, (alice as any), bobPriv.toPublicKey().toString())
    await alice.verifySignature({
      signature: bs1,
      data: bd1,
      protocolID: [0, 'tests'],
      keyID: '1',
      counterparty: bobPriv.toPublicKey().toString()
    })
  })
  describe('ProtoWallet Key Linkage Revelation', () => {
    it('Validates the revealCounterpartyKeyLinkage function', async () => {
      // Initialize keys
      const proverKey = PrivateKey.fromRandom()
      const counterpartyKey = PrivateKey.fromRandom()
      const verifierKey = PrivateKey.fromRandom()

      // Initialize wallets
      const proverWallet = new ProtoWallet(proverKey)
      const verifierWallet = new ProtoWallet(verifierKey)

      // Prover reveals counterparty key linkage
      const revelation = await proverWallet.revealCounterpartyKeyLinkage({
        counterparty: counterpartyKey.toPublicKey().toString(),
        verifier: verifierKey.toPublicKey().toString()
      })

      // Verifier decrypts the encrypted linkage
      const { plaintext: linkage } = await verifierWallet.decrypt({
        ciphertext: revelation.encryptedLinkage,
        protocolID: [2, 'counterparty linkage revelation'],
        keyID: revelation.revelationTime,
        counterparty: proverKey.toPublicKey().toString()
      })

      // Compute expected linkage
      const expectedLinkage = proverKey
        .deriveSharedSecret(counterpartyKey.toPublicKey())
        .encode(true)

      // Compare linkage and expectedLinkage
      expect(linkage).toEqual(expectedLinkage)
    })

    it('Validates the revealSpecificKeyLinkage function', async () => {
      // Initialize keys
      const proverKey = PrivateKey.fromRandom()
      const counterpartyKey = PrivateKey.fromRandom()
      const verifierKey = PrivateKey.fromRandom()

      // Initialize wallets
      const proverWallet = new ProtoWallet(proverKey)
      const verifierWallet = new ProtoWallet(verifierKey)

      const protocolID: [0 | 1 | 2, string] = [0, 'tests']
      const keyID = 'test key id'

      // Prover reveals specific key linkage
      const revelation = await proverWallet.revealSpecificKeyLinkage({
        counterparty: counterpartyKey.toPublicKey().toString(),
        verifier: verifierKey.toPublicKey().toString(),
        protocolID,
        keyID
      })

      // Verifier decrypts the encrypted linkage
      const { plaintext: linkage } = await verifierWallet.decrypt({
        ciphertext: revelation.encryptedLinkage,
        protocolID: [
          2,
          `specific linkage revelation ${protocolID[0]} ${protocolID[1]}`
        ],
        keyID,
        counterparty: proverKey.toPublicKey().toString()
      })

      // Compute expected linkage
      const sharedSecret = proverKey
        .deriveSharedSecret(counterpartyKey.toPublicKey())
        .encode(true)

      // Function to compute the invoice number
      const computeInvoiceNumber = function (protocolID, keyID): string {
        const securityLevel = protocolID[0]
        if (
          !Number.isInteger(securityLevel) ||
          securityLevel < 0 ||
          securityLevel > 2
        ) {
          throw new Error('Protocol security level must be 0, 1, or 2')
        }
        const protocolName = protocolID[1].toLowerCase().trim()
        if (keyID.length > 800) {
          throw new Error('Key IDs must be 800 characters or less')
        }
        if (keyID.length < 1) {
          throw new Error('Key IDs must be 1 character or more')
        }
        if (protocolName.length > 400) {
          throw new Error('Protocol names must be 400 characters or less')
        }
        if (protocolName.length < 5) {
          throw new Error('Protocol names must be 5 characters or more')
        }
        if (String(protocolName).includes('  ')) {
          throw new Error(
            'Protocol names cannot contain multiple consecutive spaces ("  ")'
          )
        }
        if (!/^[a-z0-9 ]+$/g.test(protocolName)) {
          throw new Error(
            'Protocol names can only contain letters, numbers and spaces'
          )
        }
        if (String(protocolName).endsWith(' protocol')) {
          throw new Error('No need to end your protocol name with " protocol"')
        }
        return `${String(securityLevel)}-${String(protocolName)}-${String(keyID)}`
      }
      const invoiceNumber = computeInvoiceNumber(protocolID, keyID)
      const invoiceNumberBin = Utils.toArray(invoiceNumber, 'utf8')

      // Compute expected linkage
      const expectedLinkage = Hash.sha256hmac(sharedSecret, invoiceNumberBin)

      // Compare linkage and expectedLinkage
      expect(linkage).toEqual(expectedLinkage)
    })
  })

  it('Fails constant-time HMAC validation for wrong-but-same-length HMAC', async () => {
    const { hmac: correctHmac } = await user.createHmac({
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: counterpartyKey.toPublicKey().toString()
    })

    // Create a different HMAC with same length
    const wrong = correctHmac.slice()
    wrong[0] = (wrong[0] + 1) & 0xff  // minimally alter 1 byte

    await expect(async () =>
      await counterparty.verifyHmac({
        hmac: wrong,
        data: sampleData,
        protocolID: [2, 'tests'],
        keyID: '4',
        counterparty: userKey.toPublicKey().toString()
      })
    ).rejects.toThrow('HMAC is not valid')
  })

  it('Validates correct HMAC using the constant-time comparison path', async () => {
    const { hmac } = await user.createHmac({
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: counterpartyKey.toPublicKey().toString()
    })

    const { valid } = await counterparty.verifyHmac({
      hmac,
      data: sampleData,
      protocolID: [2, 'tests'],
      keyID: '4',
      counterparty: userKey.toPublicKey().toString()
    })

    expect(valid).toBe(true)
  })
})
