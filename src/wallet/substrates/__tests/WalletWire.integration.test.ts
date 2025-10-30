import { CompletedProtoWallet } from '../../../auth/certificates/__tests/CompletedProtoWallet'
import { Utils, PrivateKey, Hash } from '../../../primitives/index'
import WalletWireTransceiver from '../../../wallet/substrates/WalletWireTransceiver'
import WalletWireProcessor from '../../../wallet/substrates/WalletWireProcessor'

const sampleData = [3, 1, 4, 1, 5, 9]

describe('WalletWire Integration Tests', () => {
  /**
   * This is a copy of the test suite for CompletedProtoWallet, but instead of using a CompletedProtoWallet directly, we're using it over the WalletWire.
   * This serves as an imperfect but still useful way to ensure that the WalletWire doesn't contain serialization or deserialization issues.
   */
  describe('ProtoWallet Over Wallet Wire', () => {
    it('Throws when functions are not supported', async () => {
      const wallet = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet('anyone'))
      )
      await expect(() => {
        return (wallet as any).createAction()
      }).rejects.toThrow()
      await expect(() => {
        return (wallet as any).abortAction()
      }).rejects.toThrow()
      await expect(() => {
        return (wallet as any).signAction()
      }).rejects.toThrow()
      await expect(() => {
        return (wallet as any).listOutputs()
      }).rejects.toThrow()
      await expect(() => {
        return (wallet as any).relinquishOutput()
      }).rejects.toThrow()
      await expect(() => {
        return (wallet as any).listActions()
      }).rejects.toThrow()
      await expect(() => {
        return (wallet as any).internalizeAction()
      }).rejects.toThrow()
      await expect(() => {
        return (wallet as any).acquireCertificate()
      }).rejects.toThrow()
      await expect(() => {
        return (wallet as any).proveCertificate()
      }).rejects.toThrow()
      await expect(() => {
        return (wallet as any).listCertificates()
      }).rejects.toThrow()
      await expect(() => {
        return (wallet as any).relinquishCertificate()
      }).rejects.toThrow()
      await expect(() => {
        return (wallet as any).getHeight()
      }).rejects.toThrow()
      await expect(() => {
        return (wallet as any).getHeaderForHeight()
      }).rejects.toThrow()
      // TODO: Remove these two from the throw list once they are implemented.
      await expect(() => {
        return (wallet as any).discoverByIdentityKey()
      }).rejects.toThrow()
      await expect(() => {
        return (wallet as any).discoverByAttributes()
      }).rejects.toThrow()
    })
    it('Validates the BRC-3 compliance vector', async () => {
      const wallet = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet('anyone'))
      )
      const { valid } = await wallet.verifySignature({
        data: Utils.toArray('BRC-3 Compliance Validated!', 'utf8'),
        signature: [
          48, 68, 2, 32, 43, 34, 58, 156, 219, 32, 50, 70, 29, 240, 155, 137,
          88, 60, 200, 95, 243, 198, 201, 21, 56, 82, 141, 112, 69, 196, 170,
          73, 156, 6, 44, 48, 2, 32, 118, 125, 254, 201, 44, 87, 177, 170, 93,
          11, 193, 134, 18, 70, 9, 31, 234, 27, 170, 177, 54, 96, 181, 140, 166,
          196, 144, 14, 230, 118, 106, 105
        ],
        protocolID: [2, 'BRC3 Test'],
        keyID: '42',
        counterparty:
          '0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1'
      })
      expect(valid).toBe(true)
    })
    it('Validates the BRC-2 HMAC compliance vector', async () => {
      const wallet = new WalletWireTransceiver(
        new WalletWireProcessor(
          new CompletedProtoWallet(
            new PrivateKey(
              '6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8',
              'hex'
            )
          )
        )
      )
      const { valid } = await wallet.verifyHmac({
        data: Utils.toArray('BRC-2 HMAC Compliance Validated!', 'utf8'),
        hmac: [
          6, 64, 49, 30, 30, 163, 149, 94, 197, 152, 109, 219, 127, 236, 48, 47,
          10, 240, 213, 37, 68, 253, 170, 161, 146, 73, 192, 91, 125, 72, 184, 9
        ],
        protocolID: [2, 'BRC2 Test'],
        keyID: '42',
        counterparty:
          '0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1'
      })
      expect(valid).toBe(true)
    })
    it('Validates the BRC-2 Encryption compliance vector', async () => {
      const wallet = new WalletWireTransceiver(
        new WalletWireProcessor(
          new CompletedProtoWallet(
            new PrivateKey(
              '6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8',
              'hex'
            )
          )
        )
      )
      const { plaintext } = await wallet.decrypt({
        ciphertext: [
          246, 144, 167, 40, 218, 49, 221, 143, 190, 223, 153, 253, 8, 75, 206, 248,
          91, 153, 103, 10, 237, 58, 133, 210, 95, 81, 35, 80, 204, 237, 50, 86,
          95, 26, 251, 199, 108, 168, 136, 110, 43, 113, 17, 206, 101, 175, 0, 119,
          50, 8, 134, 131, 16, 35, 124, 163, 46, 241, 123, 157, 182, 31, 221, 127,
          122, 251, 214, 77, 0, 170, 53, 139, 172, 206, 239, 166, 31, 196, 54, 192,
          90, 28, 249, 183, 168, 253
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
      const userKey = PrivateKey.fromRandom()
      const counterpartyKey = PrivateKey.fromRandom()
      const user = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(userKey))
      )
      const counterparty = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(counterpartyKey))
      )
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
      const userKey = PrivateKey.fromRandom()
      const counterpartyKey = PrivateKey.fromRandom()
      const user = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(userKey))
      )
      const counterparty = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(counterpartyKey))
      )
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
      const userKey = PrivateKey.fromRandom()
      const counterpartyKey = PrivateKey.fromRandom()
      const user = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(userKey))
      )
      const counterparty = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(counterpartyKey))
      )
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
      const userKey = PrivateKey.fromRandom()
      const counterpartyKey = PrivateKey.fromRandom()
      const user = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(userKey))
      )
      const counterparty = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(counterpartyKey))
      )
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
      const userKey = PrivateKey.fromRandom()
      const counterpartyKey = PrivateKey.fromRandom()
      const user = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(userKey))
      )
      const counterparty = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(counterpartyKey))
      )
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
      const userKey = PrivateKey.fromRandom()
      const counterpartyKey = PrivateKey.fromRandom()
      const user = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(userKey))
      )
      const counterparty = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(counterpartyKey))
      )
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
      const userKey = PrivateKey.fromRandom()
      const counterpartyKey = PrivateKey.fromRandom()
      const user = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(userKey))
      )
      const counterparty = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(counterpartyKey))
      )
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
      const userKey = PrivateKey.fromRandom()
      const counterpartyKey = PrivateKey.fromRandom()
      const user = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(userKey))
      )
      const counterparty = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(counterpartyKey))
      )
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
      const userKey = PrivateKey.fromRandom()
      const user = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(userKey))
      )
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
      const anyone = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet('anyone'))
      )
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
    it('Validates the revealCounterpartyKeyLinkage function', async () => {
      // Initialize keys
      const proverKey = PrivateKey.fromRandom()
      const counterpartyKey = PrivateKey.fromRandom()
      const verifierKey = PrivateKey.fromRandom()

      // Initialize wallets
      const proverWallet = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(proverKey))
      )
      const verifierWallet = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(verifierKey))
      )

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
      const proverWallet = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(proverKey))
      )
      const verifierWallet = new WalletWireTransceiver(
        new WalletWireProcessor(new CompletedProtoWallet(verifierKey))
      )

      const protocolID: [0 | 1 | 2, string] = [0, 'tests']
      const keyID = 'test key id'

      // Prover reveals specific key linkage
      const revelation = await proverWallet.revealSpecificKeyLinkage({
        counterparty: counterpartyKey.toPublicKey().toString(),
        verifier: verifierKey.toPublicKey().toString(),
        protocolID,
        keyID
      })
      expect(revelation.encryptedLinkageProof).toBeDefined()
      expect(revelation.proofType).toBeDefined()

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
      const computeInvoiceNumber = function (protocolID: [number, string], keyID: string): string {
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
        if (protocolName.includes('  ')) {
          throw new Error(
            'Protocol names cannot contain multiple consecutive spaces ("  ")'
          )
        }
        if (!/^[a-z0-9 ]+$/g.test(protocolName)) {
          throw new Error(
            'Protocol names can only contain letters, numbers and spaces'
          )
        }
        if (protocolName.endsWith(' protocol')) {
          throw new Error('No need to end your protocol name with " protocol"')
        }
        return `${securityLevel}-${protocolName}-${keyID}`
      }
      const invoiceNumber = computeInvoiceNumber(protocolID, keyID)
      const invoiceNumberBin = Utils.toArray(invoiceNumber, 'utf8')

      // Compute expected linkage
      const expectedLinkage = Hash.sha256hmac(sharedSecret, invoiceNumberBin)

      // Compare linkage and expectedLinkage
      expect(linkage).toEqual(expectedLinkage)
    })
  })
  // Helper function to create a test wallet wire setup
  const createTestWalletWire = (wallet: CompletedProtoWallet): WalletWireTransceiver => {
    const processor = new WalletWireProcessor(wallet)
    const transceiver = new WalletWireTransceiver(processor)
    return transceiver
  }

  // Mock implementation for methods not supported by CompletedProtoWallet
  const mockUnsupportedMethods = (
    methods: Partial<CompletedProtoWallet>
  ): CompletedProtoWallet => {
    // @ts-expect-error
    const result: CompletedProtoWallet = {
      ...methods
    }
    return result
  }

  describe('createAction', () => {
    it('should create an action with valid inputs', async () => {
      // Mock the createAction method
      const createActionMock = jest.fn().mockResolvedValue({
        txid: 'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806',
        tx: [1, 2, 3, 4]
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          createAction: createActionMock
        })
      )

      const args = {
        description: 'Test action description',
        outputs: [
          {
            lockingScript: '00', // Sample locking script
            satoshis: 1000,
            outputDescription: 'Test output',
            basket: 'test-basket',
            customInstructions: 'Test instructions',
            tags: ['test-tag']
          }
        ],
        labels: ['test-label']
      }
      const result = await wallet.createAction(args)
      expect(result).toHaveProperty('txid')
      expect(result).toHaveProperty('tx')
      expect(result.tx).toBeInstanceOf(Array)
      expect(createActionMock).toHaveBeenCalledWith(args, '')
    })

    it('should create an action with minimal inputs (only description)', async () => {
      // Mock the createAction method
      const createActionMock = jest.fn().mockResolvedValue({
        txid: 'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806'
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          createAction: createActionMock
        })
      )

      const args = {
        description: 'Minimal action description'
      }
      const result = await wallet.createAction(args)
      expect(result).toHaveProperty('txid')
      expect(result).not.toHaveProperty('tx')
      expect(result).not.toHaveProperty('noSendChange')
      expect(result).not.toHaveProperty('sendWithResults')
      expect(result).not.toHaveProperty('signableTransaction')
      expect(createActionMock).toHaveBeenCalledWith(args, '')
    })

    it('should create an action and return only txid when returnTXIDOnly is true', async () => {
      // Mock the createAction method
      const createActionMock = jest.fn().mockResolvedValue({
        txid: 'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806'
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          createAction: createActionMock
        })
      )

      const args = {
        description: 'Test action with returnTXIDOnly',
        options: {
          returnTXIDOnly: true
        }
      }
      const result = await wallet.createAction(args)
      expect(result).toHaveProperty('txid')
      expect(result).not.toHaveProperty('tx')
      expect(result).not.toHaveProperty('noSendChange')
      expect(result).not.toHaveProperty('sendWithResults')
      expect(result).not.toHaveProperty('signableTransaction')
      expect(createActionMock).toHaveBeenCalledWith(args, '')
    })

    it('should create an action and return a signableTransaction when noSend is true', async () => {
      // Mock the createAction method
      const createActionMock = jest.fn().mockResolvedValue({
        signableTransaction: {
          tx: [0x01],
          reference: Utils.toBase64([0x01])
        }
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          createAction: createActionMock
        })
      )

      const args = {
        description: 'Test action with noSend',
        options: {
          noSend: true
        }
      }
      const result = await wallet.createAction(args)
      expect(result).toHaveProperty('signableTransaction')
      expect(result.signableTransaction).toHaveProperty('tx')
      expect(result.signableTransaction).toHaveProperty('reference')
      expect(result).not.toHaveProperty('txid')
      expect(result).not.toHaveProperty('tx')
      expect(createActionMock).toHaveBeenCalledWith(args, '')
    })

    it('should create an action with all options set and handle all return values', async () => {
      // Mock the createAction method
      const createActionMock = jest.fn().mockResolvedValue({
        txid: 'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806',
        tx: [1, 2, 3, 4],
        noSendChange: [
          'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806.0'
        ],
        sendWithResults: [
          {
            txid: 'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806',
            status: 'sending'
          }
        ],
        signableTransaction: {
          tx: [0x01],
          reference: Utils.toBase64([0x01])
        }
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          createAction: createActionMock
        })
      )

      const args = {
        description: 'Test action with all options',
        inputs: [],
        inputBEEF: [1, 2, 3, 4],
        outputs: [
          {
            lockingScript: '016a',
            satoshis: 1,
            outputDescription: 'This is a test.'
          }
        ],
        lockTime: 0,
        version: 1,
        labels: ['label1', 'label2'],
        options: {
          signAndProcess: false,
          acceptDelayedBroadcast: false,
          trustSelf: 'known' as 'known',
          knownTxids: [
            'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806'
          ],
          returnTXIDOnly: false,
          noSend: true,
          noSendChange: [
            'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806.0'
          ],
          sendWith: [
            'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806'
          ],
          randomizeOutputs: false
        }
      }
      const result = await wallet.createAction(args)
      expect(result).toHaveProperty('txid')
      expect(result).toHaveProperty('tx')
      expect(result).toHaveProperty('noSendChange')
      expect(result).toHaveProperty('sendWithResults')
      expect(result).toHaveProperty('signableTransaction')
      expect(createActionMock).toHaveBeenCalledWith(args, '')
    })

    it('should throw an error with invalid inputs', async () => {
      // Mock the createAction method to throw an error
      const createActionMock = jest
        .fn()
        .mockRejectedValue(new Error('Invalid inputs'))
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          createAction: createActionMock
        })
      )
      const args = {
        description: '' // Invalid description (too short)
      }
      await expect(wallet.createAction(args)).rejects.toThrow('Invalid inputs')
      expect(createActionMock).toHaveBeenCalledWith(args, '')
    })
  })

  describe('signAction', () => {
    it('should sign an action with valid inputs', async () => {
      // Mock the signAction method
      const signActionMock = jest.fn().mockResolvedValue({
        txid: 'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806',
        tx: [1, 2, 3, 4]
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          signAction: signActionMock
        })
      )

      const spends = {
        0: {
          unlockingScript: '00' // Sample unlocking script
        }
      }
      const reference = Utils.toBase64([1, 2, 3])
      const args = { spends, reference }
      const result = await wallet.signAction(args)
      expect(result).toHaveProperty('txid')
      expect(result).toHaveProperty('tx')
      expect(result.tx).toBeInstanceOf(Array)
      expect(signActionMock).toHaveBeenCalledWith(args, '')
    })

    it('should throw an error with invalid inputs', async () => {
      // Mock the signAction method to throw an error
      const signActionMock = jest
        .fn()
        .mockRejectedValue(new Error('Invalid inputs'))
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          signAction: signActionMock
        })
      )
      const spends = {}
      const reference = ''
      const args = { spends, reference }
      await expect(wallet.signAction(args)).rejects.toThrow('Invalid inputs')
      expect(signActionMock).toHaveBeenCalledWith(args, '')
    })
  })

  describe('abortAction', () => {
    it('should abort an action with valid reference', async () => {
      // Mock the abortAction method
      const abortActionMock = jest.fn().mockResolvedValue({ aborted: true })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          abortAction: abortActionMock
        })
      )

      const reference = Utils.toBase64([1, 2, 3])
      const args = { reference }
      const result = await wallet.abortAction(args)
      expect(result).toEqual({ aborted: true })
      expect(abortActionMock).toHaveBeenCalledWith(args, '')
    })

    it('should throw an error with invalid reference', async () => {
      // Mock the abortAction method to throw an error
      const abortActionMock = jest
        .fn()
        .mockRejectedValue(new Error('Invalid reference'))
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          abortAction: abortActionMock
        })
      )
      const reference = ''
      const args = { reference }
      await expect(wallet.abortAction(args)).rejects.toThrow(
        'Invalid reference'
      )
      expect(abortActionMock).toHaveBeenCalledWith(args, '')
    })
  })

  describe('listActions', () => {
    it('should list actions with valid inputs', async () => {
      // Mock the listActions method
      const listActionsMock = jest.fn().mockResolvedValue({
        totalActions: 1,
        actions: [
          {
            txid: 'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806',
            satoshis: 1000,
            status: 'completed',
            isOutgoing: true,
            description: 'Test action',
            labels: ['test-label'],
            version: 1,
            lockTime: 0
          }
        ]
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          listActions: listActionsMock
        })
      )

      const args = {
        labels: ['test-label'],
        includeLabels: true,
        limit: 10,
        offset: 0
      }
      const result = await wallet.listActions(args)
      expect(result).toHaveProperty('totalActions')
      expect(result).toHaveProperty('actions')
      expect(Array.isArray(result.actions)).toBe(true)
      expect(listActionsMock).toHaveBeenCalledWith(args, '')
    })

    it('should list actions with empty labels array', async () => {
      // Mock the listActions method
      const listActionsMock = jest.fn().mockResolvedValue({
        totalActions: 0,
        actions: []
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          listActions: listActionsMock
        })
      )

      const args = {
        labels: [],
        includeLabels: true,
        limit: 10,
        offset: 0
      }
      const result = await wallet.listActions(args)
      expect(result).toHaveProperty('totalActions')
      expect(result.totalActions).toBe(0)
      expect(result.actions).toEqual([])
      expect(listActionsMock).toHaveBeenCalledWith(args, '')
    })

    it('should throw an error with invalid inputs', async () => {
      // Mock the listActions method to throw an error
      const listActionsMock = jest
        .fn()
        .mockRejectedValue(new Error('Invalid inputs'))
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          listActions: listActionsMock
        })
      )
      const args = {
        labels: []
      }
      await expect(wallet.listActions(args)).rejects.toThrow('Invalid inputs')
      expect(listActionsMock).toHaveBeenCalledWith(args, '')
    })
  })

  describe('internalizeAction', () => {
    it('should internalize an action with valid inputs', async () => {
      // Mock the internalizeAction method
      const internalizeActionMock = jest
        .fn()
        .mockResolvedValue({ accepted: true })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          internalizeAction: internalizeActionMock
        })
      )

      const args = {
        tx: [0x00], // Sample transaction byte array
        outputs: [
          {
            outputIndex: 0,
            protocol: 'wallet payment' as 'wallet payment',
            paymentRemittance: {
              derivationPrefix: Utils.toBase64([1, 2, 3]),
              derivationSuffix: Utils.toBase64([4, 5, 6]),
              senderIdentityKey: '02' + '1'.repeat(64)
            }
          }
        ],
        description: 'Test internalize action',
        labels: ['test-label']
      }
      const result = await wallet.internalizeAction(args)
      expect(result).toEqual({ accepted: true })
      expect(internalizeActionMock).toHaveBeenCalledWith(args, '')
    })

    it('should throw an error with invalid inputs', async () => {
      // Mock the internalizeAction method to throw an error
      const internalizeActionMock = jest
        .fn()
        .mockRejectedValue(new Error('Invalid inputs'))
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          internalizeAction: internalizeActionMock
        })
      )
      const args = {
        tx: [], // Empty transaction array
        outputs: [],
        description: 'Test internalize action'
      }
      await expect(wallet.internalizeAction(args)).rejects.toThrow(
        'Invalid inputs'
      )
      expect(internalizeActionMock).toHaveBeenCalledWith(args, '')
    })
    it('should internalize an action with "basket insertion" protocol', async () => {
      // Mock the internalizeAction method
      const internalizeActionMock = jest
        .fn()
        .mockResolvedValue({ accepted: true })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          internalizeAction: internalizeActionMock
        })
      )

      const args = {
        tx: [0x00], // Sample transaction byte array
        outputs: [
          {
            outputIndex: 0,
            protocol: 'basket insertion' as 'basket insertion',
            insertionRemittance: {
              basket: 'test-basket',
              customInstructions: 'Test instructions',
              tags: ['test-tag1', 'test-tag2']
            }
          }
        ],
        description: 'Test internalize action with basket insertion',
        labels: ['test-label']
      }
      const result = await wallet.internalizeAction(args)
      expect(result).toEqual({ accepted: true })
      expect(internalizeActionMock).toHaveBeenCalledWith(args, '')
    })
  })

  describe('listOutputs', () => {
    it('should list outputs with valid inputs', async () => {
      // Mock the listOutputs method
      const listOutputsMock = jest.fn().mockResolvedValue({
        totalOutputs: 1,
        outputs: [
          {
            outpoint:
              'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806.0',
            satoshis: 1000,
            lockingScript: '00',
            spendable: true,
            customInstructions: 'Test instructions',
            tags: ['test-tag'],
            labels: ['test-label']
          }
        ]
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          listOutputs: listOutputsMock
        })
      )

      const args = {
        basket: 'test-basket',
        includeLabels: true,
        limit: 10,
        offset: 0
      }
      const result = await wallet.listOutputs(args)
      expect(result).toHaveProperty('totalOutputs')
      expect(result).toHaveProperty('outputs')
      expect(Array.isArray(result.outputs)).toBe(true)
      expect(listOutputsMock).toHaveBeenCalledWith(args, '')
    })

    it('should throw an error with invalid inputs', async () => {
      // Mock the listOutputs method to throw an error
      const listOutputsMock = jest
        .fn()
        .mockRejectedValue(new Error('Invalid inputs'))
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          listOutputs: listOutputsMock
        })
      )
      const args = {
        basket: ''
      }
      await expect(wallet.listOutputs(args)).rejects.toThrow('Invalid inputs')
      expect(listOutputsMock).toHaveBeenCalledWith(args, '')
    })
    it('should list outputs without specifying optional parameters', async () => {
      // Mock the listOutputs method
      const listOutputsMock = jest.fn().mockResolvedValue({
        totalOutputs: 1,
        BEEF: [1, 2, 3, 4],
        outputs: [
          {
            outpoint:
              'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806.0',
            satoshis: 1000,
            spendable: true
          }
        ]
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          listOutputs: listOutputsMock
        })
      )

      const args = {
        basket: 'test-basket'
        // Optional parameters are not specified
      }
      const result = await wallet.listOutputs(args)
      expect(result).toHaveProperty('totalOutputs')
      expect(result).toHaveProperty('outputs')
      expect(result).toHaveProperty('BEEF')
      expect(result.outputs[0]).toHaveProperty('outpoint')
      expect(result.outputs[0]).toHaveProperty('satoshis')
      expect(result.outputs[0]).toHaveProperty('spendable')
      expect(result.outputs[0]).not.toHaveProperty('lockingScript')
      expect(result.outputs[0]).not.toHaveProperty('customInstructions')
      expect(result.outputs[0]).not.toHaveProperty('tags')
      expect(result.outputs[0]).not.toHaveProperty('labels')
      expect(listOutputsMock).toHaveBeenCalledWith(args, '')
    })
  })

  describe('getPublicKey', () => {
    it('should get the identity public key', async () => {
      const wallet = createTestWalletWire(
        new CompletedProtoWallet(PrivateKey.fromRandom())
      )
      const result = await wallet.getPublicKey({ identityKey: true })
      expect(result).toHaveProperty('publicKey')
      expect(typeof result.publicKey).toBe('string')
      expect(result.publicKey.length).toBe(66) // Compressed public key hex length
    })

    it('should get a derived public key with valid inputs', async () => {
      const userKey = PrivateKey.fromRandom()
      const counterpartyKey = PrivateKey.fromRandom()
      const wallet = createTestWalletWire(new CompletedProtoWallet(userKey))
      const args = {
        protocolID: [2, 'tests'] as [0 | 1 | 2, string],
        keyID: 'test-key-id',
        counterparty: counterpartyKey.toPublicKey().toString()
      }
      const result = await wallet.getPublicKey(args)
      expect(result).toHaveProperty('publicKey')
      expect(typeof result.publicKey).toBe('string')
      expect(result.publicKey.length).toBe(66)
    })

    it('should get the public key with counterparty "anyone"', async () => {
      const wallet = createTestWalletWire(
        new CompletedProtoWallet(PrivateKey.fromRandom())
      )
      const args = {
        protocolID: [1, 'testprotocol'] as [0 | 1 | 2, string],
        keyID: 'testkeyid',
        counterparty: 'anyone' as 'anyone'
      }
      const result = await wallet.getPublicKey(args)
      expect(result).toHaveProperty('publicKey')
      expect(typeof result.publicKey).toBe('string')
      expect(result.publicKey.length).toBe(66) // Compressed public key hex length
    })

    it('should get the public key with missing optional parameters', async () => {
      const wallet = createTestWalletWire(
        new CompletedProtoWallet(PrivateKey.fromRandom())
      )
      const args = {
        protocolID: [0, 'minimalprotocol'] as [0 | 1 | 2, string],
        keyID: 'minimalkeyid'
        // Missing counterparty, should default to 'self' or 'anyone' based on context
      }
      const result = await wallet.getPublicKey(args)
      expect(result).toHaveProperty('publicKey')
      expect(typeof result.publicKey).toBe('string')
      expect(result.publicKey.length).toBe(66)
    })
  })

  describe('encrypt and decrypt', () => {
    it('should encrypt and decrypt data correctly', async () => {
      const userKey = PrivateKey.fromRandom()
      const counterpartyKey = PrivateKey.fromRandom()
      const userWallet = createTestWalletWire(new CompletedProtoWallet(userKey))
      const counterpartyWallet = createTestWalletWire(
        new CompletedProtoWallet(counterpartyKey)
      )

      const plaintext = sampleData
      const encryptArgs = {
        plaintext,
        protocolID: [2, 'tests'] as [0 | 1 | 2, string],
        keyID: 'test-key-id',
        counterparty: counterpartyKey.toPublicKey().toString()
      }
      const encryptResult = await userWallet.encrypt(encryptArgs)
      expect(encryptResult).toHaveProperty('ciphertext')
      expect(encryptResult.ciphertext).not.toEqual(plaintext)

      const decryptArgs = {
        ciphertext: encryptResult.ciphertext,
        protocolID: [2, 'tests'] as [0 | 1 | 2, string],
        keyID: 'test-key-id',
        counterparty: userKey.toPublicKey().toString()
      }
      const decryptResult = await counterpartyWallet.decrypt(decryptArgs)
      expect(decryptResult).toHaveProperty('plaintext')
      expect(decryptResult.plaintext).toEqual(plaintext)
    })

    it('should throw an error for invalid decryption inputs', async () => {
      const userKey = PrivateKey.fromRandom()
      const counterpartyKey = PrivateKey.fromRandom()
      const counterpartyWallet = createTestWalletWire(
        new CompletedProtoWallet(counterpartyKey)
      )

      const decryptArgs = {
        ciphertext: [0x00],
        protocolID: [2, 'tests'] as [0 | 1 | 2, string],
        keyID: 'test-key-id',
        counterparty: userKey.toPublicKey().toString()
      }
      await expect(counterpartyWallet.decrypt(decryptArgs)).rejects.toThrow()
    })
  })

  describe('createHmac and verifyHmac', () => {
    it('should create and verify HMAC correctly', async () => {
      const userKey = PrivateKey.fromRandom()
      const counterpartyKey = PrivateKey.fromRandom()
      const userWallet = createTestWalletWire(new CompletedProtoWallet(userKey))
      const counterpartyWallet = createTestWalletWire(
        new CompletedProtoWallet(counterpartyKey)
      )

      const data = sampleData
      const createHmacArgs = {
        data,
        protocolID: [2, 'tests'] as [0 | 1 | 2, string],
        keyID: 'test-key-id',
        counterparty: counterpartyKey.toPublicKey().toString()
      }
      const createHmacResult = await userWallet.createHmac(createHmacArgs)
      expect(createHmacResult).toHaveProperty('hmac')
      expect(createHmacResult.hmac.length).toBe(32)

      const verifyHmacArgs = {
        data,
        hmac: createHmacResult.hmac,
        protocolID: [2, 'tests'] as [0 | 1 | 2, string],
        keyID: 'test-key-id',
        counterparty: userKey.toPublicKey().toString()
      }
      const verifyHmacResult =
        await counterpartyWallet.verifyHmac(verifyHmacArgs)
      expect(verifyHmacResult).toEqual({ valid: true })
    })

    it('should throw an error for invalid HMAC verification', async () => {
      const userKey = PrivateKey.fromRandom()
      const counterpartyWallet = createTestWalletWire(
        new CompletedProtoWallet(PrivateKey.fromRandom())
      )

      const verifyHmacArgs = {
        data: sampleData,
        hmac: [0x00],
        protocolID: [2, 'tests'] as [0 | 1 | 2, string],
        keyID: 'test-key-id',
        counterparty: userKey.toPublicKey().toString()
      }
      await expect(
        counterpartyWallet.verifyHmac(verifyHmacArgs)
      ).rejects.toThrow()
    })
  })

  describe('createSignature and verifySignature', () => {
    it('should create and verify signature correctly', async () => {
      const userKey = PrivateKey.fromRandom()
      const counterpartyKey = PrivateKey.fromRandom()
      const userWallet = createTestWalletWire(new CompletedProtoWallet(userKey))
      const counterpartyWallet = createTestWalletWire(
        new CompletedProtoWallet(counterpartyKey)
      )

      const data = sampleData
      const createSignatureArgs = {
        data,
        protocolID: [2, 'tests'] as [0 | 1 | 2, string],
        keyID: 'test-key-id',
        counterparty: counterpartyKey.toPublicKey().toString()
      }
      const createSignatureResult =
        await userWallet.createSignature(createSignatureArgs)
      expect(createSignatureResult).toHaveProperty('signature')
      expect(createSignatureResult.signature.length).toBeGreaterThan(0)

      const verifySignatureArgs = {
        data,
        signature: createSignatureResult.signature,
        protocolID: [2, 'tests'] as [0 | 1 | 2, string],
        keyID: 'test-key-id',
        counterparty: userKey.toPublicKey().toString()
      }
      const verifySignatureResult =
        await counterpartyWallet.verifySignature(verifySignatureArgs)
      expect(verifySignatureResult).toEqual({ valid: true })
    })

    it('should throw an error for invalid signature verification', async () => {
      const userKey = PrivateKey.fromRandom()
      const counterpartyWallet = createTestWalletWire(
        new CompletedProtoWallet(PrivateKey.fromRandom())
      )

      const verifySignatureArgs = {
        data: sampleData,
        signature: [0x00],
        protocolID: [2, 'tests'] as [0 | 1 | 2, string],
        keyID: 'test-key-id',
        counterparty: userKey.toPublicKey().toString()
      }
      await expect(
        counterpartyWallet.verifySignature(verifySignatureArgs)
      ).rejects.toThrow()
    })
  })

  describe('revealCounterpartyKeyLinkage', () => {
    it('should reveal counterparty key linkage correctly', async () => {
      const proverKey = PrivateKey.fromRandom()
      const counterpartyKey = PrivateKey.fromRandom()
      const verifierKey = PrivateKey.fromRandom()

      const proverWallet = createTestWalletWire(
        new CompletedProtoWallet(proverKey)
      )
      const verifierWallet = createTestWalletWire(
        new CompletedProtoWallet(verifierKey)
      )

      const args = {
        counterparty: counterpartyKey.toPublicKey().toString(),
        verifier: verifierKey.toPublicKey().toString()
      }

      const revelation = await proverWallet.revealCounterpartyKeyLinkage(args)
      expect(revelation.encryptedLinkageProof).toBeDefined()

      const decryptArgs = {
        ciphertext: revelation.encryptedLinkage,
        protocolID: [2, 'counterparty linkage revelation'] as [
          0 | 1 | 2,
          string
        ],
        keyID: revelation.revelationTime,
        counterparty: proverKey.toPublicKey().toString()
      }
      const decryptedResult = await verifierWallet.decrypt(decryptArgs)

      const expectedLinkage = proverKey
        .deriveSharedSecret(counterpartyKey.toPublicKey())
        .encode(true)
      expect(decryptedResult.plaintext).toEqual(expectedLinkage)
    })
  })

  describe('acquireCertificate', () => {
    it('should acquire a certificate with valid inputs', async () => {
      // Mock the acquireCertificate method
      const acquireCertificateMock = jest.fn().mockResolvedValue({
        type: Utils.toBase64(new Array(32).fill(1)),
        subject: '02' + 'a'.repeat(64),
        serialNumber: Utils.toBase64(new Array(32).fill(2)),
        certifier: '02' + 'b'.repeat(64),
        revocationOutpoint:
          'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806.0',
        signature:
          '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
        fields: {
          field1: 'value1',
          field2: 'value2'
        }
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          acquireCertificate: acquireCertificateMock
        })
      )

      const args = {
        type: Utils.toBase64(new Array(32).fill(1)),
        certifier: '02' + 'b'.repeat(64),
        acquisitionProtocol: 'direct' as 'direct',
        fields: {
          field1: 'value1',
          field2: 'value2'
        },
        serialNumber: Utils.toBase64(new Array(32).fill(2)),
        revocationOutpoint:
          'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806.0',
        signature:
          '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
        keyringRevealer: 'certifier',
        keyringForSubject: {}
      }
      const result = await wallet.acquireCertificate(args)
      expect(result).toHaveProperty('type')
      expect(result).toHaveProperty('subject')
      expect(result).toHaveProperty('serialNumber')
      expect(result).toHaveProperty('certifier')
      expect(result).toHaveProperty('revocationOutpoint')
      expect(result).toHaveProperty('signature')
      expect(result).toHaveProperty('fields')
      expect(acquireCertificateMock).toHaveBeenCalledWith(args, '')
    })
    it('should acquire a certificate using acquisitionProtocol "direct" with keyringRevealer as "certifier"', async () => {
      // Mock the acquireCertificate method
      const acquireCertificateMock = jest.fn().mockResolvedValue({
        type: Utils.toBase64(new Array(32).fill(1)),
        subject: '02' + 'a'.repeat(64),
        serialNumber: Utils.toBase64(new Array(32).fill(2)),
        certifier: '02' + 'b'.repeat(64),
        revocationOutpoint:
          'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806.0',
        signature:
          '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
        fields: {
          field1: 'value1',
          field2: 'value2'
        }
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          acquireCertificate: acquireCertificateMock
        })
      )

      const args = {
        type: Utils.toBase64(new Array(32).fill(1)),
        certifier: '02' + 'b'.repeat(64),
        acquisitionProtocol: 'direct' as 'direct',
        fields: {
          field1: 'value1',
          field2: 'value2'
        },
        serialNumber: Utils.toBase64(new Array(32).fill(2)),
        revocationOutpoint:
          'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806.0',
        signature:
          '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
        keyringRevealer: 'certifier' as 'certifier',
        keyringForSubject: {
          field1: Utils.toBase64([0x01, 0x02, 0x03]),
          field2: Utils.toBase64([0x04, 0x05, 0x06])
        }
      }
      const result = await wallet.acquireCertificate(args)
      expect(result).toHaveProperty('type')
      expect(result).toHaveProperty('subject')
      expect(result).toHaveProperty('serialNumber')
      expect(result).toHaveProperty('certifier')
      expect(result).toHaveProperty('revocationOutpoint')
      expect(result).toHaveProperty('signature')
      expect(result).toHaveProperty('fields')
      expect(acquireCertificateMock).toHaveBeenCalledWith(args, '')
    })

    it('should acquire a certificate using acquisitionProtocol "direct" with keyringRevealer as PubKeyHex', async () => {
      // Mock the acquireCertificate method
      const acquireCertificateMock = jest.fn().mockResolvedValue({
        type: Utils.toBase64(new Array(32).fill(1)),
        subject: '02' + 'a'.repeat(64),
        serialNumber: Utils.toBase64(new Array(32).fill(2)),
        certifier: '02' + 'b'.repeat(64),
        revocationOutpoint:
          'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806.0',
        signature:
          '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
        fields: {
          field1: 'value1',
          field2: 'value2'
        }
      })
      const keyringRevealerPubKey = '02' + 'c'.repeat(64)
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          acquireCertificate: acquireCertificateMock
        })
      )

      const args = {
        type: Utils.toBase64(new Array(32).fill(1)),
        certifier: '02' + 'b'.repeat(64),
        acquisitionProtocol: 'direct' as 'direct',
        fields: {
          field1: 'value1',
          field2: 'value2'
        },
        serialNumber: Utils.toBase64(new Array(32).fill(2)),
        revocationOutpoint:
          'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806.0',
        signature:
          '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
        keyringRevealer: keyringRevealerPubKey,
        keyringForSubject: {
          field1: Utils.toBase64([0x01, 0x02, 0x03]),
          field2: Utils.toBase64([0x04, 0x05, 0x06])
        }
      }
      const result = await wallet.acquireCertificate(args)
      expect(result).toHaveProperty('type')
      expect(result).toHaveProperty('subject')
      expect(result).toHaveProperty('serialNumber')
      expect(result).toHaveProperty('certifier')
      expect(result).toHaveProperty('revocationOutpoint')
      expect(result).toHaveProperty('signature')
      expect(result).toHaveProperty('fields')
      expect(acquireCertificateMock).toHaveBeenCalledWith(args, '')
    })

    it('should acquire a certificate using acquisitionProtocol "issuance"', async () => {
      // Mock the acquireCertificate method
      const acquireCertificateMock = jest.fn().mockResolvedValue({
        type: Utils.toBase64(new Array(32).fill(1)),
        subject: '02' + 'd'.repeat(64),
        serialNumber: Utils.toBase64(new Array(32).fill(2)),
        certifier: '02' + 'b'.repeat(64),
        revocationOutpoint:
          'cafebabedeadbeefcafebabedeadbeefdeadbeefdeadbeefdeadbeefdeadbeef.1',
        signature:
          '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
        fields: {
          field3: 'value3',
          field4: 'value4'
        }
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          acquireCertificate: acquireCertificateMock
        })
      )

      const args = {
        type: Utils.toBase64(new Array(32).fill(1)),
        certifier: '02' + 'b'.repeat(64),
        acquisitionProtocol: 'issuance' as 'issuance',
        fields: {
          field3: 'value3',
          field4: 'value4'
        },
        certifierUrl: 'https://certifier.example.com/api/issue'
      }
      const result = await wallet.acquireCertificate(args)
      expect(result).toHaveProperty('type')
      expect(result).toHaveProperty('subject')
      expect(result).toHaveProperty('serialNumber')
      expect(result).toHaveProperty('certifier')
      expect(result).toHaveProperty('revocationOutpoint')
      expect(result).toHaveProperty('signature')
      expect(result).toHaveProperty('fields')
      expect(acquireCertificateMock).toHaveBeenCalledWith(args, '')
    })

    it('should handle optional keyringForSubject being empty in "direct" protocol', async () => {
      // Mock the acquireCertificate method
      const acquireCertificateMock = jest.fn().mockResolvedValue({
        type: Utils.toBase64(new Array(32).fill(1)),
        subject: '02' + 'e'.repeat(64),
        serialNumber: Utils.toBase64(new Array(32).fill(2)),
        certifier: '02' + 'b'.repeat(64),
        revocationOutpoint:
          'beadbeadbeadbeadbeadbeadbeadbeadbeadbeadbeadbeadbeadbeadbeadbead.2',
        signature:
          '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
        fields: {
          field5: 'value5'
        }
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          acquireCertificate: acquireCertificateMock
        })
      )

      const args = {
        type: Utils.toBase64(new Array(32).fill(1)),
        certifier: '02' + 'b'.repeat(64),
        acquisitionProtocol: 'direct' as 'direct',
        fields: {
          field5: 'value5'
        },
        serialNumber: Utils.toBase64(new Array(32).fill(2)),
        revocationOutpoint:
          'beadbeadbeadbeadbeadbeadbeadbeadbeadbeadbeadbeadbeadbeadbeadbead.2',
        signature:
          '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
        keyringRevealer: 'certifier' as 'certifier',
        keyringForSubject: {} // Empty keyring
      }
      const result = await wallet.acquireCertificate(args)
      expect(result).toHaveProperty('type')
      expect(result).toHaveProperty('subject')
      expect(result).toHaveProperty('serialNumber')
      expect(result).toHaveProperty('certifier')
      expect(result).toHaveProperty('revocationOutpoint')
      expect(result).toHaveProperty('signature')
      expect(result).toHaveProperty('fields')
      expect(result.fields).toEqual({ field5: 'value5' })
      expect(acquireCertificateMock).toHaveBeenCalledWith(args, '')
    })
  })

  describe('listCertificates', () => {
    it('should list certificates with valid inputs', async () => {
      // Mock the listCertificates method
      const listCertificatesMock = jest.fn().mockResolvedValue({
        totalCertificates: 1,
        certificates: [
          {
            type: Utils.toBase64(new Array(32).fill(1)),
            subject: '02' + 'a'.repeat(64),
            serialNumber: Utils.toBase64(new Array(32).fill(2)),
            certifier: '02' + 'b'.repeat(64),
            revocationOutpoint:
              'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806.0',
            signature:
              '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
            fields: {
              field1: 'value1',
              field2: 'value2'
            }
          }
        ]
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          listCertificates: listCertificatesMock
        })
      )

      const args = {
        certifiers: ['02' + 'b'.repeat(64)],
        types: [Utils.toBase64(new Array(32).fill(1))],
        limit: 10,
        offset: 0
      }
      const result = await wallet.listCertificates(args)
      expect(result).toHaveProperty('totalCertificates')
      expect(result).toHaveProperty('certificates')
      expect(Array.isArray(result.certificates)).toBe(true)
      expect(listCertificatesMock).toHaveBeenCalledWith(args, '')
    })
    it('should list certificates with multiple fields in each certificate', async () => {
      // Mock the listCertificates method
      const listCertificatesMock = jest.fn().mockResolvedValue({
        totalCertificates: 2,
        certificates: [
          {
            type: Utils.toBase64(new Array(32).fill(1)),
            subject: '02' + 'a'.repeat(64),
            serialNumber: Utils.toBase64(new Array(32).fill(2)),
            certifier: '02' + 'b'.repeat(64),
            revocationOutpoint:
              'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef.0',
            signature:
              '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
            fields: {
              field1: 'value1',
              field2: 'value2'
            }
          },
          {
            type: Utils.toBase64(new Array(32).fill(1)),
            subject: '02' + 'c'.repeat(64),
            serialNumber: Utils.toBase64(new Array(32).fill(2)),
            certifier: '02' + 'b'.repeat(64),
            revocationOutpoint:
              'cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe.1',
            signature:
              '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
            fields: {
              field3: 'value3',
              field4: 'value4',
              field5: 'value5'
            }
          }
        ]
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          listCertificates: listCertificatesMock
        })
      )

      const args = {
        certifiers: ['02' + 'b'.repeat(64)],
        types: [
          Utils.toBase64(new Array(32).fill(1)),
          Utils.toBase64(new Array(32).fill(2))
        ],
        limit: 10,
        offset: 0
      }
      const result = await wallet.listCertificates(args)
      expect(result).toHaveProperty('totalCertificates', 2)
      expect(result.certificates.length).toBe(2)
      expect(result.certificates[0].fields).toEqual({
        field1: 'value1',
        field2: 'value2'
      })
      expect(result.certificates[1].fields).toEqual({
        field3: 'value3',
        field4: 'value4',
        field5: 'value5'
      })
      expect(listCertificatesMock).toHaveBeenCalledWith(args, '')
    })

    it('should list certificates when privileged is true', async () => {
      // Mock the listCertificates method
      const listCertificatesMock = jest.fn().mockResolvedValue({
        totalCertificates: 1,
        certificates: [
          {
            type: Utils.toBase64(new Array(32).fill(1)),
            subject: '02' + 'd'.repeat(64),
            serialNumber: Utils.toBase64(new Array(32).fill(2)),
            certifier: '02' + 'e'.repeat(64),
            revocationOutpoint:
              'cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe.2',
            signature:
              '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
            fields: {
              field6: 'value6'
            }
          }
        ]
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          listCertificates: listCertificatesMock
        })
      )

      const args = {
        certifiers: ['02' + 'e'.repeat(64)],
        types: [Utils.toBase64(new Array(32).fill(1))],
        limit: 10,
        offset: 0,
        privileged: true,
        privilegedReason: 'Testing privileged access'
      }
      const result = await wallet.listCertificates(args)
      expect(result).toHaveProperty('totalCertificates', 1)
      expect(result.certificates[0].fields).toEqual({ field6: 'value6' })
      expect(listCertificatesMock).toHaveBeenCalledWith(args, '')
    })
  })

  describe('proveCertificate', () => {
    it('should prove a certificate with valid inputs', async () => {
      // Mock the proveCertificate method
      const proveCertificateMock = jest.fn().mockResolvedValue({
        keyringForVerifier: {
          field1: Utils.toBase64([0x01, 0x02, 0x03]),
          field2: Utils.toBase64([0x04, 0x05, 0x06])
        }
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          proveCertificate: proveCertificateMock
        })
      )

      const args = {
        certificate: {
          type: Utils.toBase64(new Array(32).fill(1)),
          subject: '02' + 'a'.repeat(64),
          serialNumber: Utils.toBase64(new Array(32).fill(2)),
          certifier: '02' + 'b'.repeat(64),
          revocationOutpoint:
            'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806.0',
          signature:
            '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
          fields: {
            field1: 'value1',
            field2: 'value2'
          }
        },
        fieldsToReveal: ['field1'],
        verifier: '02' + 'c'.repeat(64)
      }
      const result = await wallet.proveCertificate(args)
      expect(result).toHaveProperty('keyringForVerifier')
      expect(proveCertificateMock).toHaveBeenCalledWith(args, '')
    })
    it('should prove a certificate revealing multiple fields', async () => {
      // Mock the proveCertificate method
      const proveCertificateMock = jest.fn().mockResolvedValue({
        keyringForVerifier: {
          field1: Utils.toBase64([0x01, 0x02, 0x03]),
          field2: Utils.toBase64([0x04, 0x05, 0x06])
        }
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          proveCertificate: proveCertificateMock
        })
      )

      const args = {
        certificate: {
          type: Utils.toBase64(new Array(32).fill(1)),
          subject: '02' + 'a'.repeat(64),
          serialNumber: Utils.toBase64(new Array(32).fill(2)),
          certifier: '02' + 'b'.repeat(64),
          revocationOutpoint:
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef.0',
          signature:
            '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
          fields: {
            field1: 'value1',
            field2: 'value2',
            field3: 'value3'
          }
        },
        fieldsToReveal: ['field1', 'field2'],
        verifier: '02' + 'f'.repeat(64)
      }
      const result = await wallet.proveCertificate(args)
      expect(result).toHaveProperty('keyringForVerifier')
      expect(Object.keys(result.keyringForVerifier)).toEqual([
        'field1',
        'field2'
      ])
      expect(proveCertificateMock).toHaveBeenCalledWith(args, '')
    })

    it('should handle empty fieldsToReveal array (no fields revealed)', async () => {
      // Mock the proveCertificate method
      const proveCertificateMock = jest.fn().mockResolvedValue({
        keyringForVerifier: {}
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          proveCertificate: proveCertificateMock
        })
      )

      const args = {
        certificate: {
          type: Utils.toBase64(new Array(32).fill(1)),
          subject: '02' + 'a'.repeat(64),
          serialNumber: Utils.toBase64(new Array(32).fill(2)),
          certifier: '02' + 'b'.repeat(64),
          revocationOutpoint:
            'cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe.1',
          signature:
            '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
          fields: {
            field4: 'value4',
            field5: 'value5'
          }
        },
        fieldsToReveal: [],
        verifier: '02' + 'f'.repeat(64)
      }
      const result = await wallet.proveCertificate(args)
      expect(result).toHaveProperty('keyringForVerifier')
      expect(Object.keys(result.keyringForVerifier).length).toBe(0)
      expect(proveCertificateMock).toHaveBeenCalledWith(args, '')
    })
  })

  describe('relinquishCertificate', () => {
    it('should relinquish a certificate with valid inputs', async () => {
      // Mock the relinquishCertificate method
      const relinquishCertificateMock = jest
        .fn()
        .mockResolvedValue({ relinquished: true })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          relinquishCertificate: relinquishCertificateMock
        })
      )

      const args = {
        type: Utils.toBase64(new Array(32).fill(1)),
        serialNumber: Utils.toBase64(new Array(32).fill(2)),
        certifier: '02' + 'b'.repeat(64)
      }
      const result = await wallet.relinquishCertificate(args)
      expect(result).toEqual({ relinquished: true })
      expect(relinquishCertificateMock).toHaveBeenCalledWith(args, '')
    })
  })

  describe('getHeight and getHeaderForHeight', () => {
    it('should get the current blockchain height', async () => {
      // Mock the getHeight method
      const getHeightMock = jest.fn().mockResolvedValue({ height: 680000 })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          getHeight: getHeightMock
        })
      )

      const result = await wallet.getHeight({})
      expect(result).toHaveProperty('height')
      expect(typeof result.height).toBe('number')
      expect(result.height).toBeGreaterThan(0)
      expect(getHeightMock).toHaveBeenCalledWith({}, '')
    })

    it('should throw an error when getHeight fails', async () => {
      // Mock the getHeight method to throw an error
      const getHeightMock = jest
        .fn()
        .mockRejectedValue(new Error('Failed to get height'))
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          getHeight: getHeightMock
        })
      )
      await expect(wallet.getHeight({})).rejects.toThrow('Failed to get height')
      expect(getHeightMock).toHaveBeenCalledWith({}, '')
    })

    it('should get the header for a given height', async () => {
      // Mock the getHeaderForHeight method
      const getHeaderForHeightMock = jest.fn().mockResolvedValue({
        header: '00' + 'ff'.repeat(79)
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          getHeaderForHeight: getHeaderForHeightMock
        })
      )

      const args = { height: 680000 }
      const result = await wallet.getHeaderForHeight(args)
      expect(result).toHaveProperty('header')
      expect(typeof result.header).toBe('string')
      expect(result.header.length).toBe(80 * 2) // 80 bytes in hex
      expect(getHeaderForHeightMock).toHaveBeenCalledWith(args, '')
    })

    it('should throw an error when getHeaderForHeight fails', async () => {
      // Mock the getHeaderForHeight method to throw an error
      const getHeaderForHeightMock = jest
        .fn()
        .mockRejectedValue(new Error('Failed to get header'))
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          getHeaderForHeight: getHeaderForHeightMock
        })
      )
      const args = { height: -1 } // Invalid height
      await expect(wallet.getHeaderForHeight(args)).rejects.toThrow(
        'Failed to get header'
      )
      expect(getHeaderForHeightMock).toHaveBeenCalledWith(args, '')
    })
  })

  describe('discoverByIdentityKey', () => {
    it('should discover certificates by identity key with valid inputs', async () => {
      // Mock the discoverByIdentityKey method
      const discoverByIdentityKeyMock = jest.fn().mockResolvedValue({
        totalCertificates: 1,
        certificates: [
          {
            type: Utils.toBase64(new Array(32).fill(1)),
            subject: '02' + 'a'.repeat(64),
            serialNumber: Utils.toBase64(new Array(32).fill(2)),
            certifier: '02' + 'b'.repeat(64),
            revocationOutpoint:
              'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806.0',
            signature:
              '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
            fields: {},
            certifierInfo: {
              name: 'Test Certifier',
              iconUrl: 'https://example.com/icon.png',
              description: 'Test description',
              trust: 5
            },
            publiclyRevealedKeyring: {},
            decryptedFields: {}
          }
        ]
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          discoverByIdentityKey: discoverByIdentityKeyMock
        })
      )

      const args = {
        identityKey: '02' + 'a'.repeat(64),
        limit: 10,
        offset: 0
      }
      const result = await wallet.discoverByIdentityKey(args)
      expect(result).toHaveProperty('totalCertificates')
      expect(result).toHaveProperty('certificates')
      expect(Array.isArray(result.certificates)).toBe(true)
      expect(discoverByIdentityKeyMock).toHaveBeenCalledWith(args, '')
    })
    it('should discover certificates with empty decryptedFields and publiclyRevealedKeyring', async () => {
      // Mock the discoverByIdentityKey method
      const discoverByIdentityKeyMock = jest.fn().mockResolvedValue({
        totalCertificates: 1,
        certificates: [
          {
            type: Utils.toBase64(new Array(32).fill(1)),
            subject: '02' + 'a'.repeat(64),
            serialNumber: Utils.toBase64(new Array(32).fill(2)),
            certifier: '02' + 'b'.repeat(64),
            revocationOutpoint:
              'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef.0',
            signature:
              '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
            fields: {},
            certifierInfo: {
              name: 'Test Certifier',
              iconUrl: 'https://example.com/icon.png',
              description: 'Test description',
              trust: 5
            },
            publiclyRevealedKeyring: {},
            decryptedFields: {}
          }
        ]
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          discoverByIdentityKey: discoverByIdentityKeyMock
        })
      )

      const args = {
        identityKey: '02' + 'a'.repeat(64),
        limit: 10,
        offset: 0
      }
      const result = await wallet.discoverByIdentityKey(args)
      expect(result).toHaveProperty('totalCertificates')
      expect(result.certificates.length).toBe(1)
      expect(result.certificates[0].publiclyRevealedKeyring).toEqual({})
      expect(result.certificates[0].decryptedFields).toEqual({})
      expect(discoverByIdentityKeyMock).toHaveBeenCalledWith(args, '')
    })

    it('should discover multiple certificates with varying fields', async () => {
      // Mock the discoverByIdentityKey method
      const discoverByIdentityKeyMock = jest.fn().mockResolvedValue({
        totalCertificates: 2,
        certificates: [
          {
            type: Utils.toBase64(new Array(32).fill(1)),
            subject: '02' + 'a'.repeat(64),
            serialNumber: Utils.toBase64(new Array(32).fill(2)),
            certifier: '02' + 'b'.repeat(64),
            revocationOutpoint:
              'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef.0',
            signature:
              '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
            fields: {},
            certifierInfo: {
              name: 'Certifier One',
              iconUrl: 'https://example.com/icon1.png',
              description: 'First certifier',
              trust: 5
            },
            publiclyRevealedKeyring: {
              field1: Utils.toBase64([0x01])
            },
            decryptedFields: {
              fieldA: 'decryptedValueA'
            }
          },
          {
            type: Utils.toBase64(new Array(32).fill(1)),
            subject: '02' + 'a'.repeat(64),
            serialNumber: Utils.toBase64(new Array(32).fill(2)),
            certifier: '02' + 'c'.repeat(64),
            revocationOutpoint:
              'cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe.1',
            signature:
              '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
            fields: {},
            certifierInfo: {
              name: 'Certifier Two',
              iconUrl: 'https://example.com/icon2.png',
              description: 'Second certifier',
              trust: 7
            },
            publiclyRevealedKeyring: {},
            decryptedFields: {
              fieldB: 'decryptedValueB',
              fieldC: 'decryptedValueC'
            }
          }
        ]
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          discoverByIdentityKey: discoverByIdentityKeyMock
        })
      )

      const args = {
        identityKey: '02' + 'a'.repeat(64),
        limit: 10,
        offset: 0
      }
      const result = await wallet.discoverByIdentityKey(args)
      expect(result).toHaveProperty('totalCertificates', 2)
      expect(result.certificates.length).toBe(2)
      expect(result.certificates[0].certifierInfo.name).toBe('Certifier One')
      expect(result.certificates[1].certifierInfo.name).toBe('Certifier Two')
      expect(discoverByIdentityKeyMock).toHaveBeenCalledWith(args, '')
    })
  })

  describe('discoverByAttributes', () => {
    it('should discover certificates by attributes with valid inputs', async () => {
      // Mock the discoverByAttributes method
      const discoverByAttributesMock = jest.fn().mockResolvedValue({
        totalCertificates: 1,
        certificates: [
          {
            type: Utils.toBase64(new Array(32).fill(1)),
            subject: '02' + 'a'.repeat(64),
            serialNumber: Utils.toBase64(new Array(32).fill(2)),
            certifier: '02' + 'b'.repeat(64),
            revocationOutpoint:
              'deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806.0',
            signature:
              '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
            fields: {},
            certifierInfo: {
              name: 'Test Certifier',
              iconUrl: 'https://example.com/icon.png',
              description: 'Test description',
              trust: 5
            },
            publiclyRevealedKeyring: {},
            decryptedFields: {}
          }
        ]
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          discoverByAttributes: discoverByAttributesMock
        })
      )

      const args = {
        attributes: {
          field1: 'value1'
        },
        limit: 10,
        offset: 0
      }
      const result = await wallet.discoverByAttributes(args)
      expect(result).toHaveProperty('totalCertificates')
      expect(result).toHaveProperty('certificates')
      expect(Array.isArray(result.certificates)).toBe(true)
      expect(discoverByAttributesMock).toHaveBeenCalledWith(args, '')
    })

    it('should throw an error with invalid inputs', async () => {
      // Mock the discoverByAttributes method to throw an error
      const discoverByAttributesMock = jest
        .fn()
        .mockRejectedValue(new Error('Invalid inputs'))
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          discoverByAttributes: discoverByAttributesMock
        })
      )
      const args = {
        attributes: {}
      }
      await expect(wallet.discoverByAttributes(args)).rejects.toThrow(
        'Invalid inputs'
      )
      expect(discoverByAttributesMock).toHaveBeenCalledWith(args, '')
    })
    it('should discover certificates matching provided attributes', async () => {
      // Mock the discoverByAttributes method
      const discoverByAttributesMock = jest.fn().mockResolvedValue({
        totalCertificates: 1,
        certificates: [
          {
            type: Utils.toBase64(new Array(32).fill(1)),
            subject: '02' + 'd'.repeat(64),
            serialNumber: Utils.toBase64(new Array(32).fill(2)),
            certifier: '02' + 'e'.repeat(64),
            revocationOutpoint:
              'beadbeadbeadbeadbeadbeadbeadbeadbeadbeadbeadbeadbeadbeadbeadbead.2',
            signature:
              '3045022100e4d03d959697ed191f9ef7ae7deacd3118b8693d18da0fd76e4ad92664ce05cf02200d753951e766cbf2d2b306e08921c06341d2de67ab75389bf84caf954ee40e88',
            fields: {},
            certifierInfo: {
              name: 'Certifier Three',
              iconUrl: 'https://example.com/icon3.png',
              description: 'Third certifier',
              trust: 8
            },
            publiclyRevealedKeyring: {
              fieldX: Utils.toBase64([0x0a, 0x0b])
            },
            decryptedFields: {
              fieldY: 'decryptedValueY'
            }
          }
        ]
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          discoverByAttributes: discoverByAttributesMock
        })
      )

      const args = {
        attributes: {
          fieldY: 'decryptedValueY'
        },
        limit: 5,
        offset: 0
      }
      const result = await wallet.discoverByAttributes(args)
      expect(result).toHaveProperty('totalCertificates', 1)
      expect(result.certificates.length).toBe(1)
      expect(result.certificates[0].certifierInfo.name).toBe('Certifier Three')
      expect(result.certificates[0].decryptedFields.fieldY).toBe(
        'decryptedValueY'
      )
      expect(discoverByAttributesMock).toHaveBeenCalledWith(args, '')
    })

    it('should return empty certificates array when no matches found', async () => {
      // Mock the discoverByAttributes method
      const discoverByAttributesMock = jest.fn().mockResolvedValue({
        totalCertificates: 0,
        certificates: []
      })
      const wallet = createTestWalletWire(
        mockUnsupportedMethods({
          discoverByAttributes: discoverByAttributesMock
        })
      )

      const args = {
        attributes: {
          nonExistentField: 'noValue'
        },
        limit: 5,
        offset: 0
      }
      const result = await wallet.discoverByAttributes(args)
      expect(result).toHaveProperty('totalCertificates', 0)
      expect(result.certificates.length).toBe(0)
      expect(discoverByAttributesMock).toHaveBeenCalledWith(args, '')
    })
  })
})
