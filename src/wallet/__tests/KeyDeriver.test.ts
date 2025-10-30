import {
  PrivateKey,
  PublicKey,
  SymmetricKey,
  Utils,
  Hash
} from '../../primitives/index'
import KeyDeriver from '../../wallet/KeyDeriver'

describe('KeyDeriver', () => {
  const rootPrivateKey = new PrivateKey(42)
  const rootPublicKey = rootPrivateKey.toPublicKey()
  const counterpartyPrivateKey = new PrivateKey(69)
  const counterpartyPublicKey = counterpartyPrivateKey.toPublicKey()
  const anyonePublicKey = new PrivateKey(1).toPublicKey()

  const protocolID: [0 | 1 | 2, string] = [0, 'testprotocol']
  const keyID = '12345'

  let keyDeriver: KeyDeriver

  beforeEach(() => {
    keyDeriver = new KeyDeriver(rootPrivateKey)
  })

  test('should compute the correct invoice number', () => {
    const invoiceNumber = (keyDeriver as any).computeInvoiceNumber(
      protocolID,
      keyID
    )
    expect(invoiceNumber).toBe('0-testprotocol-12345')
  })

  test('should throw if no co counterparty given', () => {
    expect(() => (keyDeriver as any).normalizeCounterparty()).toThrow()
  })

  test('should normalize counterparty correctly for self', () => {
    const normalized = (keyDeriver as any).normalizeCounterparty('self')
    expect(normalized.toString()).toBe(rootPublicKey.toString())
  })

  test('should normalize counterparty correctly for anyone', () => {
    const normalized = (keyDeriver as any).normalizeCounterparty('anyone')
    expect(normalized.toString()).toBe(anyonePublicKey.toString())
  })

  test('should normalize counterparty correctly when given as a hex string', () => {
    const normalized = (keyDeriver as any).normalizeCounterparty(
      counterpartyPublicKey.toString()
    )
    expect(normalized.toString()).toBe(counterpartyPublicKey.toString())
  })

  test('should normalize counterparty correctly when given as a public key', () => {
    const normalized = (keyDeriver as any).normalizeCounterparty(
      counterpartyPublicKey
    )
    expect(normalized.toString()).toBe(counterpartyPublicKey.toString())
  })

  test('should allow public key derivation as anyone', () => {
    const anyoneDeriver = new KeyDeriver('anyone')
    const derivedPublicKey = anyoneDeriver.derivePublicKey(
      protocolID,
      keyID,
      counterpartyPublicKey
    )
    expect(derivedPublicKey).toBeInstanceOf(PublicKey)
    expect(derivedPublicKey.toString()).toEqual(
      counterpartyPublicKey
        .deriveChild(new PrivateKey(1), '0-testprotocol-12345')
        .toString()
    )
  })

  test('should derive the correct public key for counterparty', () => {
    const derivedPublicKey = keyDeriver.derivePublicKey(
      protocolID,
      keyID,
      counterpartyPublicKey
    )
    expect(derivedPublicKey).toBeInstanceOf(PublicKey)
    expect(derivedPublicKey.toString()).toEqual(
      counterpartyPublicKey
        .deriveChild(rootPrivateKey, '0-testprotocol-12345')
        .toString()
    )
  })

  test('should derive the correct public key for self', () => {
    const derivedPublicKey = keyDeriver.derivePublicKey(
      protocolID,
      keyID,
      counterpartyPublicKey,
      true
    )
    expect(derivedPublicKey).toBeInstanceOf(PublicKey)
    expect(derivedPublicKey.toString()).toEqual(
      rootPrivateKey
        .deriveChild(counterpartyPublicKey, '0-testprotocol-12345')
        .toPublicKey()
        .toString()
    )
  })

  test('should derive the correct private key', () => {
    const derivedPrivateKey = keyDeriver.derivePrivateKey(
      protocolID,
      keyID,
      counterpartyPublicKey
    )
    expect(derivedPrivateKey).toBeInstanceOf(PrivateKey)
    expect(derivedPrivateKey.toString()).toEqual(
      rootPrivateKey
        .deriveChild(counterpartyPublicKey, '0-testprotocol-12345')
        .toString()
    )
  })

  test('should derive the correct symmetric key using HKDF', () => {
    const derivedSymmetricKey = keyDeriver.deriveSymmetricKey(
      protocolID,
      keyID,
      counterpartyPublicKey
    )
    expect(derivedSymmetricKey).toBeInstanceOf(SymmetricKey)
    
    // Verify the key was derived using HKDF
    const priv = rootPrivateKey.deriveChild(
      counterpartyPublicKey,
      '0-testprotocol-12345'
    )
    const pub = counterpartyPublicKey.deriveChild(
      rootPrivateKey,
      '0-testprotocol-12345'
    )
    const sharedSecret = priv.deriveSharedSecret(pub)
    const ikm = sharedSecret.x?.toArray()
    const info = Utils.toArray('0-testprotocol-12345', 'utf8')
    const expectedKey = Hash.hkdf(ikm ?? [], 32, undefined, info)
    
    expect(derivedSymmetricKey.toHex()).toEqual(
      new SymmetricKey(expectedKey).toHex()
    )
  })

  test('should be able to derive symmetric key with anyone', () => {
    expect(() =>
      keyDeriver.deriveSymmetricKey(protocolID, keyID, 'anyone')
    ).not.toThrow()
  })

  test('should reveal the correct counterparty shared secret', () => {
    const sharedSecret = keyDeriver.revealCounterpartySecret(
      counterpartyPublicKey
    )
    expect(sharedSecret).toBeInstanceOf(Array)
    expect(sharedSecret.length).toBeGreaterThan(0)
    expect(sharedSecret).toEqual(
      rootPrivateKey.deriveSharedSecret(counterpartyPublicKey).encode(true)
    )
  })

  test('should not reveal shared secret for self', () => {
    expect(() => keyDeriver.revealCounterpartySecret('self')).toThrow()
    expect(() => keyDeriver.revealCounterpartySecret(rootPublicKey)).toThrow()
  })

  test('should reveal the specific key association', () => {
    const specificSecret = keyDeriver.revealSpecificSecret(
      counterpartyPublicKey,
      protocolID,
      keyID
    )
    expect(specificSecret).toBeInstanceOf(Array)
    expect(specificSecret.length).toBeGreaterThan(0)
    const sharedSecret = rootPrivateKey.deriveSharedSecret(
      counterpartyPublicKey
    )
    const invoiceNumberBin = Utils.toArray(
      (keyDeriver as any).computeInvoiceNumber(protocolID, keyID),
      'utf8'
    )
    expect(specificSecret).toEqual(
      Hash.sha256hmac(sharedSecret.encode(true), invoiceNumberBin)
    )
  })

  test('should throw an error for invalid protocol names', () => {
    expect(() =>
      (keyDeriver as any).computeInvoiceNumber(
        protocolID,
        'long' + 'a'.repeat(800)
      )
    ).toThrow()
    expect(() =>
      (keyDeriver as any).computeInvoiceNumber(protocolID, '')
    ).toThrow()
    expect(() =>
      (keyDeriver as any).computeInvoiceNumber([-3, 'otherwise valid'], keyID)
    ).toThrow()
    expect(() =>
      (keyDeriver as any).computeInvoiceNumber([2, 'double  space'], keyID)
    ).toThrow()
    expect(() =>
      (keyDeriver as any).computeInvoiceNumber([0, ''], keyID)
    ).toThrow()
    expect(() =>
      (keyDeriver as any).computeInvoiceNumber([0, ' a'], keyID)
    ).toThrow()
    expect(() =>
      (keyDeriver as any).computeInvoiceNumber(
        [0, 'long' + 'a'.repeat(400)],
        keyID
      )
    ).toThrow()
    expect(() =>
      (keyDeriver as any).computeInvoiceNumber(
        [2, 'redundant protocol protocol'],
        keyID
      )
    ).toThrow()
    expect(() =>
      (keyDeriver as any).computeInvoiceNumber([2, 'üñî√é®sål ©0på'], keyID)
    ).toThrow()
  })
})
