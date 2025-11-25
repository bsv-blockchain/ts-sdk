import { Certificate } from '../../../auth/index'
import { CompletedProtoWallet } from '../../../auth/certificates/__tests/CompletedProtoWallet'
import { Utils, PrivateKey } from '../../../primitives/index'

describe('Certificate', () => {
  // Sample data for testing
  const sampleType = Utils.toBase64(new Array(32).fill(1))
  const sampleSerialNumber = Utils.toBase64(new Array(32).fill(2))
  const sampleSubjectPrivateKey = PrivateKey.fromRandom()
  const sampleSubjectPubKey = sampleSubjectPrivateKey.toPublicKey().toString()
  const sampleCertifierPrivateKey = PrivateKey.fromRandom()
  const sampleCertifierPubKey = sampleCertifierPrivateKey
    .toPublicKey()
    .toString()
  const sampleRevocationOutpoint =
    'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef.1'
  const sampleFields = {
    name: 'Alice',
    email: 'alice@example.com',
    organization: 'Example Corp'
  }
  const sampleFieldsEmpty = {}

  it('should construct a Certificate with valid data', () => {
    const certificate = new Certificate(
      sampleType,
      sampleSerialNumber,
      sampleSubjectPubKey,
      sampleCertifierPubKey,
      sampleRevocationOutpoint,
      sampleFields,
      undefined // No signature
    )

    expect(certificate.type).toEqual(sampleType)
    expect(certificate.serialNumber).toEqual(sampleSerialNumber)
    expect(certificate.subject).toEqual(sampleSubjectPubKey)
    expect(certificate.certifier).toEqual(sampleCertifierPubKey)
    expect(certificate.revocationOutpoint).toEqual(sampleRevocationOutpoint)
    expect(certificate.signature).toBeUndefined()
    expect(certificate.fields).toEqual(sampleFields)
  })

  it('should serialize and deserialize the Certificate without signature', () => {
    const certificate = new Certificate(
      sampleType,
      sampleSerialNumber,
      sampleSubjectPubKey,
      sampleCertifierPubKey,
      sampleRevocationOutpoint,
      sampleFields,
      undefined // No signature
    )

    const serialized = certificate.toBinary(false) // Exclude signature
    const deserializedCertificate = Certificate.fromBinary(serialized)

    expect(deserializedCertificate.type).toEqual(sampleType)
    expect(deserializedCertificate.serialNumber).toEqual(sampleSerialNumber)
    expect(deserializedCertificate.subject).toEqual(sampleSubjectPubKey)
    expect(deserializedCertificate.certifier).toEqual(sampleCertifierPubKey)
    expect(deserializedCertificate.revocationOutpoint).toEqual(
      sampleRevocationOutpoint
    )
    expect(deserializedCertificate.signature).toBeUndefined()
    expect(deserializedCertificate.fields).toEqual(sampleFields)
  })

  it('should serialize and deserialize the Certificate with signature', async () => {
    const certificate = new Certificate(
      sampleType,
      sampleSerialNumber,
      sampleSubjectPubKey,
      sampleCertifierPubKey,
      sampleRevocationOutpoint,
      sampleFields,
      undefined // No signature
    )

    // Sign the certificate
    const certifierWallet = new CompletedProtoWallet(sampleCertifierPrivateKey)
    await certificate.sign(certifierWallet)

    const serialized = certificate.toBinary(true) // Include signature
    const deserializedCertificate = Certificate.fromBinary(serialized)

    expect(deserializedCertificate.type).toEqual(sampleType)
    expect(deserializedCertificate.serialNumber).toEqual(sampleSerialNumber)
    expect(deserializedCertificate.subject).toEqual(sampleSubjectPubKey)
    expect(deserializedCertificate.certifier).toEqual(sampleCertifierPubKey)
    expect(deserializedCertificate.revocationOutpoint).toEqual(
      sampleRevocationOutpoint
    )
    expect(deserializedCertificate.signature).toEqual(certificate.signature)
    expect(deserializedCertificate.fields).toEqual(sampleFields)
  })

  it('should sign the Certificate and verify the signature successfully', async () => {
    const certificate = new Certificate(
      sampleType,
      sampleSerialNumber,
      sampleSubjectPubKey,
      sampleCertifierPubKey,
      sampleRevocationOutpoint,
      sampleFields,
      undefined // No signature
    )

    // Sign the certificate
    const certifierWallet = new CompletedProtoWallet(sampleCertifierPrivateKey)
    await certificate.sign(certifierWallet)

    // Verify the signature
    const isValid = await certificate.verify()
    expect(isValid).toBe(true)
  })

  it('should fail verification if the Certificate is tampered with', async () => {
    const certificate = new Certificate(
      sampleType,
      sampleSerialNumber,
      sampleSubjectPubKey,
      sampleCertifierPubKey,
      sampleRevocationOutpoint,
      sampleFields,
      undefined // No signature
    )

    // Sign the certificate
    const certifierWallet = new CompletedProtoWallet(sampleCertifierPrivateKey)
    await certificate.sign(certifierWallet)

    // Tamper with the certificate (modify a field)
    certificate.fields.email = 'attacker@example.com'

    // Verify the signature
    await expect(certificate.verify()).rejects.toThrow()
  })

  it('should fail verification if the signature is missing', async () => {
    const certificate = new Certificate(
      sampleType,
      sampleSerialNumber,
      sampleSubjectPubKey,
      sampleCertifierPubKey,
      sampleRevocationOutpoint,
      sampleFields,
      undefined // No signature
    )

    // Verify the signature
    await expect(certificate.verify()).rejects.toThrow()
  })

  it('should fail verification if the signature is incorrect', async () => {
    const certificate = new Certificate(
      sampleType,
      sampleSerialNumber,
      sampleSubjectPubKey,
      sampleCertifierPubKey,
      sampleRevocationOutpoint,
      sampleFields,
      '3045022100cde229279465bb91992ccbc30bf6ed4eb8cdd9d517f31b30ff778d500d5400010220134f0e4065984f8668a642a5ad7a80886265f6aaa56d215d6400c216a4802177' // Incorrect signature
    )

    // Verify the signature
    await expect(
      certificate.verify()
    ).rejects.toThrowErrorMatchingInlineSnapshot('"Signature is not valid"')
  })

  it('should handle certificates with empty fields', async () => {
    const certificate = new Certificate(
      sampleType,
      sampleSerialNumber,
      sampleSubjectPubKey,
      sampleCertifierPubKey,
      sampleRevocationOutpoint,
      sampleFieldsEmpty,
      undefined // No signature
    )

    // Sign the certificate
    const certifierWallet = new CompletedProtoWallet(sampleCertifierPrivateKey)
    await certificate.sign(certifierWallet)

    // Serialize and deserialize
    const serialized = certificate.toBinary(true)
    const deserializedCertificate = Certificate.fromBinary(serialized)

    expect(deserializedCertificate.fields).toEqual(sampleFieldsEmpty)

    // Verify the signature
    const isValid = await deserializedCertificate.verify()
    expect(isValid).toBe(true)
  })

  it('should correctly handle serialization/deserialization when signature is excluded', () => {
    const certificate = new Certificate(
      sampleType,
      sampleSerialNumber,
      sampleSubjectPubKey,
      sampleCertifierPubKey,
      sampleRevocationOutpoint,
      sampleFields,
      'deadbeef1234' // Placeholder signature
    )

    // Serialize without signature
    const serialized = certificate.toBinary(false)
    const deserializedCertificate = Certificate.fromBinary(serialized)

    expect(deserializedCertificate.signature).toBeUndefined() // Signature should be empty
    expect(deserializedCertificate.fields).toEqual(sampleFields)
  })

  it('should correctly handle certificates with long field names and values', async () => {
    const longFieldName = 'longFieldName_'.repeat(10) // ✅ Removed `as any`
    const longFieldValue = 'longFieldValue_'.repeat(20)

    const fields: Record<string, string> = { // ✅ Explicitly type `fields`
      [longFieldName]: longFieldValue
    }

    const certificate = new Certificate(
      sampleType,
      sampleSerialNumber,
      sampleSubjectPubKey,
      sampleCertifierPubKey,
      sampleRevocationOutpoint,
      fields,
      undefined // No signature
    )

    // Sign the certificate
    const certifierWallet = new CompletedProtoWallet(sampleCertifierPrivateKey)
    await certificate.sign(certifierWallet)

    // Serialize and deserialize
    const serialized = certificate.toBinary(true)
    const deserializedCertificate = Certificate.fromBinary(serialized)

    expect(deserializedCertificate.fields).toEqual(fields)

    // Verify the signature
    const isValid = await deserializedCertificate.verify()
    expect(isValid).toBe(true)
  })

  it('should correctly serialize and deserialize the revocationOutpoint', () => {
    const certificate = new Certificate(
      sampleType,
      sampleSerialNumber,
      sampleSubjectPubKey,
      sampleCertifierPubKey,
      sampleRevocationOutpoint,
      sampleFields,
      undefined // No signature
    )

    const serialized = certificate.toBinary(false)
    const deserializedCertificate = Certificate.fromBinary(serialized)

    expect(deserializedCertificate.revocationOutpoint).toEqual(
      sampleRevocationOutpoint
    )
  })

  it('should correctly handle certificates with no fields', async () => {
    const certificate = new Certificate(
      sampleType,
      sampleSerialNumber,
      sampleSubjectPubKey,
      sampleCertifierPubKey,
      sampleRevocationOutpoint,
      {}, // No fields
      undefined // No signature
    )

    // Sign the certificate
    const certifierWallet = new CompletedProtoWallet(sampleCertifierPrivateKey)
    await certificate.sign(certifierWallet)

    // Serialize and deserialize
    const serialized = certificate.toBinary(true)
    const deserializedCertificate = Certificate.fromBinary(serialized)

    expect(deserializedCertificate.fields).toEqual({})

    // Verify the signature
    const isValid = await deserializedCertificate.verify()
    expect(isValid).toBe(true)
  })

  it("should throw if already signed, and should update the certifier field if it differs from the wallet's public key", async () => {
    // Scenario 1: Certificate already has a signature
    const preSignedCertificate = new Certificate(
      sampleType,
      sampleSerialNumber,
      sampleSubjectPubKey,
      sampleCertifierPubKey, // We'll pretend this was signed by them
      sampleRevocationOutpoint,
      sampleFields,
      'deadbeef' // Already has a placeholder signature
    )
    const certifierWallet = new CompletedProtoWallet(sampleCertifierPrivateKey)

    // Trying to sign again should throw
    await expect(preSignedCertificate.sign(certifierWallet)).rejects.toThrow(
      'Certificate has already been signed!'
    )

    // Scenario 2: The certifier property is set to something different from the wallet's public key
    const mismatchedCertifierPubKey = PrivateKey.fromRandom()
      .toPublicKey()
      .toString()
    const certificateWithMismatch = new Certificate(
      sampleType,
      sampleSerialNumber,
      sampleSubjectPubKey,
      mismatchedCertifierPubKey, // Different from actual wallet key
      sampleRevocationOutpoint,
      sampleFields
    )

    // Sign the certificate; it should automatically update
    // the certifier field to match the wallet's actual public key
    const certifierPubKey = (
      await certifierWallet.getPublicKey({ identityKey: true })
    ).publicKey
    await certificateWithMismatch.sign(certifierWallet)
    expect(certificateWithMismatch.certifier).toBe(certifierPubKey)
    expect(await certificateWithMismatch.verify()).toBe(true)
  })

  it('should create a Certificate from an object using fromObject()', () => {
    const certificateObject = {
      type: 'Q29tbW9uU291cmNlIGlkZW50aXR5',
      subject: '028e2e075e1e57ba4c62c90125468109f9b4e2a7741da3dd76ccd0c73b2a8a37ad',
      serialNumber: 'UegX3uufsqHsbEKeBSxUd9AziLSyru86TnwfhPoZJYE=',
      certifier: '03c644fe2fd97673a5d86555a58587e7936390be6582ece262bc387014bcff6fe4',
      revocationOutpoint: '0245242bd144a85053b4c1e4a0ed5467c79a4d172680ca77a970ebabd682d564.0',
      signature: '304402202c86ef816c469fe657289ddea12d2c444f006ef5ab5851f00107c7724eb67ea602202786244c077567c8f3ec5da78bd61ce0c35bf1eeac0488e026c03b21c403b0fd',
      fields: {
        displayName: 'eqsSpUgTKk891y1EkyCPPg+C4YoVZJvB0EQ4iore7VofkM5TB9Ctj7x2PgBaWI0A9tfATDO9',
        email: 'n6HVUvyHkIDMvB4ERxVGxmX6lgRBM+e7kbbC5DiRCKe5a60BJeXr05g4POq6OHYO9Wl/b1Xxe+JKsejl',
        phoneNumber: '5yWyN9kOGaZs5G6yvXUWnWj4rm7kDAug4YIsn4BQLKGYRzDx8s1dytb43ega6BnSp0gUTnskcjiM8ekqul2a',
        lat: 'lc3u6SFKQ5Mpxp5vc+6s4aXe7lOyQQLfN+CbOu4XlBYsj7Jlc78gt4sGCwDSxbzvA41eElCjlc2Our5bpLcsg1I6',
        lng: 'FmY3iM/2/LDfYNEeXpcj7Epn933tRHz50WoBkBrqYv6jmZ6dXE6RRYId9TcaxIvB0D7Y14aD5vjSV6Bx48hdic5g'
      }
    }

    const certificate = Certificate.fromObject(certificateObject)

    expect(certificate.type).toEqual(certificateObject.type)
    expect(certificate.serialNumber).toEqual(certificateObject.serialNumber)
    expect(certificate.subject).toEqual(certificateObject.subject)
    expect(certificate.certifier).toEqual(certificateObject.certifier)
    expect(certificate.revocationOutpoint).toEqual(certificateObject.revocationOutpoint)
    expect(certificate.signature).toEqual(certificateObject.signature)
    expect(certificate.fields).toEqual(certificateObject.fields)
  })

  it('should create a Certificate from an object without signature using fromObject()', () => {
    const certificateObject = {
      type: 'Q29tbW9uU291cmNlIGlkZW50aXR5',
      subject: '028e2e075e1e57ba4c62c90125468109f9b4e2a7741da3dd76ccd0c73b2a8a37ad',
      serialNumber: 'UegX3uufsqHsbEKeBSxUd9AziLSyru86TnwfhPoZJYE=',
      certifier: '03c644fe2fd97673a5d86555a58587e7936390be6582ece262bc387014bcff6fe4',
      revocationOutpoint: '0245242bd144a85053b4c1e4a0ed5467c79a4d172680ca77a970ebabd682d564.0',
      fields: {
        displayName: 'eqsSpUgTKk891y1EkyCPPg+C4YoVZJvB0EQ4iore7VofkM5TB9Ctj7x2PgBaWI0A9tfATDO9'
      }
    }

    const certificate = Certificate.fromObject(certificateObject)

    expect(certificate.type).toEqual(certificateObject.type)
    expect(certificate.serialNumber).toEqual(certificateObject.serialNumber)
    expect(certificate.subject).toEqual(certificateObject.subject)
    expect(certificate.certifier).toEqual(certificateObject.certifier)
    expect(certificate.revocationOutpoint).toEqual(certificateObject.revocationOutpoint)
    expect(certificate.signature).toBeUndefined()
    expect(certificate.fields).toEqual(certificateObject.fields)
  })
})
