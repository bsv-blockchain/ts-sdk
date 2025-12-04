import { MasterCertificate } from '../../../auth/certificates/MasterCertificate'
import { VerifiableCertificate } from '../../../auth/certificates/VerifiableCertificate'
import { PrivateKey, SymmetricKey, Utils, Random } from '../../../../mod'
import { CompletedProtoWallet } from '../../../auth/certificates/__tests/CompletedProtoWallet'

const subjectPrivateKey = new PrivateKey(21)
const certifierPrivateKey = new PrivateKey(22)

const fieldSymFixed1 = new SymmetricKey(51)
const fieldSymWrong = new SymmetricKey(61)

const subjectKey2 = new PrivateKey(71)
const verifierKey2 = new PrivateKey(81)

// A mock revocation outpoint for testing
const mockRevocationOutpoint =
  'deadbeefdeadbeefdeadbeefdeadbeef00000001'


// Arbitrary certificate data (in plaintext)
const plaintextFields = {
  name: 'Alice',
  email: 'alice@example.com',
  department: 'Engineering'
}

const subjectWallet = new CompletedProtoWallet(subjectPrivateKey)
const certifierWallet = new CompletedProtoWallet(certifierPrivateKey)

describe('MasterCertificate', () => {
  let subjectIdentityKey: string
  let certifierIdentityKey: string

  beforeAll(async () => {
    subjectIdentityKey = (
      await subjectWallet.getPublicKey({ identityKey: true })
    ).publicKey
    certifierIdentityKey = (
      await certifierWallet.getPublicKey({ identityKey: true })
    ).publicKey
  })

  describe('constructor', () => {
    it('should construct a MasterCertificate successfully when masterKeyring is valid', () => {
      // Prepare a minimal valid MasterCertificate
      const fieldSymKey = fieldSymFixed1
      const encryptedFieldValue = Utils.toBase64(
        fieldSymKey.encrypt(Utils.toArray('Alice', 'utf8')) as number[]
      )

      const encryptedKeyForSubject = Utils.toBase64([0, 1, 2, 3])
      // We assume we have the same fieldName in both `fields` and `masterKeyring`.
      const fields = { name: encryptedFieldValue }
      const masterKeyring = { name: encryptedKeyForSubject }

      const certificate = new MasterCertificate(
        Utils.toBase64(Random(16)), // type
        Utils.toBase64(Random(16)), // serialNumber
        subjectIdentityKey,
        certifierIdentityKey,
        mockRevocationOutpoint,
        fields,
        masterKeyring
      )

      expect(certificate).toBeInstanceOf(MasterCertificate)
      expect(certificate.fields).toEqual(fields)
      expect(certificate.masterKeyring).toEqual(masterKeyring)
      expect(certificate.subject).toEqual(subjectIdentityKey)
      expect(certificate.certifier).toEqual(certifierIdentityKey)
    })

    it('should throw if masterKeyring is missing a key for any field', () => {
      const fields = { name: 'encrypted_value' }
      const masterKeyring = {} // intentionally empty

      expect(() => (
        new MasterCertificate(
          Utils.toBase64(Random(16)), // type
          Utils.toBase64(Random(16)), // serialNumber
          subjectIdentityKey,
          certifierIdentityKey,
          mockRevocationOutpoint,
          fields,
          masterKeyring
        )
      )).toThrow(/Master keyring must contain a value for every field/)
    })
  })

  describe('decryptFields (static)', () => {
    it('should decrypt all fields correctly using subject wallet', async () => {
      // Issue a certificate for the subject, which includes a valid masterKeyring
      const certificate = await MasterCertificate.issueCertificateForSubject(
        certifierWallet,
        subjectIdentityKey,
        plaintextFields,
        'TEST_CERT'
      )

      // Now subject should be able to decrypt all fields via static method
      const decrypted = await MasterCertificate.decryptFields(
        subjectWallet,
        certificate.masterKeyring,
        certificate.fields,
        certificate.certifier // because certifier was the encryption counterparty
      )
      expect(decrypted).toEqual(plaintextFields)
    })

    it('should throw if masterKeyring is empty or invalid', async () => {
      // Manually create a MasterCertificate with an empty masterKeyring
      expect(
        () =>
          new MasterCertificate(
            Utils.toBase64(Random(16)),
            Utils.toBase64(Random(16)),
            subjectIdentityKey,
            certifierIdentityKey,
            mockRevocationOutpoint,
            { name: Utils.toBase64([1, 2, 3]) },
            {}
          )
      ).toThrow(
        'Master keyring must contain a value for every field. Missing or empty key for field: "name"'
      )
    })

    it('should throw if decryption fails for any field', async () => {
      // Manually craft a scenario where the key is incorrect
      const badKeyMasterKeyring = Utils.toBase64([9, 9, 9, 9]) // Not the correct key
      const badKeyCertificate = new MasterCertificate(
        Utils.toBase64(Random(16)),
        Utils.toBase64(Random(16)),
        subjectIdentityKey,
        certifierIdentityKey,
        mockRevocationOutpoint,
        {
          name: Utils.toBase64(
            fieldSymWrong.encrypt(
              Utils.toArray('Alice', 'utf8')
            ) as number[]
          )
        },
        { name: badKeyMasterKeyring }
      )

      await expect(
        MasterCertificate.decryptFields(
          subjectWallet,
          badKeyCertificate.masterKeyring,
          badKeyCertificate.fields,
          badKeyCertificate.certifier
        )
      ).rejects.toThrow('Failed to decrypt all master certificate fields.')
    })
  })

  describe('createKeyringForVerifier (static)', () => {
    const verifierPrivateKey = verifierKey2
    const verifierWallet = new CompletedProtoWallet(verifierPrivateKey)
    let verifierIdentityKey: string

    let issuedCert: MasterCertificate

    beforeAll(async () => {
      verifierIdentityKey = (
        await verifierWallet.getPublicKey({ identityKey: true })
      ).publicKey
      // Issue a certificate to reuse in tests
      issuedCert = await MasterCertificate.issueCertificateForSubject(
        certifierWallet,
        subjectIdentityKey,
        plaintextFields,
        'TEST_CERT'
      )
    })

    it('should create a verifier keyring for specified fields', async () => {
      // We only want to share "name" with the verifier
      const fieldsToReveal = ['name']

      const keyringForVerifier =
        await MasterCertificate.createKeyringForVerifier(
          subjectWallet,
          issuedCert.certifier, // the original certifier
          verifierIdentityKey, // the new verifier
          issuedCert.fields, // encrypted fields
          fieldsToReveal,
          issuedCert.masterKeyring,
          issuedCert.serialNumber
        )

      // The new keyring should only contain "name"
      expect(Object.keys(keyringForVerifier)).toHaveLength(1)
      expect(keyringForVerifier).toHaveProperty('name')

      // Now let's create a VerifiableCertificate for the verifier
      const verifiableCert = new VerifiableCertificate(
        issuedCert.type,
        issuedCert.serialNumber,
        issuedCert.subject,
        issuedCert.certifier,
        issuedCert.revocationOutpoint,
        issuedCert.fields,
        keyringForVerifier,
        issuedCert.signature
      )

      // The verifier should successfully decrypt the "name" field
      const decrypted = await verifiableCert.decryptFields(verifierWallet)
      expect(decrypted).toEqual({ name: plaintextFields.name })
    })

    it('should throw if fields to reveal are not a subset of the certificate fields', async () => {
      await expect(
        MasterCertificate.createKeyringForVerifier(
          subjectWallet,
          issuedCert.certifier,
          verifierIdentityKey,
          issuedCert.fields,
          ['nonexistent_field'],
          issuedCert.masterKeyring,
          issuedCert.serialNumber
        )
      ).rejects.toThrow(
        /Fields to reveal must be a subset of the certificate fields\. Missing the "nonexistent_field" field\./
      )
    })

    it('should throw if the master key fails to decrypt the corresponding field', async () => {
      // We'll tamper with the certificate's masterKeyring so that a field key is invalid
      const tamperedCert = new MasterCertificate(
        issuedCert.type,
        issuedCert.serialNumber,
        issuedCert.subject,
        issuedCert.certifier,
        issuedCert.revocationOutpoint,
        issuedCert.fields,
        {
          // Tamper: replace 'name' field with nonsense
          name: Utils.toBase64([66, 66, 66]),
          email: issuedCert.masterKeyring.email,
          department: issuedCert.masterKeyring.department
        },
        issuedCert.signature
      )

      await expect(
        MasterCertificate.createKeyringForVerifier(
          subjectWallet,
          tamperedCert.certifier,
          verifierIdentityKey,
          tamperedCert.fields,
          ['name'],
          tamperedCert.masterKeyring,
          tamperedCert.serialNumber
        )
      ).rejects.toThrow('Failed to decrypt certificate field!')
    })

    it('should support optional originator parameter', async () => {
      const fieldsToReveal = ['name']
      const keyringForVerifier =
        await MasterCertificate.createKeyringForVerifier(
          subjectWallet,
          issuedCert.certifier,
          verifierIdentityKey,
          issuedCert.fields,
          fieldsToReveal,
          issuedCert.masterKeyring,
          issuedCert.serialNumber
        )
      expect(keyringForVerifier).toHaveProperty('name')
    })

    it('should support counterparty of "anyone" or "self"', async () => {
      const fieldsToReveal = ['name']

      // "anyone"
      const anyoneKeyring = await MasterCertificate.createKeyringForVerifier(
        subjectWallet,
        issuedCert.certifier,
        'anyone',
        issuedCert.fields,
        fieldsToReveal,
        issuedCert.masterKeyring,
        issuedCert.serialNumber
      )
      expect(anyoneKeyring).toHaveProperty('name')

      // "self"
      const selfKeyring = await MasterCertificate.createKeyringForVerifier(
        subjectWallet,
        issuedCert.certifier,
        'self',
        issuedCert.fields,
        fieldsToReveal,
        issuedCert.masterKeyring,
        issuedCert.serialNumber
      )
      expect(selfKeyring).toHaveProperty('name')
    })
  })

  describe('issueCertificateForSubject (static)', () => {
    it('should issue a valid MasterCertificate for the given subject', async () => {
      const newPlaintextFields = {
        project: 'Top Secret',
        clearanceLevel: 'High'
      }

      const revocationFn = jest.fn().mockResolvedValue(mockRevocationOutpoint)

      const newCert = await MasterCertificate.issueCertificateForSubject(
        certifierWallet,
        subjectIdentityKey,
        newPlaintextFields,
        'TEST_CERT',
        revocationFn
      )

      expect(newCert).toBeInstanceOf(MasterCertificate)
      // The certificate's fields should be encrypted base64
      for (const fieldName in newPlaintextFields) {
        expect(newCert.fields[fieldName]).toMatch(/^[A-Za-z0-9+/]+=*$/) // quick base64 check
      }
      // The masterKeyring should also contain base64 strings
      for (const fieldName in newPlaintextFields) {
        expect(newCert.masterKeyring[fieldName]).toMatch(/^[A-Za-z0-9+/]+=*$/)
      }
      // Check revocation outpoint is from mock
      expect(newCert.revocationOutpoint).toEqual(mockRevocationOutpoint)
      // Check we have a signature
      expect(newCert.signature).toBeDefined()
      // Check that the revocationFn was called
      expect(revocationFn).toHaveBeenCalledWith(newCert.serialNumber)
    })

    it('should allow passing a custom serial number when issuing the certificate', async () => {
      const customSerialNumber = Utils.toBase64(Random(32))
      const newPlaintextFields = { status: 'Approved' }
      const newCert = await MasterCertificate.issueCertificateForSubject(
        certifierWallet,
        subjectIdentityKey,
        newPlaintextFields,
        'TEST_CERT',
        undefined, // No custom revocation function
        customSerialNumber // Pass our custom serial number
      )

      expect(newCert).toBeInstanceOf(MasterCertificate)
      expect(newCert.serialNumber).toEqual(customSerialNumber) // Must match exactly
      // Check encryption
      for (const fieldName in newPlaintextFields) {
        expect(newCert.fields[fieldName]).toMatch(/^[A-Za-z0-9+/]+=*$/)
      }
    })

    it('should allow issuing a self-signed certificate and decrypt it with the same wallet', async () => {
      const subjectWallet = new CompletedProtoWallet(subjectKey2)

      const selfSignedFields = {
        owner: 'Bob',
        organization: 'SelfCo'
      }

      const subjectIdentityKey = (
        await subjectWallet.getPublicKey({ identityKey: true })
      ).publicKey

      // Issue the certificate: subject = actual identity key (valid hex)
      const selfSignedCert = await MasterCertificate.issueCertificateForSubject(
        subjectWallet,        // acts as certifier
        subjectIdentityKey,   // <-- was 'self', now real hex
        selfSignedFields,
        'SELF_SIGNED_TEST'
      )

      // Decrypt with the same wallet
      const decrypted = await MasterCertificate.decryptFields(
        subjectWallet,
        selfSignedCert.masterKeyring,
        selfSignedCert.fields,
        'self' // still fine here if decryptFields treats 'self' specially
      )

      expect(decrypted).toEqual(selfSignedFields)
    })

    it('resolves subject === "self" to the certifier wallet identity key', async () => {
      const certifierWallet = new CompletedProtoWallet(new PrivateKey(99))

      const certifierIdentityKey = (
        await certifierWallet.getPublicKey({ identityKey: true })
      ).publicKey

      const cert = await MasterCertificate.issueCertificateForSubject(
        certifierWallet,
        'self',
        { name: 'Alice' },
        'TEST_CERT'
      )

      expect(cert.subject).toBe(certifierIdentityKey)
    })

    it('uses provided subjectIdentityKey when subject is a valid hex string', async () => {
      const certifierWallet = new CompletedProtoWallet(new PrivateKey(42))

      const validPubkey =
        '0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'

      const cert = await MasterCertificate.issueCertificateForSubject(
        certifierWallet,
        validPubkey,
        { name: 'Alice' },
        'TEST_CERT'
      )

      expect(cert.subject).toBe(validPubkey)
    })
  })
})