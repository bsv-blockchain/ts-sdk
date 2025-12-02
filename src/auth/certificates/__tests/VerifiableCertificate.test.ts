import { VerifiableCertificate } from '../../../auth/certificates/VerifiableCertificate'
import Certificate from '../../../auth/certificates/Certificate'
import { PrivateKey, Utils } from '../../../../mod'
import { CompletedProtoWallet } from '../../../auth/certificates/__tests/CompletedProtoWallet'
import { MasterCertificate } from '../../../auth/certificates/MasterCertificate'
import { ProtoWallet, WalletCertificate } from '../../../wallet/index'

const subjectPrivateKey = new PrivateKey(21)
const subjectIdentityKey = subjectPrivateKey.toPublicKey().toString()
const certifierPrivateKey = new PrivateKey(22)
const certifierIdentityKey = certifierPrivateKey.toPublicKey().toString()
const verifierPrivateKey = new PrivateKey(23)
const verifierIdentityKey = verifierPrivateKey.toPublicKey().toString()

const wrongPrivateKey = new PrivateKey(31)
const wrongWallet = new CompletedProtoWallet(wrongPrivateKey)

const subjectWallet = new CompletedProtoWallet(subjectPrivateKey)
const verifierWallet = new CompletedProtoWallet(verifierPrivateKey)

const sampleType = Utils.toBase64(new Array(32).fill(1))
const sampleSerialNumber = Utils.toBase64(new Array(32).fill(2))
const sampleRevocationOutpoint =
  'deadbeefdeadbeefdeadbeefdeadbeef00000000000000000000000000000000.1'

const plaintextFields = {
  name: 'Alice',
  email: 'alice@example.com',
  organization: 'Example Corp'
}

describe('VerifiableCertificate', () => {
  let verifiableCert: VerifiableCertificate

  beforeEach(async () => {
    // For each test, we'll build a fresh VerifiableCertificate with valid encryption
    const { certificateFields, masterKeyring } =
      await MasterCertificate.createCertificateFields(
        subjectWallet,
        certifierIdentityKey,
        plaintextFields
      )
    const keyringForVerifier = await MasterCertificate.createKeyringForVerifier(
      subjectWallet,
      certifierIdentityKey,
      verifierIdentityKey,
      certificateFields,
      Object.keys(certificateFields),
      masterKeyring,
      sampleSerialNumber
    )
    verifiableCert = new VerifiableCertificate(
      sampleType,
      sampleSerialNumber,
      subjectIdentityKey,
      certifierIdentityKey,
      sampleRevocationOutpoint,
      certificateFields,
      keyringForVerifier
    )
  })

  describe('constructor', () => {
    it('should create a VerifiableCertificate with all required properties', () => {
      expect(verifiableCert).toBeInstanceOf(VerifiableCertificate)
      expect(verifiableCert.type).toEqual(sampleType)
      expect(verifiableCert.serialNumber).toEqual(sampleSerialNumber)
      expect(verifiableCert.subject).toEqual(subjectIdentityKey)
      expect(verifiableCert.certifier).toEqual(certifierIdentityKey)
      expect(verifiableCert.revocationOutpoint).toEqual(
        sampleRevocationOutpoint
      )
      expect(verifiableCert.fields).toBeDefined()
      expect(verifiableCert.keyring).toBeDefined()
    })
  })

  describe('decryptFields', () => {
    it('should decrypt fields successfully when provided the correct verifier wallet and keyring', async () => {
      const decrypted = await verifiableCert.decryptFields(verifierWallet)
      expect(decrypted).toEqual(plaintextFields)
    })

    it('should fail if the verifier wallet does not have the correct private key (wrong key)', async () => {
      await expect(verifiableCert.decryptFields(wrongWallet)).rejects.toThrow(
        /Failed to decrypt selectively revealed certificate fields using keyring/
      )
    })

    it('should fail if the keyring is empty or missing keys', async () => {
      // Create a new VerifiableCertificate but with an empty keyring
      const fields = verifiableCert.fields
      const emptyKeyringCert = new VerifiableCertificate(
        verifiableCert.type,
        verifiableCert.serialNumber,
        verifiableCert.subject,
        verifiableCert.certifier,
        verifiableCert.revocationOutpoint,
        fields,
        {}, // empty
        verifiableCert.signature
      )

      await expect(
        emptyKeyringCert.decryptFields(verifierWallet)
      ).rejects.toThrow(
        'A keyring is required to decrypt certificate fields for the verifier.'
      )
    })

    it('should fail if the encrypted field or its key is tampered', async () => {
      // Tamper the keyring so it doesn't match the field encryption
      verifiableCert.keyring.name = Utils.toBase64([9, 9, 9, 9])
      await expect(
        verifiableCert.decryptFields(verifierWallet)
      ).rejects.toThrow(
        /Failed to decrypt selectively revealed certificate fields using keyring/
      )
    })

    it('should be able to decrypt fields using the anyone wallet', async () => {
      const { certificateFields, masterKeyring } =
        await MasterCertificate.createCertificateFields(
          subjectWallet,
          certifierIdentityKey,
          plaintextFields
        )
      const keyringForVerifier =
        await MasterCertificate.createKeyringForVerifier(
          subjectWallet,
          certifierIdentityKey,
          'anyone',
          certificateFields,
          Object.keys(certificateFields),
          masterKeyring,
          sampleSerialNumber
        )
      verifiableCert = new VerifiableCertificate(
        sampleType,
        sampleSerialNumber,
        subjectIdentityKey,
        'anyone',
        sampleRevocationOutpoint,
        certificateFields,
        keyringForVerifier
      )
      const decrypted = await verifiableCert.decryptFields(
        new ProtoWallet('anyone')
      )
      expect(decrypted).toEqual(plaintextFields)
    })
  })

  describe('fromCertificate', () => {
    it('should create an equivalent VerifiableCertificate and decrypt correctly', async () => {
      const baseCert = new Certificate(
        verifiableCert.type,
        verifiableCert.serialNumber,
        verifiableCert.subject,
        verifiableCert.certifier,
        verifiableCert.revocationOutpoint,
        verifiableCert.fields,
        verifiableCert.signature
      ) as WalletCertificate

      const verifiable = VerifiableCertificate.fromCertificate(
        baseCert,
        verifiableCert.keyring
      )

      expect(verifiable).toBeInstanceOf(VerifiableCertificate)
      expect(verifiable.serialNumber).toEqual(sampleSerialNumber)
      expect(verifiable.keyring).toEqual(verifiableCert.keyring)

      const decrypted = await verifiable.decryptFields(verifierWallet)
      expect(decrypted).toEqual(plaintextFields)
    })
  })
})
