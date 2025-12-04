import {
  Base64String,
  CertificateFieldNameUnder50Bytes,
  HexString,
  OutpointString,
  PubKeyHex,
  WalletCounterparty,
} from '../../wallet/Wallet.interfaces.js'
import Certificate from './Certificate.js'
import * as Utils from '../../primitives/utils.js'
import SymmetricKey from '../../primitives/SymmetricKey.js'
import Random from '../../primitives/Random.js'
import ProtoWallet from '../../wallet/ProtoWallet.js'

interface CreateCertificateFieldsResult {
  certificateFields: Record<CertificateFieldNameUnder50Bytes, Base64String>
  masterKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>
}

/**
 * MasterCertificate extends the base Certificate class to manage a master keyring, enabling the creation of verifiable certificates.
 *
 * It allows for the selective disclosure of certificate fields by creating a `VerifiableCertificate` for a specific verifier.
 * The `MasterCertificate` can securely decrypt each master key and re-encrypt it for a verifier, creating a customized
 * keyring containing only the keys necessary for the verifier to access designated fields.
 *
 */
export class MasterCertificate extends Certificate {
  declare type: Base64String
  declare serialNumber: Base64String
  declare subject: PubKeyHex
  declare certifier: PubKeyHex
  declare revocationOutpoint: OutpointString
  declare fields: Record<CertificateFieldNameUnder50Bytes, Base64String>
  declare signature?: HexString

  masterKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>

  constructor(
    type: Base64String,
    serialNumber: Base64String,
    subject: PubKeyHex,
    certifier: PubKeyHex,
    revocationOutpoint: OutpointString,
    fields: Record<CertificateFieldNameUnder50Bytes, Base64String>,
    masterKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>,
    signature?: HexString
  ) {
    super(
      type,
      serialNumber,
      subject,
      certifier,
      revocationOutpoint,
      fields,
      signature
    )

    // Ensure every field in `fields` is a string and has a corresponding key in `masterKeyring`
    for (const fieldName of Object.keys(fields)) {
      if (masterKeyring[fieldName] === undefined || masterKeyring[fieldName] === '') {
        throw new Error(
          `Master keyring must contain a value for every field. Missing or empty key for field: "${fieldName}".`
        )
      }
    }

    this.masterKeyring = masterKeyring
  }

  /**
   * Encrypts certificate fields for a subject and generates a master keyring.
   * This method returns a master keyring tied to a specific certifier or subject who will validate
   * and sign off on the fields, along with the encrypted certificate fields.
   *
   * @param {ProtoWallet} creatorWallet - The wallet of the creator responsible for encrypting the fields.
   * @param {WalletCounterparty} certifierOrSubject - The certifier or subject who will validate the certificate fields.
   * @param {Record<CertificateFieldNameUnder50Bytes, string>} fields - A record of certificate field names (under 50 bytes) mapped to their values.
   * @param {BooleanDefaultFalse} [privileged] - Whether this is a privileged request.
   * @param {DescriptionString5to50Bytes} [privilegedReason] - Reason provided for privileged access, required if this is a privileged operation.   * 
   * @returns {Promise<CreateCertificateFieldsResult>} A promise resolving to an object containing:
   *   - `certificateFields` {Record<CertificateFieldNameUnder50Bytes, Base64String>}:
   *     The encrypted certificate fields.
   *   - `masterKeyring` {Record<CertificateFieldNameUnder50Bytes, Base64String>}:
   *     The master keyring containing encrypted revelation keys for each field.
   */
  static async createCertificateFields(
    creatorWallet: ProtoWallet,
    certifierOrSubject: WalletCounterparty,
    fields: Record<CertificateFieldNameUnder50Bytes, string>,
    privileged?: boolean,
    privilegedReason?: string
  ): Promise<CreateCertificateFieldsResult> {
    const certificateFields: Record<
      CertificateFieldNameUnder50Bytes,
      Base64String
    > = {}
    const masterKeyring: Record<
      CertificateFieldNameUnder50Bytes,
      Base64String
    > = {}
    for (const [fieldName, fieldValue] of Object.entries(fields)) {
      const fieldSymmetricKey = SymmetricKey.fromRandom()
      const encryptedFieldValue = fieldSymmetricKey.encrypt(
        Utils.toArray(fieldValue, 'utf8')
      )
      certificateFields[fieldName] = Utils.toBase64(
        encryptedFieldValue as number[]
      )

      const { ciphertext: encryptedFieldRevelationKey } =
        await creatorWallet.encrypt(
          {
            plaintext: fieldSymmetricKey.toArray(),
            ...Certificate.getCertificateFieldEncryptionDetails(fieldName), // Only fieldName used on MasterCertificate
            counterparty: certifierOrSubject,
            privileged,
            privilegedReason
          }
        )
      masterKeyring[fieldName] = Utils.toBase64(encryptedFieldRevelationKey)
    }

    return {
      certificateFields,
      masterKeyring
    }
  }

  /**
   * Creates a keyring for a verifier, enabling them to decrypt specific certificate fields.
   * This method decrypts the master field keys for the specified fields and re-encrypts them
   * for the verifier's identity key. The result is a keyring containing the keys necessary
   * for the verifier to access the designated fields.
   *
   * @param {ProtoWallet} subjectWallet - The wallet instance of the subject, used to decrypt and re-encrypt field keys.
   * @param {WalletCounterparty} verifier - The verifier who will receive access to the selectively revealed fields. Can be an identity key as hex, 'anyone', or 'self'.
   * @param {string[]} fieldsToReveal - An array of field names to be revealed to the verifier. Must be a subset of the certificate's fields.
   * @param {string} [originator] - Optional originator identifier, used if additional context is needed for decryption and encryption operations.
   * @returns {Promise<Record<CertificateFieldNameUnder50Bytes, string>>} - A keyring mapping field names to encrypted field revelation keys, allowing the verifier to decrypt specified fields.
   * @param {BooleanDefaultFalse} [privileged] - Whether this is a privileged request.
   * @param {DescriptionString5to50Bytes} [privilegedReason] - Reason provided for privileged access, required if this is a privileged operation.   * 
   * @throws {Error} Throws an error if:
   *   - fieldsToReveal is not an array of strings.
   *   - A field in `fieldsToReveal` does not exist in the certificate.
   *   - The decrypted master field key fails to decrypt the corresponding field (indicating an invalid key).
   */
  static async createKeyringForVerifier(
    subjectWallet: ProtoWallet,
    certifier: WalletCounterparty,
    verifier: WalletCounterparty,
    fields: Record<CertificateFieldNameUnder50Bytes, Base64String>,
    fieldsToReveal: string[],
    masterKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>,
    serialNumber: Base64String,
    privileged?: boolean,
    privilegedReason?: string
  ): Promise<Record<CertificateFieldNameUnder50Bytes, string>> {
    if (!Array.isArray(fieldsToReveal)) {
      throw new Error('fieldsToReveal must be an array of strings')
    }
    const fieldRevelationKeyring = {}
    for (const fieldName of fieldsToReveal) {
      // Make sure that fields to reveal is a subset of the certificate fields
      if (fields[fieldName] === undefined || fields[fieldName] === null || fields[fieldName] === '') {
        throw new Error(
          `Fields to reveal must be a subset of the certificate fields. Missing the "${fieldName}" field.`
        )
      }

      // Decrypt the master field key and verify that derived key actually decrypts requested field
      const masterFieldKey = (
        await this.decryptField(
          subjectWallet,
          masterKeyring,
          fieldName,
          fields[fieldName],
          certifier,
          privileged,
          privilegedReason
        )
      ).fieldRevelationKey

      // Encrypt derived fieldRevelationKey for verifier
      const { ciphertext: encryptedFieldRevelationKey } =
        await subjectWallet.encrypt(
          {
            plaintext: masterFieldKey,
            ...Certificate.getCertificateFieldEncryptionDetails(
              fieldName,
              serialNumber
            ),
            counterparty: verifier,
            privileged,
            privilegedReason
          }
        )

      // Add encryptedFieldRevelationKey to fieldRevelationKeyring
      fieldRevelationKeyring[fieldName] = Utils.toBase64(
        encryptedFieldRevelationKey
      )
    }

    // Return the field revelation keyring which can be used to create a verifiable certificate for a verifier.
    return fieldRevelationKeyring
  }

  /**
   * Issues a new MasterCertificate for a specified subject.
   *
   * This method generates a certificate containing encrypted fields and a keyring
   * for the subject to decrypt all fields. Each field is encrypted with a randomly
   * generated symmetric key, which is then encrypted for the subject. The certificate
   * can also includes a revocation outpoint to manage potential revocation.
   *
   * @param {ProtoWallet} certifierWallet - The wallet of the certifier, used to sign the certificate and encrypt field keys.
   * @param {WalletCounterparty} subject - The subject for whom the certificate is issued.
   * @param {Record<CertificateFieldNameUnder50Bytes, string>} fields - Unencrypted certificate fields to include, with their names and values.
   * @param {string} certificateType - The type of certificate being issued.
   * @param {function(string, Record<CertificateFieldNameUnder50Bytes, string>?): Promise<string>} getRevocationOutpoint -
   *   Optional function to obtain a revocation outpoint for the certificate. Defaults to a placeholder.
   * @param {function(string): Promise<void>} updateProgress - Optional callback for reporting progress updates during the operation. Defaults to a no-op.
   * @returns {Promise<MasterCertificate>} - A signed MasterCertificate instance containing the encrypted fields and subject specific keyring.
   *
   * @throws {Error} Throws an error if any operation (e.g., encryption, signing) fails during certificate issuance.
   */
  static async issueCertificateForSubject(
    certifierWallet: ProtoWallet,
    subject: WalletCounterparty,
    fields: Record<CertificateFieldNameUnder50Bytes, string>,
    certificateType: string,
    getRevocationOutpoint = async (_serial: string): Promise<string> => {
      void _serial // Explicitly acknowledge unused parameter
      return '00'.repeat(32)
    },
    serialNumber?: string
  ): Promise<MasterCertificate> {
    // 1. Generate a random serialNumber if not provided
    const finalSerialNumber = serialNumber ?? Utils.toBase64(Random(32))

    // 2. Create encrypted certificate fields and associated master keyring
    const { certificateFields, masterKeyring } =
      await this.createCertificateFields(certifierWallet, subject, fields)

    // 3. Obtain a revocation outpoint
    const revocationOutpoint = await getRevocationOutpoint(finalSerialNumber)

    let subjectIdentityKey: string
      if (subject === 'self') {
        subjectIdentityKey = (await certifierWallet.getPublicKey({ identityKey: true })).publicKey
      } else {
        subjectIdentityKey = subject
      }

    // 4. Create new MasterCertificate instance
    const certificate = new MasterCertificate(
      certificateType,
      finalSerialNumber,
      subjectIdentityKey,
      (await certifierWallet.getPublicKey({ identityKey: true })).publicKey,
      revocationOutpoint,
      certificateFields,
      masterKeyring
    )

    // 5. Sign and return the new MasterCertificate certifying the subject.
    await certificate.sign(certifierWallet)
    return certificate
  }

  /**
   * Decrypts all fields in the MasterCertificate using the subject's or certifier's wallet.
   *
   * This method allows the subject or certifier to decrypt the `masterKeyring` and retrieve
   * the encryption keys for each field, which are then used to decrypt the corresponding field values.
   * The counterparty used for decryption depends on how the certificate fields were created:
   * - If the certificate is self-signed, the counterparty should be set to 'self'.
   * - Otherwise, the counterparty should always be the other party involved in the certificate issuance process (the subject or certifier).
   *
   * @param {ProtoWallet} subjectOrCertifierWallet - The wallet of the subject or certifier, used to decrypt the master keyring and field values.
   * @param {Record<CertificateFieldNameUnder50Bytes, Base64String>} masterKeyring - A record containing encrypted keys for each field.
   * @param {Record<CertificateFieldNameUnder50Bytes, Base64String>} fields - A record of encrypted field names and their values.
   * @param {WalletCounterparty} counterparty - The counterparty responsible for creating or signing the certificate. For self-signed certificates, use 'self'.
   * @param {BooleanDefaultFalse} [privileged] - Whether this is a privileged request.
   * @param {DescriptionString5to50Bytes} [privilegedReason] - Reason provided for privileged access, required if this is a privileged operation.
   * @returns {Promise<Record<CertificateFieldNameUnder50Bytes, string>>} A promise resolving to a record of field names and their decrypted values in plaintext.
   *
   * @throws {Error} Throws an error if the `masterKeyring` is invalid or if decryption fails for any field.
   */
  static async decryptFields(
    subjectOrCertifierWallet: ProtoWallet,
    masterKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>,
    fields: Record<CertificateFieldNameUnder50Bytes, Base64String>,
    counterparty: WalletCounterparty,
    privileged?: boolean,
    privilegedReason?: string
  ): Promise<Record<CertificateFieldNameUnder50Bytes, string>> {
    if (masterKeyring == null || Object.keys(masterKeyring).length === 0) {
      throw new Error('A MasterCertificate must have a valid masterKeyring!')
    }
    try {
      const decryptedFields: Record<CertificateFieldNameUnder50Bytes, string> =
        {}
      // Note: we want to iterate through all fields, not just masterKeyring keys/value pairs.
      for (const fieldName of Object.keys(fields)) {
        decryptedFields[fieldName] = (
          await this.decryptField(
            subjectOrCertifierWallet,
            masterKeyring,
            fieldName,
            fields[fieldName],
            counterparty,
            privileged,
            privilegedReason
          )
        ).decryptedFieldValue
      }
      return decryptedFields
    } catch {
      throw new Error('Failed to decrypt all master certificate fields.')
    }
  }

  static async decryptField(
    subjectOrCertifierWallet: ProtoWallet,
    masterKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>,
    fieldName: Base64String,
    fieldValue: Base64String,
    counterparty: WalletCounterparty,
    privileged?: boolean,
    privilegedReason?: string
  ): Promise<{ fieldRevelationKey: number[], decryptedFieldValue: string }> {
    if (masterKeyring == null || Object.keys(masterKeyring).length === 0) {
      throw new Error('A MasterCertificate must have a valid masterKeyring!')
    }
    try {
      const { plaintext: fieldRevelationKey } =
        await subjectOrCertifierWallet.decrypt(
          {
            ciphertext: Utils.toArray(masterKeyring[fieldName], 'base64'),
            ...Certificate.getCertificateFieldEncryptionDetails(fieldName), // Only fieldName used on MasterCertificate
            counterparty,
            privileged,
            privilegedReason
          }
        )

      const decryptedFieldValue = new SymmetricKey(fieldRevelationKey).decrypt(
        Utils.toArray(fieldValue, 'base64')
      )
      return {
        fieldRevelationKey,
        decryptedFieldValue: Utils.toUTF8(decryptedFieldValue as number[])
      }
    } catch {
      throw new Error('Failed to decrypt certificate field!')
    }
  }
}
