import type {
  PubKeyHex,
  Base64String,
  CertificateFieldNameUnder50Bytes,
  HexString,
  OutpointString,
  WalletCertificate,
  OriginatorDomainNameStringUnder250Bytes
} from '../../wallet/Wallet.interfaces.js'
import SymmetricKey from '../../primitives/SymmetricKey.js'
import * as Utils from '../../primitives/utils.js'
import ProtoWallet from '../../wallet/ProtoWallet.js'
import Certificate from './Certificate.js'

/**
 * VerifiableCertificate extends the Certificate class, adding functionality to manage a verifier-specific keyring.
 * This keyring allows selective decryption of certificate fields for authorized verifiers.
 */
export class VerifiableCertificate extends Certificate {
  declare type: Base64String
  declare serialNumber: Base64String
  declare subject: PubKeyHex
  declare certifier: PubKeyHex
  declare revocationOutpoint: OutpointString
  declare fields: Record<CertificateFieldNameUnder50Bytes, string>
  declare signature?: HexString

  keyring: Record<CertificateFieldNameUnder50Bytes, string>
  decryptedFields?: Record<CertificateFieldNameUnder50Bytes, Base64String>

  constructor (
    type: Base64String,
    serialNumber: Base64String,
    subject: PubKeyHex,
    certifier: PubKeyHex,
    revocationOutpoint: OutpointString,
    fields: Record<CertificateFieldNameUnder50Bytes, string>,
    keyring: Record<CertificateFieldNameUnder50Bytes, string>,
    signature?: HexString,
    decryptedFields?: Record<CertificateFieldNameUnder50Bytes, Base64String>
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
    this.keyring = keyring
    this.decryptedFields = decryptedFields
  }

  /**
   *
   * @param {WalletCertificate} certificate – The source certificate that was issued and signed by the certifier.
   * @param {Record<CertificateFieldNameUnder50Bytes, string>} keyring – A allows the verifier to decrypt selected certificate fields.
   * @returns {VerifiableCertificate} – A fully-formed instance containing the
   *   original certificate data plus the supplied keyring.
   */
  static fromCertificate (
    certificate: WalletCertificate,
    keyring: Record<CertificateFieldNameUnder50Bytes, string>
  ): VerifiableCertificate {
    return new VerifiableCertificate(
      certificate.type,
      certificate.serialNumber,
      certificate.subject,
      certificate.certifier,
      certificate.revocationOutpoint,
      certificate.fields,
      keyring,
      certificate.signature
    )
  }

  /**
   * Decrypts selectively revealed certificate fields using the provided keyring and verifier wallet
   * @param {ProtoWallet} verifierWallet - The wallet instance of the certificate's verifier, used to decrypt field keys.
   * @returns {Promise<Record<CertificateFieldNameUnder50Bytes, string>>} - A promise that resolves to an object where each key is a field name and each value is the decrypted field value as a string.
   * @param {BooleanDefaultFalse} [privileged] - Whether this is a privileged request.
   * @param {DescriptionString5to50Bytes} [privilegedReason] - Reason provided for privileged access, required if this is a privileged operation.
   * @throws {Error} Throws an error if any of the decryption operations fail, with a message indicating the failure context.
   */
  async decryptFields (
    verifierWallet: ProtoWallet,
    privileged?: boolean,
    privilegedReason?: string,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<Record<CertificateFieldNameUnder50Bytes, string>> {
    if (this.keyring == null || Object.keys(this.keyring).length === 0) {
      throw new Error(
        'A keyring is required to decrypt certificate fields for the verifier.'
      )
    }

    try {
      const decryptedFields: Record<CertificateFieldNameUnder50Bytes, string> =
        {}
      for (const fieldName in this.keyring) {
        const { plaintext: fieldRevelationKey } = await verifierWallet.decrypt({
          ciphertext: Utils.toArray(this.keyring[fieldName], 'base64'),
          ...Certificate.getCertificateFieldEncryptionDetails(
            fieldName,
            this.serialNumber
          ),
          counterparty: this.subject,
          privileged,
          privilegedReason
        }, originator)

        const fieldValue = new SymmetricKey(fieldRevelationKey).decrypt(
          Utils.toArray(this.fields[fieldName], 'base64')
        )
        decryptedFields[fieldName] = Utils.toUTF8(fieldValue as number[])
      }
      return decryptedFields
    } catch (error) {
      throw new Error(
        `Failed to decrypt selectively revealed certificate fields using keyring: ${String(error instanceof Error ? error.message : error)}`
      )
    }
  }
}
