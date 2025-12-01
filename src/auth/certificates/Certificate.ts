import {
  Base64String,
  PubKeyHex,
  HexString,
  OutpointString,
  CertificateFieldNameUnder50Bytes,
  WalletProtocol
} from '../../wallet/Wallet.interfaces.js'
import * as Utils from '../../primitives/utils.js'
import ProtoWallet from '../../wallet/ProtoWallet.js'
import Signature from '../../primitives/Signature.js'

/**
 * Represents an Identity Certificate as per the Wallet interface specifications.
 *
 * This class provides methods to serialize and deserialize certificates, as well as signing and verifying the certificate's signature.
 */
export default class Certificate {
  /**
   * Type identifier for the certificate, base64 encoded string, 32 bytes.
   */
  type: Base64String

  /**
   * Unique serial number of the certificate, base64 encoded string, 32 bytes.
   */
  serialNumber: Base64String

  /**
   * The public key belonging to the certificate's subject, compressed public key hex string.
   */
  subject: PubKeyHex

  /**
   * Public key of the certifier who issued the certificate, compressed public key hex string.
   */
  certifier: PubKeyHex

  /**
   * The outpoint used to confirm that the certificate has not been revoked (TXID.OutputIndex), as a string.
   */
  revocationOutpoint: OutpointString

  /**
   * All the fields present in the certificate, with field names as keys and encrypted field values as Base64 strings.
   */
  fields: Record<CertificateFieldNameUnder50Bytes, Base64String>

  /**
   * Certificate signature by the certifier's private key, DER encoded hex string.
   */
  signature?: HexString

  /**
   * Constructs a new Certificate.
   *
   * @param {Base64String} type - Type identifier for the certificate, base64 encoded string, 32 bytes.
   * @param {Base64String} serialNumber - Unique serial number of the certificate, base64 encoded string, 32 bytes.
   * @param {PubKeyHex} subject - The public key belonging to the certificate's subject, compressed public key hex string.
   * @param {PubKeyHex} certifier - Public key of the certifier who issued the certificate, compressed public key hex string.
   * @param {OutpointString} revocationOutpoint - The outpoint used to confirm that the certificate has not been revoked (TXID.OutputIndex), as a string.
   * @param {Record<CertificateFieldNameUnder50Bytes, string>} fields - All the fields present in the certificate.
   * @param {HexString} signature - Certificate signature by the certifier's private key, DER encoded hex string.
   */
  constructor(
    type: Base64String,
    serialNumber: Base64String,
    subject: PubKeyHex,
    certifier: PubKeyHex,
    revocationOutpoint: OutpointString,
    fields: Record<CertificateFieldNameUnder50Bytes, string>,
    signature?: HexString
  ) {
    this.type = type
    this.serialNumber = serialNumber
    this.subject = subject
    this.certifier = certifier
    this.revocationOutpoint = revocationOutpoint
    this.fields = fields
    this.signature = signature
  }

  /**
   * Serializes the certificate into binary format, with or without a signature.
   *
   * @param {boolean} [includeSignature=true] - Whether to include the signature in the serialization.
   * @returns {number[]} - The serialized certificate in binary format.
   */
  toBinary(includeSignature: boolean = true): number[] {
    const writer = new Utils.Writer()

    // Write type (Base64String, 32 bytes)
    const typeBytes = Utils.toArray(this.type, 'base64')
    writer.write(typeBytes)

    // Write serialNumber (Base64String, 32 bytes)
    const serialNumberBytes = Utils.toArray(this.serialNumber, 'base64')
    writer.write(serialNumberBytes)

    // Write subject (33 bytes compressed PubKeyHex)
    const subjectBytes = Utils.toArray(this.subject, 'hex')
    writer.write(subjectBytes)

    // Write certifier (33 bytes compressed PubKeyHex)
    const certifierBytes = Utils.toArray(this.certifier, 'hex')
    writer.write(certifierBytes)

    // Write revocationOutpoint (TXID + OutputIndex)
    const [txid, outputIndex] = this.revocationOutpoint.split('.')
    const txidBytes = Utils.toArray(txid, 'hex')
    writer.write(txidBytes)
    writer.writeVarIntNum(Number(outputIndex))

    // Write fields
    // Sort field names lexicographically
    const fieldNames = Object.keys(this.fields).sort()
    writer.writeVarIntNum(fieldNames.length)
    for (const fieldName of fieldNames) {
      const fieldValue = this.fields[fieldName]

      // Field name
      const fieldNameBytes = Utils.toArray(fieldName, 'utf8')
      writer.writeVarIntNum(fieldNameBytes.length)
      writer.write(fieldNameBytes)

      // Field value
      const fieldValueBytes = Utils.toArray(fieldValue, 'utf8')
      writer.writeVarIntNum(fieldValueBytes.length)
      writer.write(fieldValueBytes)
    }

    // Write signature if included
    if (includeSignature && (this.signature ?? '').length > 0) { // ✅ Explicitly handle nullish signature
      const signatureBytes = Utils.toArray(this.signature as string, 'hex') // ✅ Type assertion ensures it's a string
      writer.write(signatureBytes)
    }

    return writer.toArray()
  }

  /**
   * Deserializes a certificate from binary format.
   *
   * @param {number[]} bin - The binary data representing the certificate.
   * @returns {Certificate} - The deserialized Certificate object.
   */
  static fromBinary(bin: number[]): Certificate {
    const reader = new Utils.Reader(bin)

    // Read type
    const typeBytes = reader.read(32)
    const type = Utils.toBase64(typeBytes)

    // Read serialNumber
    const serialNumberBytes = reader.read(32)
    const serialNumber = Utils.toBase64(serialNumberBytes)

    // Read subject (33 bytes)
    const subjectBytes = reader.read(33)
    const subject = Utils.toHex(subjectBytes)

    // Read certifier (33 bytes)
    const certifierBytes = reader.read(33)
    const certifier = Utils.toHex(certifierBytes)

    // Read revocationOutpoint
    const txidBytes = reader.read(32)
    const txid = Utils.toHex(txidBytes)
    const outputIndex = reader.readVarIntNum()
    const revocationOutpoint = `${txid}.${outputIndex}`

    // Read fields
    const numFields = reader.readVarIntNum()
    const fields: Record<CertificateFieldNameUnder50Bytes, string> = {}
    for (let i = 0; i < numFields; i++) {
      // Field name
      const fieldNameLength = reader.readVarIntNum()
      const fieldNameBytes = reader.read(fieldNameLength)
      const fieldName = Utils.toUTF8(fieldNameBytes)

      // Field value
      const fieldValueLength = reader.readVarIntNum()
      const fieldValueBytes = reader.read(fieldValueLength)
      const fieldValue = Utils.toUTF8(fieldValueBytes)

      fields[fieldName] = fieldValue
    }

    // Read signature if present
    let signature: string | undefined
    if (!reader.eof()) {
      const signatureBytes = reader.read()
      const sig = Signature.fromDER(signatureBytes)
      signature = sig.toString('hex') as string
    }

    return new Certificate(
      type,
      serialNumber,
      subject,
      certifier,
      revocationOutpoint,
      fields,
      signature
    )
  }

  /**
   * Verifies the certificate's signature.
   *
   * @returns {Promise<boolean>} - A promise that resolves to true if the signature is valid.
   */
  async verify(): Promise<boolean> {
    // A verifier can be any wallet capable of verifying signatures
    const verifier = new ProtoWallet('anyone')
    const verificationData = this.toBinary(false) // Exclude the signature from the verification data

    const signatureHex = this.signature ?? '' // Provide a fallback value (empty string)

    const { valid } = await verifier.verifySignature({
      signature: Utils.toArray(signatureHex, 'hex'), // Now it is always a string
      data: verificationData,
      protocolID: [2, 'certificate signature'],
      keyID: `${this.type} ${this.serialNumber}`,
      counterparty: this.certifier // The certifier is the one who signed the certificate
    })

    return valid
  }

  /**
 * Signs the certificate using the provided certifier wallet.
 *
 * @param {Wallet} certifierWallet - The wallet representing the certifier.
 * @returns {Promise<void>}
 */
  async sign(certifierWallet: ProtoWallet): Promise<void> {
    if (this.signature != null && this.signature.length > 0) { // ✅ Explicitly checking for null/undefined
      throw new Error(
        `Certificate has already been signed! Signature present: ${this.signature}`
      )
    }

    // Ensure the certifier declared is the one actually signing
    this.certifier = (
      await certifierWallet.getPublicKey({ identityKey: true })
    ).publicKey

    const preimage = this.toBinary(false) // Exclude the signature when signing
    const { signature } = await certifierWallet.createSignature({
      data: preimage,
      protocolID: [2, 'certificate signature'],
      keyID: `${this.type} ${this.serialNumber}`
    })
    this.signature = Utils.toHex(signature)
  }

  /**
   * Helper function which retrieves the protocol ID and key ID for certificate field encryption.
   *
   * For master certificate creation, no serial number is provided because entropy is required
   * from both the client and the certifier. In this case, the `keyID` is simply the `fieldName`.
   *
   * For VerifiableCertificates verifier keyring creation, both the serial number and field name are available,
   * so the `keyID` is formed by concatenating the `serialNumber` and `fieldName`.
   *
   * @param fieldName - The name of the field within the certificate to be encrypted.
   * @param serialNumber - (Optional) The serial number of the certificate.
   * @returns An object containing:
   *   - `protocolID` (WalletProtocol): The protocol ID for certificate field encryption.
   *   - `keyID` (string): A unique key identifier. It is the `fieldName` if `serialNumber` is undefined,
   *     otherwise it is a combination of `serialNumber` and `fieldName`.
   */
  static getCertificateFieldEncryptionDetails(
    fieldName: string,
    serialNumber?: string
  ): { protocolID: WalletProtocol, keyID: string } {
    return {
      protocolID: [2, 'certificate field encryption'],
      keyID: serialNumber ? `${serialNumber} ${fieldName}` : fieldName
    }
  }

  /**
   * Creates a Certificate instance from a plain object representation.
   * 
   * @param obj - The object containing certificate data.
   * @returns A new Certificate instance.
   */
  static fromObject(obj: { 
    type: Base64String, 
    serialNumber: Base64String, 
    subject: PubKeyHex, 
    certifier: PubKeyHex, 
    revocationOutpoint: OutpointString, 
    fields: Record<CertificateFieldNameUnder50Bytes, Base64String>, 
    signature?: HexString 
  }): Certificate {
    const cert = new Certificate(
      obj.type, 
      obj.serialNumber, 
      obj.subject, 
      obj.certifier, 
      obj.revocationOutpoint, 
      obj.fields, 
      obj.signature
    );

    return cert;
  }
}
