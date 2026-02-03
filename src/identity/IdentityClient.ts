import { DEFAULT_IDENTITY_CLIENT_OPTIONS, defaultIdentity, DisplayableIdentity, KNOWN_IDENTITY_TYPES } from './types/index.js'
import {
  Base64String,
  CertificateFieldNameUnder50Bytes,
  DiscoverByAttributesArgs,
  DiscoverByIdentityKeyArgs,
  IdentityCertificate,
  OriginatorDomainNameStringUnder250Bytes,
  PubKeyHex,
  WalletCertificate,
  WalletClient,
  WalletInterface
} from '../wallet/index.js'
import { BroadcastFailure, BroadcastResponse, Transaction } from '../transaction/index.js'
import Certificate from '../auth/certificates/Certificate.js'
import { VerifiableCertificate } from '../auth/certificates/VerifiableCertificate.js'
import { PushDrop } from '../script/index.js'
import { PrivateKey, Utils } from '../primitives/index.js'
import ProtoWallet from '../wallet/ProtoWallet.js'
import { LookupResolver, SHIPBroadcaster, TopicBroadcaster, withDoubleSpendRetry } from '../overlay-tools/index.js'
import { ContactsManager, Contact } from './ContactsManager.js'

// Default SocialCert certifier for fallback resolution when no wallet is available
const DEFAULT_CERTIFIER = '02cf6cdf466951d8dfc9e7c9367511d0007ed6fba35ed42d425cc412fd6cfd4a17'

/**
 * IdentityClient lets you discover who others are, and let the world know who you are.
 */
export class IdentityClient {
  private readonly wallet: WalletInterface
  private readonly contactsManager: ContactsManager
  constructor (
    wallet?: WalletInterface,
    private readonly options = DEFAULT_IDENTITY_CLIENT_OPTIONS,
    private readonly originator?: OriginatorDomainNameStringUnder250Bytes
  ) {
    this.originator = originator
    this.wallet = wallet ?? new WalletClient('auto', this.originator)
    this.contactsManager = new ContactsManager(this.wallet, this.originator)
  }

  /**
   * Publicly reveals selected fields from a given certificate by creating a publicly verifiable certificate.
   * The publicly revealed certificate is included in a blockchain transaction and broadcast to a federated overlay node.
   *
   * @param {Certificate} certificate - The master certificate to selectively reveal.
   * @param {CertificateFieldNameUnder50Bytes[]} fieldsToReveal - An array of certificate field names to reveal. Only these fields will be included in the public certificate.
   *
   * @returns {Promise<object>} A promise that resolves with the broadcast result from the overlay network.
   * @throws {Error} Throws an error if the certificate is invalid, the fields cannot be revealed, or if the broadcast fails.
   */
  async publiclyRevealAttributes (
    certificate: WalletCertificate,
    fieldsToReveal: CertificateFieldNameUnder50Bytes[]
  ): Promise<BroadcastResponse | BroadcastFailure> {
    if (Object.keys(certificate.fields).length === 0) {
      throw new Error(
        'Public reveal failed: Certificate has no fields to reveal!'
      )
    }
    if (fieldsToReveal.length === 0) {
      throw new Error(
        'Public reveal failed: You must reveal at least one field!'
      )
    }
    try {
      const masterCert = new Certificate(
        certificate.type,
        certificate.serialNumber,
        certificate.subject,
        certificate.certifier,
        certificate.revocationOutpoint,
        certificate.fields,
        certificate.signature
      )
      await masterCert.verify()
    } catch (error) {
      throw new Error('Public reveal failed: Certificate verification failed!')
    }

    // Given we already have a master certificate from a certifier,
    // create an anyone verifiable certificate with selectively revealed fields
    const { keyringForVerifier } = await this.wallet.proveCertificate(
      {
        certificate,
        fieldsToReveal,
        verifier: new PrivateKey(1).toPublicKey().toString()
      },
      this.originator
    )

    // Build the lockingScript with pushdrop.create() and the transaction with createAction()
    const lockingScript = await new PushDrop(this.wallet, this.originator).lock(
      [
        Utils.toArray(
          JSON.stringify({ ...certificate, keyring: keyringForVerifier })
        )
      ],
      this.options.protocolID,
      this.options.keyID,
      'anyone',
      true,
      true
    )
    // TODO: Consider verification and if this is necessary
    // counterpartyCanVerifyMyOwnership: true

    const { tx } = await this.wallet.createAction(
      {
        description: 'Create a new Identity Token',
        outputs: [
          {
            satoshis: this.options.tokenAmount,
            lockingScript: lockingScript.toHex(),
            outputDescription: 'Identity Token'
          }
        ],
        options: {
          randomizeOutputs: false
        }
      },
      this.originator
    )

    if (tx !== undefined) {
      // Submit the transaction to an overlay
      const broadcaster = new TopicBroadcaster(['tm_identity'], {
        networkPreset: (await this.wallet.getNetwork({})).network
      })
      return await broadcaster.broadcast(Transaction.fromAtomicBEEF(tx))
    }
    throw new Error('Public reveal failed: failed to create action!')
  }

  /**
   * Resolves displayable identity certificates, issued to a given identity key by a trusted certifier.
   *
   * @param {DiscoverByIdentityKeyArgs} args - Arguments for requesting the discovery based on the identity key.
   * @param {boolean} [overrideWithContacts=true] - Whether to override the results with personal contacts if available.
   * @returns {Promise<DisplayableIdentity[]>} The promise resolves to displayable identities.
   */
  async resolveByIdentityKey (
    args: DiscoverByIdentityKeyArgs,
    overrideWithContacts = true
  ): Promise<DisplayableIdentity[]> {
    if (overrideWithContacts) {
      // Override results with personal contacts if available
      try {
        const contacts = await this.contactsManager.getContacts(args.identityKey)
        if (contacts.length > 0) {
          return contacts
        }
      } catch (e) {
        // Contacts require wallet - continue to try discovery
      }
    }

    try {
      const { certificates } = await this.wallet.discoverByIdentityKey(
        args,
        this.originator
      )
      return certificates.map((cert) => {
        return IdentityClient.parseIdentity(cert)
      })
    } catch (error: unknown) {
      // Fallback to LookupResolver if no wallet is available
      const errorMessage = error instanceof Error ? error.message : ''
      if (errorMessage.includes('No wallet available')) {
        const certificates = await this.resolveViaLookup({ identityKey: args.identityKey })
        return certificates.map((cert) => IdentityClient.parseIdentity(cert))
      }
      throw error
    }
  }

  /**
   * Resolves displayable identity certificates by specific identity attributes, issued by a trusted entity.
   *
   * @param {DiscoverByAttributesArgs} args - Attributes and optional parameters used to discover certificates.
   * @param {boolean} [overrideWithContacts=true] - Whether to override the results with personal contacts if available.
   * @returns {Promise<DisplayableIdentity[]>} The promise resolves to displayable identities.
   */
  async resolveByAttributes (
    args: DiscoverByAttributesArgs,
    overrideWithContacts = true
  ): Promise<DisplayableIdentity[]> {
    // Run both queries in parallel for better performance
    const contactsPromise = overrideWithContacts
      ? this.contactsManager.getContacts().catch(() => [] as Contact[])
      : Promise.resolve([] as Contact[])

    try {
      const [contacts, certificatesResult] = await Promise.all([
        contactsPromise,
        this.wallet.discoverByAttributes(args, this.originator)
      ])

      // Fast lookup by identityKey
      const contactByKey = new Map<PubKeyHex, Contact>(
        contacts.map((contact) => [contact.identityKey, contact] as const)
      )

      // Guard if certificates might be absent
      const certs = certificatesResult?.certificates ?? []

      // Parse certificates and substitute with contacts where available
      return certs.map(
        (cert) =>
          contactByKey.get(cert.subject) ?? IdentityClient.parseIdentity(cert)
      )
    } catch (error: unknown) {
      // Fallback to LookupResolver if no wallet is available
      const errorMessage = error instanceof Error ? error.message : ''
      if (errorMessage.includes('No wallet available')) {
        const certificates = await this.resolveViaLookup({ attributes: args.attributes })
        return certificates.map((cert) => IdentityClient.parseIdentity(cert))
      }
      throw error
    }
  }

  /**
   * Fallback method to resolve identity certificates via LookupResolver when no wallet is available.
   * Uses the ls_identity overlay with a default SocialCert certifier.
   *
   * @param query - Query parameters: either identityKey or attributes
   * @returns {Promise<IdentityCertificate[]>} Array of identity certificates
   */
  private async resolveViaLookup (
    query: { identityKey?: PubKeyHex, attributes?: Record<string, string> }
  ): Promise<IdentityCertificate[]> {
    const resolver = new LookupResolver({ networkPreset: 'mainnet' })

    // Build the lookup query based on what was provided
    const lookupQuery: Record<string, any> = {
      certifiers: [DEFAULT_CERTIFIER]
    }

    if (query.identityKey !== undefined) {
      lookupQuery.identityKey = query.identityKey
    } else if (query.attributes !== undefined) {
      // For attribute search, use the 'any' matcher for flexible matching
      const attributeValues = Object.values(query.attributes)
      if (attributeValues.length === 1) {
        lookupQuery.attributes = { any: attributeValues[0] }
      } else {
        lookupQuery.attributes = query.attributes
      }
    }

    const lookupResult = await resolver.query({
      service: 'ls_identity',
      query: lookupQuery
    })

    if (lookupResult.type !== 'output-list' || lookupResult.outputs.length === 0) {
      return []
    }

    const certificates: IdentityCertificate[] = []
    const anyoneWallet = new ProtoWallet('anyone')

    for (const output of lookupResult.outputs) {
      try {
        const tx = Transaction.fromBEEF(output.beef)
        const decodedOutput = PushDrop.decode(tx.outputs[output.outputIndex].lockingScript)
        const certData = JSON.parse(Utils.toUTF8(decodedOutput.fields[0]))

        const verifiableCert = new VerifiableCertificate(
          certData.type,
          certData.serialNumber,
          certData.subject,
          certData.certifier,
          certData.revocationOutpoint,
          certData.fields,
          certData.keyring,
          certData.signature
        )

        // Decrypt fields using 'anyone' wallet for publicly revealed certificates
        const decryptedFields = await verifiableCert.decryptFields(anyoneWallet)

        // Verify the certificate is valid
        await verifiableCert.verify()

        // Construct IdentityCertificate with default certifier info
        const identityCert: IdentityCertificate = {
          type: certData.type,
          serialNumber: certData.serialNumber,
          subject: certData.subject,
          certifier: certData.certifier,
          revocationOutpoint: certData.revocationOutpoint,
          fields: certData.fields,
          signature: certData.signature,
          certifierInfo: {
            name: 'SocialCert',
            iconUrl: 'https://socialcert.net/favicon.ico',
            description: 'Social identity verification',
            trust: 5
          },
          publiclyRevealedKeyring: certData.keyring,
          decryptedFields
        }

        certificates.push(identityCert)
      } catch (e) {
        // Skip invalid certificates and continue processing
        continue
      }
    }

    return certificates
  }

  /**
   * Remove public certificate revelation from overlay services by spending the identity token
   * @param serialNumber - Unique serial number of the certificate to revoke revelation
   */
  async revokeCertificateRevelation (
    serialNumber: Base64String
  ): Promise<void> {
    // 1. Find existing UTXO
    const lookupResolver = new LookupResolver({
      networkPreset: (await this.wallet.getNetwork({})).network
    })
    const result = await lookupResolver.query({
      service: 'ls_identity',
      query: {
        serialNumber
      }
    })

    if (result.type !== 'output-list') { throw new Error('Failed to get lookup result') }

    const topicBroadcaster = new SHIPBroadcaster(['tm_identity'], {
      networkPreset: (await this.wallet.getNetwork({})).network,
      requireAcknowledgmentFromAllHostsForTopics: [],
      requireAcknowledgmentFromAnyHostForTopics: [],
      requireAcknowledgmentFromSpecificHostsForTopics: { tm_identity: [] }
    })

    await withDoubleSpendRetry(async () => {
      const tx = Transaction.fromBEEF(result.outputs[0].beef)
      const outpoint = `${tx.id('hex')}.${this.options.outputIndex}`
      const lockingScript = tx.outputs[this.options.outputIndex].lockingScript

      if (lockingScript === undefined || outpoint === undefined) {
        throw new Error('Failed to get locking script for revelation output!')
      }

      // 2. Parse results
      const { signableTransaction } = await this.wallet.createAction(
        {
          description: 'Spend certificate revelation token',
          inputBEEF: result.outputs[0].beef,
          inputs: [
            {
              inputDescription: 'Revelation token',
              outpoint,
              unlockingScriptLength: 74
            }
          ],
          options: {
            randomizeOutputs: false,
            acceptDelayedBroadcast: false,
            noSend: true
          }
        },
        this.originator
      )

      if (signableTransaction === undefined) {
        throw new Error('Failed to create signable transaction')
      }

      const partialTx = Transaction.fromBEEF(signableTransaction.tx)

      const unlocker = new PushDrop(this.wallet, this.originator).unlock(
        this.options.protocolID,
        this.options.keyID,
        'anyone'
      )

      const unlockingScript = await unlocker.sign(
        partialTx,
        this.options.outputIndex
      )

      const { tx: signedTx } = await this.wallet.signAction(
        {
          reference: signableTransaction.reference,
          spends: {
            [this.options.outputIndex]: {
              unlockingScript: unlockingScript.toHex()
            }
          },
          options: {
            acceptDelayedBroadcast: false,
            noSend: true
          }
        },
        this.originator
      )

      if (signedTx === undefined) {
        throw new Error('Failed to sign transaction')
      }

      await topicBroadcaster.broadcast(Transaction.fromAtomicBEEF(signedTx))
    }, topicBroadcaster)
  }

  /**
   * Load all records from the contacts basket
   * @param identityKey Optional specific identity key to fetch
   * @param forceRefresh Whether to force a check for new contact data
   * @param limit Optional limit on number of contacts to fetch
   * @returns A promise that resolves with an array of contacts
   */
  public async getContacts (
    identityKey?: PubKeyHex,
    forceRefresh = false,
    limit = 1000
  ): Promise<Contact[]> {
    return await this.contactsManager.getContacts(
      identityKey,
      forceRefresh,
      limit
    )
  }

  /**
   * Save or update a Metanet contact
   * @param contact The displayable identity information for the contact
   * @param metadata Optional metadata to store with the contact (ex. notes, aliases, etc)
   */
  public async saveContact (
    contact: DisplayableIdentity,
    metadata?: Record<string, any>
  ): Promise<void> {
    return await this.contactsManager.saveContact(contact, metadata)
  }

  /**
   * Remove a contact from the contacts basket
   * @param identityKey The identity key of the contact to remove
   */
  public async removeContact (identityKey: PubKeyHex): Promise<void> {
    return await this.contactsManager.removeContact(identityKey)
  }

  /**
   * Parse out identity and certifier attributes to display from an IdentityCertificate
   * @param identityToParse - The Identity Certificate to parse
   * @returns - IdentityToDisplay
   */
  static parseIdentity (
    identityToParse: IdentityCertificate
  ): DisplayableIdentity {
    const { type, decryptedFields, certifierInfo } = identityToParse
    let name, avatarURL, badgeLabel, badgeIconURL, badgeClickURL

    // Parse out the name to display based on the specific certificate type which has clearly defined fields.
    switch (type) {
      case KNOWN_IDENTITY_TYPES.xCert:
        name = decryptedFields.userName
        avatarURL = decryptedFields.profilePhoto
        badgeLabel = `X account certified by ${certifierInfo.name}`
        badgeIconURL = certifierInfo.iconUrl
        badgeClickURL = 'https://socialcert.net' // TODO Make a specific page for this.
        break
      case KNOWN_IDENTITY_TYPES.discordCert:
        name = decryptedFields.userName
        avatarURL = decryptedFields.profilePhoto
        badgeLabel = `Discord account certified by ${certifierInfo.name}`
        badgeIconURL = certifierInfo.iconUrl
        badgeClickURL = 'https://socialcert.net' // TODO Make a specific page for this.
        break
      case KNOWN_IDENTITY_TYPES.emailCert:
        name = decryptedFields.email
        avatarURL = 'XUTZxep7BBghAJbSBwTjNfmcsDdRFs5EaGEgkESGSgjJVYgMEizu'
        badgeLabel = `Email certified by ${certifierInfo.name}`
        badgeIconURL = certifierInfo.iconUrl
        badgeClickURL = 'https://socialcert.net' // TODO Make a specific page for this.
        break
      case KNOWN_IDENTITY_TYPES.phoneCert:
        name = decryptedFields.phoneNumber
        avatarURL = 'XUTLxtX3ELNUwRhLwL7kWNGbdnFM8WG2eSLv84J7654oH8HaJWrU'
        badgeLabel = `Phone certified by ${certifierInfo.name}`
        badgeIconURL = certifierInfo.iconUrl
        badgeClickURL = 'https://socialcert.net' // TODO Make a specific page for this.
        break
      case KNOWN_IDENTITY_TYPES.identiCert:
        name = `${decryptedFields.firstName} ${decryptedFields.lastName}`
        avatarURL = decryptedFields.profilePhoto
        badgeLabel = `Government ID certified by ${certifierInfo.name}`
        badgeIconURL = certifierInfo.iconUrl
        badgeClickURL = 'https://identicert.me' // TODO Make a specific page for this.
        break
      case KNOWN_IDENTITY_TYPES.registrant:
        name = decryptedFields.name
        avatarURL = decryptedFields.icon
        badgeLabel = `Entity certified by ${certifierInfo.name}`
        badgeIconURL = certifierInfo.iconUrl
        badgeClickURL = 'https://projectbabbage.com/docs/registrant' // TODO: Make this doc page exist
        break
      case KNOWN_IDENTITY_TYPES.coolCert:
        name = decryptedFields.cool === 'true' ? 'Cool Person!' : 'Not cool!'
        break
      case KNOWN_IDENTITY_TYPES.anyone:
        name = 'Anyone'
        avatarURL = 'XUT4bpQ6cpBaXi1oMzZsXfpkWGbtp2JTUYAoN7PzhStFJ6wLfoeR'
        badgeLabel =
          'Represents the ability for anyone to access this information.'
        badgeIconURL = 'XUUV39HVPkpmMzYNTx7rpKzJvXfeiVyQWg2vfSpjBAuhunTCA9uG'
        badgeClickURL = 'https://projectbabbage.com/docs/anyone-identity' // TODO: Make this doc page exist
        break
      case KNOWN_IDENTITY_TYPES.self:
        name = 'You'
        avatarURL = 'XUT9jHGk2qace148jeCX5rDsMftkSGYKmigLwU2PLLBc7Hm63VYR'
        badgeLabel = 'Represents your ability to access this information.'
        badgeIconURL = 'XUUV39HVPkpmMzYNTx7rpKzJvXfeiVyQWg2vfSpjBAuhunTCA9uG'
        badgeClickURL = 'https://projectbabbage.com/docs/self-identity' // TODO: Make this doc page exist
        break
      default: {
        const parsed = IdentityClient.tryToParseGenericIdentity(
          type,
          decryptedFields,
          certifierInfo
        )
        name = parsed.name
        avatarURL = parsed.avatarURL
        badgeLabel = parsed.badgeLabel
        badgeIconURL = parsed.badgeIconURL
        badgeClickURL = parsed.badgeClickURL
        break
      }
    }

    return {
      name,
      avatarURL,
      abbreviatedKey:
        identityToParse.subject.length > 0
          ? `${identityToParse.subject.substring(0, 10)}...`
          : '',
      identityKey: identityToParse.subject,
      badgeIconURL,
      badgeLabel,
      badgeClickURL
    }
  }

  /**
   * Helper to check if a value is a non-empty string
   */
  private static hasValue (value: any): value is string {
    return value !== undefined && value !== null && value !== ''
  }

  /**
   * Try to parse identity information from unknown certificate types
   * by checking common field names
   */
  private static tryToParseGenericIdentity (
    type: string,
    decryptedFields: Record<string, any>,
    certifierInfo: any
  ): {
      name: string
      avatarURL: string
      badgeLabel: string
      badgeIconURL: string
      badgeClickURL: string
    } {
    // Try to construct a name from common field patterns
    const firstName = decryptedFields.firstName
    const lastName = decryptedFields.lastName
    const fullName =
      IdentityClient.hasValue(firstName) && IdentityClient.hasValue(lastName)
        ? `${firstName} ${lastName}`
        : IdentityClient.hasValue(firstName)
          ? firstName
          : IdentityClient.hasValue(lastName)
            ? lastName
            : undefined

    const name = IdentityClient.hasValue(decryptedFields.name)
      ? decryptedFields.name
      : IdentityClient.hasValue(decryptedFields.userName)
        ? decryptedFields.userName
        : (fullName ??
          (IdentityClient.hasValue(decryptedFields.email)
            ? decryptedFields.email
            : defaultIdentity.name))

    // Try to find an avatar/photo from common field names
    const avatarURL = IdentityClient.hasValue(decryptedFields.profilePhoto)
      ? decryptedFields.profilePhoto
      : IdentityClient.hasValue(decryptedFields.avatar)
        ? decryptedFields.avatar
        : IdentityClient.hasValue(decryptedFields.icon)
          ? decryptedFields.icon
          : IdentityClient.hasValue(decryptedFields.photo)
            ? decryptedFields.photo
            : defaultIdentity.avatarURL

    // Generate badge information
    const badgeLabel = IdentityClient.hasValue(certifierInfo?.name)
      ? `${type} certified by ${String(certifierInfo.name)}`
      : defaultIdentity.badgeLabel

    const badgeIconURL = IdentityClient.hasValue(certifierInfo?.iconUrl)
      ? certifierInfo.iconUrl
      : defaultIdentity.badgeIconURL
    const badgeClickURL = defaultIdentity.badgeClickURL

    return { name, avatarURL, badgeLabel, badgeIconURL, badgeClickURL }
  }
}
