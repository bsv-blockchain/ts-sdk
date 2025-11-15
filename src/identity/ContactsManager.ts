import { PubKeyHex, WalletClient, WalletInterface, WalletProtocol } from '../wallet/index.js'
import { Utils, Random } from '../primitives/index.js'
import { DisplayableIdentity } from './types/index.js'
import { LockingScript, PushDrop } from '../script/index.js'
import { Transaction } from '../transaction/index.js'
export type Contact = DisplayableIdentity & { metadata?: Record<string, any> }

const CONTACT_PROTOCOL_ID: WalletProtocol = [2, 'contact']

// In-memory cache for cross-platform compatibility
class MemoryCache {
  private readonly cache = new Map<string, string>()

  getItem (key: string): string | null {
    return this.cache.get(key) ?? null
  }

  setItem (key: string, value: string): void {
    this.cache.set(key, value)
  }

  removeItem (key: string): void {
    this.cache.delete(key)
  }

  clear (): void {
    this.cache.clear()
  }
}

export class ContactsManager {
  private readonly wallet: WalletInterface
  private readonly cache = new MemoryCache()
  private readonly CONTACTS_CACHE_KEY = 'metanet-contacts'
  private readonly originator?: string

  constructor (wallet?: WalletInterface, originator?: string) {
    this.wallet = wallet ?? new WalletClient()
    this.originator = originator
  }

  /**
   * Load all records from the contacts basket
   * @param identityKey Optional specific identity key to fetch
   * @param forceRefresh Whether to force a check for new contact data
   * @param limit Maximum number of contacts to return
   * @returns A promise that resolves with an array of contacts
   */
  async getContacts (identityKey?: PubKeyHex, forceRefresh = false, limit = 1000): Promise<Contact[]> {
    // Check in-memory cache first unless forcing refresh
    if (!forceRefresh) {
      const cached = this.cache.getItem(this.CONTACTS_CACHE_KEY)
      if (cached != null && cached !== '') {
        try {
          const cachedContacts: Contact[] = JSON.parse(cached)
          return identityKey != null
            ? cachedContacts.filter(c => c.identityKey === identityKey)
            : cachedContacts
        } catch (e) {
          console.warn('Invalid cached contacts JSON; will reload from chain', e)
        }
      }
    }

    const tags: string[] = []
    if (identityKey != null) {
      // Hash the identity key to use as a tag for quick lookup
      const { hmac: hashedIdentityKey } = await this.wallet.createHmac({
        protocolID: CONTACT_PROTOCOL_ID,
        keyID: identityKey,
        counterparty: 'self',
        data: Utils.toArray(identityKey, 'utf8')
      }, this.originator)
      tags.push(`identityKey ${Utils.toHex(hashedIdentityKey)}`)
    }

    // Get all contact outputs from the contacts basket
    const outputs = await this.wallet.listOutputs({
      basket: 'contacts',
      include: 'locking scripts',
      includeCustomInstructions: true,
      tags,
      limit
    }, this.originator)

    if (outputs.outputs == null || outputs.outputs.length === 0) {
      this.cache.setItem(this.CONTACTS_CACHE_KEY, JSON.stringify([]))
      return []
    }

    const contacts: Contact[] = []

    // Process each contact output
    for (const output of outputs.outputs) {
      try {
        if (output.lockingScript == null) continue

        // Decode the PushDrop data
        const decoded = PushDrop.decode(LockingScript.fromHex(output.lockingScript))
        if (output.customInstructions == null) continue
        const keyID = JSON.parse(output.customInstructions).keyID

        // Decrypt the contact data
        const { plaintext } = await this.wallet.decrypt({
          ciphertext: decoded.fields[0],
          protocolID: CONTACT_PROTOCOL_ID,
          keyID,
          counterparty: 'self'
        }, this.originator)

        // Parse the contact data
        const contactData: Contact = JSON.parse(Utils.toUTF8(plaintext))

        contacts.push(contactData)
      } catch (error) {
        console.warn('ContactsManager: Failed to decode contact output:', error)
        // Skip this contact and continue with others
      }
    }

    // Cache the loaded contacts
    this.cache.setItem(this.CONTACTS_CACHE_KEY, JSON.stringify(contacts))
    const filteredContacts = identityKey != null
      ? contacts.filter(c => c.identityKey === identityKey)
      : contacts
    return filteredContacts
  }

  /**
   * Save or update a Metanet contact
   * @param contact The displayable identity information for the contact
   * @param metadata Optional metadata to store with the contact (ex. notes, aliases, etc)
   */
  async saveContact (contact: DisplayableIdentity, metadata?: Record<string, any>): Promise<void> {
    // Get current contacts from cache or blockchain
    const cached = this.cache.getItem(this.CONTACTS_CACHE_KEY)
    let contacts: Contact[]
    if (cached != null && cached !== '') {
      contacts = JSON.parse(cached)
    } else {
      // If cache is empty, get current data from blockchain
      contacts = await this.getContacts()
    }

    const existingIndex = contacts.findIndex(c => c.identityKey === contact.identityKey)
    const contactToStore: Contact = {
      ...contact,
      metadata
    }

    if (existingIndex >= 0) {
      contacts[existingIndex] = contactToStore
    } else {
      contacts.push(contactToStore)
    }

    const { hmac: hashedIdentityKey } = await this.wallet.createHmac({
      protocolID: CONTACT_PROTOCOL_ID,
      keyID: contact.identityKey,
      counterparty: 'self',
      data: Utils.toArray(contact.identityKey, 'utf8')
    }, this.originator)

    // Check if this contact already exists (to update it)
    const outputs = await this.wallet.listOutputs({
      basket: 'contacts',
      include: 'entire transactions',
      includeCustomInstructions: true,
      tags: [`identityKey ${Utils.toHex(hashedIdentityKey)}`],
      limit: 100 // Should only be one contact!
    }, this.originator)

    let existingOutput: any = null
    let keyID = Utils.toBase64(Random(32))
    if (outputs.outputs != null) {
      // Find output by trying to decrypt and checking identityKey in payload
      for (const output of outputs.outputs) {
        try {
          const [txid, outputIndex] = output.outpoint.split('.')
          const tx = Transaction.fromBEEF(outputs.BEEF as number[], txid)
          const decoded = PushDrop.decode(tx.outputs[Number(outputIndex)].lockingScript)
          if (output.customInstructions == null) continue
          keyID = JSON.parse(output.customInstructions).keyID

          const { plaintext } = await this.wallet.decrypt({
            ciphertext: decoded.fields[0],
            protocolID: CONTACT_PROTOCOL_ID,
            keyID,
            counterparty: 'self'
          }, this.originator)

          const storedContact: Contact = JSON.parse(Utils.toUTF8(plaintext))
          if (storedContact.identityKey === contact.identityKey) {
            // Found the right output
            existingOutput = output
            break
          }
        } catch (e) {
          // Skip malformed or undecryptable outputs
        }
      }
    }

    // Encrypt the contact data directly
    const contactWithMetadata: Contact = {
      ...contact,
      metadata
    }
    const { ciphertext } = await this.wallet.encrypt({
      plaintext: Utils.toArray(JSON.stringify(contactWithMetadata), 'utf8'),
      protocolID: CONTACT_PROTOCOL_ID,
      keyID,
      counterparty: 'self'
    }, this.originator)

    // Create locking script for the new contact token
    const lockingScript = await new PushDrop(this.wallet, this.originator).lock(
      [ciphertext],
      CONTACT_PROTOCOL_ID,
      keyID,
      'self'
    )

    if (existingOutput != null) {
      // Update existing contact by spending its output
      const [txid, outputIndex] = String(existingOutput.outpoint).split('.')
      const prevOutpoint = `${txid}.${outputIndex}` as const

      const pushdrop = new PushDrop(this.wallet, this.originator)
      const { signableTransaction } = await this.wallet.createAction({
        description: 'Update Contact',
        inputBEEF: outputs.BEEF as number[],
        inputs: [{
          outpoint: prevOutpoint,
          unlockingScriptLength: 74,
          inputDescription: 'Spend previous contact output'
        }],
        outputs: [{
          basket: 'contacts',
          satoshis: 1,
          lockingScript: lockingScript.toHex(),
          outputDescription: `Updated Contact: ${contact.name ?? contact.identityKey.slice(0, 10)}`,
          tags: [`identityKey ${Utils.toHex(hashedIdentityKey)}`],
          customInstructions: JSON.stringify({ keyID })
        }],
        options: { acceptDelayedBroadcast: false, randomizeOutputs: false } // TODO: Support custom config as needed.
      }, this.originator)

      if (signableTransaction == null) throw new Error('Unable to update contact')

      const unlocker = pushdrop.unlock(CONTACT_PROTOCOL_ID, keyID, 'self')
      const unlockingScript = await unlocker.sign(
        Transaction.fromBEEF(signableTransaction.tx),
        0
      )

      const { tx } = await this.wallet.signAction({
        reference: signableTransaction.reference,
        spends: { 0: { unlockingScript: unlockingScript.toHex() } }
      }, this.originator)

      if (tx == null) throw new Error('Failed to update contact output')
    } else {
      // Create new contact output
      const { tx } = await this.wallet.createAction({
        description: 'Add Contact',
        outputs: [{
          basket: 'contacts',
          satoshis: 1,
          lockingScript: lockingScript.toHex(),
          outputDescription: `Contact: ${contact.name ?? contact.identityKey.slice(0, 10)}`,
          tags: [`identityKey ${Utils.toHex(hashedIdentityKey)}`],
          customInstructions: JSON.stringify({ keyID })
        }],
        options: { acceptDelayedBroadcast: false, randomizeOutputs: false } // TODO: Support custom config as needed.
      }, this.originator)

      if (tx == null) throw new Error('Failed to create contact output')
    }
    this.cache.setItem(this.CONTACTS_CACHE_KEY, JSON.stringify(contacts))
  }

  /**
   * Remove a contact from the contacts basket
   * @param identityKey The identity key of the contact to remove
   */
  async removeContact (identityKey: string): Promise<void> {
    // Update in-memory cache
    const cached = this.cache.getItem(this.CONTACTS_CACHE_KEY)
    if (cached != null && cached !== '') {
      try {
        const contacts: Contact[] = JSON.parse(cached)
        const filteredContacts = contacts.filter(c => c.identityKey !== identityKey)
        this.cache.setItem(this.CONTACTS_CACHE_KEY, JSON.stringify(filteredContacts))
      } catch (e) {
        console.warn('Failed to update cache after contact removal:', e)
      }
    }

    // Hash the identity key to use as a tag for quick lookup
    const tags: string[] = []
    const { hmac: hashedIdentityKey } = await this.wallet.createHmac({
      protocolID: CONTACT_PROTOCOL_ID,
      keyID: identityKey,
      counterparty: 'self',
      data: Utils.toArray(identityKey, 'utf8')
    }, this.originator)
    tags.push(`identityKey ${Utils.toHex(hashedIdentityKey)}`)

    // Find and spend the contact's output
    const outputs = await this.wallet.listOutputs({
      basket: 'contacts',
      include: 'entire transactions',
      includeCustomInstructions: true,
      tags,
      limit: 100 // Should only be one contact!
    }, this.originator)

    if (outputs.outputs == null) return

    // Find the output for this specific contact by decrypting and checking identityKey
    for (const output of outputs.outputs) {
      try {
        const [txid, outputIndex] = String(output.outpoint).split('.')
        const tx = Transaction.fromBEEF(outputs.BEEF as number[], txid)
        const decoded = PushDrop.decode(tx.outputs[Number(outputIndex)].lockingScript)
        if (output.customInstructions == null) continue
        const keyID = JSON.parse(output.customInstructions).keyID

        const { plaintext } = await this.wallet.decrypt({
          ciphertext: decoded.fields[0],
          protocolID: CONTACT_PROTOCOL_ID,
          keyID,
          counterparty: 'self'
        }, this.originator)

        const storedContact: Contact = JSON.parse(Utils.toUTF8(plaintext))
        if (storedContact.identityKey === identityKey) {
          // Found the contact's output, spend it without creating a new one
          const prevOutpoint = `${txid}.${outputIndex}` as const

          const pushdrop = new PushDrop(this.wallet, this.originator)
          const { signableTransaction } = await this.wallet.createAction({
            description: 'Delete Contact',
            inputBEEF: outputs.BEEF as number[],
            inputs: [{
              outpoint: prevOutpoint,
              unlockingScriptLength: 74,
              inputDescription: 'Spend contact output to delete'
            }],
            outputs: [], // No outputs = deletion
            options: { acceptDelayedBroadcast: false, randomizeOutputs: false } // TODO: Support custom config as needed.
          }, this.originator)

          if (signableTransaction == null) throw new Error('Unable to delete contact')

          const unlocker = pushdrop.unlock(CONTACT_PROTOCOL_ID, keyID, 'self')
          const unlockingScript = await unlocker.sign(
            Transaction.fromBEEF(signableTransaction.tx),
            0
          )

          const { tx: deleteTx } = await this.wallet.signAction({
            reference: signableTransaction.reference,
            spends: { 0: { unlockingScript: unlockingScript.toHex() } }
          }, this.originator)

          if (deleteTx == null) throw new Error('Failed to delete contact output')
          return
        }
      } catch (e) {
        // Skip malformed or undecryptable outputs
      }
    }
  }
}
