import PushDrop from '../script/templates/PushDrop.js'
import { OriginatorDomainNameStringUnder250Bytes, WalletInterface } from '../wallet/Wallet.interfaces.js'
import {
  LockingScript,
  ScriptTemplate,
  UnlockingScript
} from '../script/index.js'
import { Transaction } from '../transaction/index.js'
import { Utils } from '../primitives/index.js'

/**
 * Script template enabling the creation, unlocking, and decoding of SHIP and SLAP advertisements.
 */
export default class OverlayAdminTokenTemplate implements ScriptTemplate {
  pushDrop: PushDrop

  /**
   * Decodes a SHIP or SLAP advertisement from a given locking script.
   * @param script Locking script comprising a SHIP or SLAP token to decode
   * @returns Decoded SHIP or SLAP advertisement
   */
  static decode (script: LockingScript): {
    protocol: 'SHIP' | 'SLAP'
    identityKey: string
    domain: string
    topicOrService: string
  } {
    const result = PushDrop.decode(script)
    if (result.fields.length < 4) {
      throw new Error('Invalid SHIP/SLAP advertisement!')
    }
    const protocol = Utils.toUTF8(result.fields[0])
    if (protocol !== 'SHIP' && protocol !== 'SLAP') {
      throw new Error('Invalid protocol type!')
    }
    const identityKey = Utils.toHex(result.fields[1])
    const domain = Utils.toUTF8(result.fields[2])
    const topicOrService = Utils.toUTF8(result.fields[3])
    return {
      protocol,
      identityKey,
      domain,
      topicOrService
    }
  }

  /**
   * Constructs a new Overlay Admin template instance
   * @param wallet Wallet to use for locking and unlocking
   */
  constructor (wallet: WalletInterface, originator?: OriginatorDomainNameStringUnder250Bytes) {
    this.pushDrop = new PushDrop(wallet, originator)
  }

  /**
   * Creates a new advertisement locking script
   * @param protocol SHIP or SLAP
   * @param domain Domain where the topic or service is available
   * @param topicOrService Topic or service to advertise
   * @returns Locking script comprising the advertisement token
   */
  async lock (
    protocol: 'SHIP' | 'SLAP',
    domain: string,
    topicOrService: string
  ): Promise<LockingScript> {
    const { publicKey: identityKey } = await this.pushDrop.wallet.getPublicKey({
      identityKey: true
    })
    return await this.pushDrop.lock(
      [
        Utils.toArray(protocol, 'utf8'),
        Utils.toArray(identityKey, 'hex'),
        Utils.toArray(domain, 'utf8'),
        Utils.toArray(topicOrService, 'utf8')
      ],
      [
        2,
        protocol === 'SHIP'
          ? 'Service Host Interconnect'
          : 'Service Lookup Availability'
      ],
      '1',
      'self'
    )
  }

  /**
   * Unlocks an advertisement token as part of a transaction.
   * @param protocol SHIP or SLAP, depending on the token to unlock
   * @returns Script unlocker capable of unlocking the advertisement token
   */
  unlock (protocol: 'SHIP' | 'SLAP'): {
    sign: (tx: Transaction, inputIndex: number) => Promise<UnlockingScript>
    estimateLength: (tx: Transaction, inputIndex: number) => Promise<number>
  } {
    return this.pushDrop.unlock(
      [
        2,
        protocol === 'SHIP'
          ? 'Service Host Interconnect'
          : 'Service Lookup Availability'
      ],
      '1',
      'self'
    )
  }
}
