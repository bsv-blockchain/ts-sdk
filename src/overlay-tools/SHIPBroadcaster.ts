import {
  Transaction,
  BroadcastResponse,
  BroadcastFailure,
  Broadcaster
} from '../transaction/index.js'
import * as Utils from '../primitives/utils.js'
import LookupResolver from './LookupResolver.js'
import OverlayAdminTokenTemplate from './OverlayAdminTokenTemplate.js'

/**
 * Tagged BEEF
 *
 * @description
 * Tagged BEEF ([Background Evaluation Extended Format](https://brc.dev/62)) structure. Comprises a transaction, its SPV information, and the overlay topics where its inclusion is requested.
 */
export interface TaggedBEEF {
  beef: number[]
  topics: string[]
  offChainValues?: number[]
}

/**
 * Instructs the Overlay Services Engine about which outputs to admit and which previous outputs to retain. Returned by a Topic Manager.
 */
export interface AdmittanceInstructions {
  /**
   * The indices of all admissible outputs into the managed topic from the provided transaction.
   */
  outputsToAdmit: number[]

  /**
   * The indices of all inputs from the provided transaction which spend previously-admitted outputs that should be retained for historical record-keeping.
   */
  coinsToRetain: number[]

  /**
   * The indices of all inputs from the provided transaction which reference previously-admitted outputs,
   * which are now considered spent and have been removed from the managed topic.
   */
  coinsRemoved?: number[]
}

/**
 * Submitted Transaction Execution AcKnowledgment
 *
 * @description
 * Comprises the topics where a transaction was submitted, and for each one, the output indices for the UTXOs newly admitted into the topics, and the coins retained.
 * An object whose keys are topic names and whose values are topical admittance instructions denoting the state of the submitted transaction with respect to the associated topic.
 */
export type STEAK = Record<string, AdmittanceInstructions>

/** Configuration options for the SHIP broadcaster. */
export interface SHIPBroadcasterConfig {
  /**
   * The network preset to use, unless other options override it.
   * - mainnet: use mainnet resolver and HTTPS facilitator
   * - testnet: use testnet resolver and HTTPS facilitator
   * - local: directly send to localhost:8080 and a facilitator that permits plain HTTP
   */
  networkPreset?: 'mainnet' | 'testnet' | 'local'
  /** The facilitator used to make requests to Overlay Services hosts. */
  facilitator?: OverlayBroadcastFacilitator
  /** The resolver used to locate suitable hosts with SHIP */
  resolver?: LookupResolver
  /** Determines which topics (all, any, or a specific list) must be present within all STEAKs received from every host for the broadcast to be considered a success. By default, all hosts must acknowledge all topics. */
  requireAcknowledgmentFromAllHostsForTopics?: 'all' | 'any' | string[]
  /** Determines which topics (all, any, or a specific list) must be present within STEAK received from at least one host for the broadcast to be considered a success. */
  requireAcknowledgmentFromAnyHostForTopics?: 'all' | 'any' | string[]
  /** Determines a mapping whose keys are specific hosts and whose values are the topics (all, any, or a specific list) that must be present within the STEAK received by the given hosts, in order for the broadcast to be considered a success. */
  requireAcknowledgmentFromSpecificHostsForTopics?: Record<string, 'all' | 'any' | string[]>
}

/** Facilitates transaction broadcasts that return STEAK. */
export interface OverlayBroadcastFacilitator {
  send: (url: string, taggedBEEF: TaggedBEEF) => Promise<STEAK>
}

const MAX_SHIP_QUERY_TIMEOUT = 5000

export class HTTPSOverlayBroadcastFacilitator implements OverlayBroadcastFacilitator {
  httpClient: typeof fetch
  allowHTTP: boolean

  constructor (httpClient = fetch, allowHTTP: boolean = false) {
    this.httpClient = httpClient
    this.allowHTTP = allowHTTP
  }

  async send (url: string, taggedBEEF: TaggedBEEF): Promise<STEAK> {
    if (!url.startsWith('https:') && !this.allowHTTP) {
      throw new Error(
        'HTTPS facilitator can only use URLs that start with "https:"'
      )
    }
    const headers = {
      'Content-Type': 'application/octet-stream',
      'X-Topics': JSON.stringify(taggedBEEF.topics)
    }
    let body
    if (Array.isArray(taggedBEEF.offChainValues)) {
      headers['x-includes-off-chain-values'] = 'true'
      const w = new Utils.Writer()
      w.writeVarIntNum(taggedBEEF.beef.length)
      w.write(taggedBEEF.beef)
      w.write(taggedBEEF.offChainValues)
      body = new Uint8Array(w.toArray())
    } else {
      body = new Uint8Array(taggedBEEF.beef)
    }
    const response = await fetch(`${url}/submit`, {
      method: 'POST',
      headers,
      body
    })
    if (response.ok) {
      return await response.json()
    } else {
      throw new Error('Failed to facilitate broadcast')
    }
  }
}

/**
 * Broadcasts transactions to one or more overlay topics.
 */
export default class TopicBroadcaster implements Broadcaster {
  private readonly topics: string[]
  private readonly facilitator: OverlayBroadcastFacilitator
  private readonly resolver: LookupResolver
  private readonly requireAcknowledgmentFromAllHostsForTopics: | 'all' | 'any' | string[]
  private readonly requireAcknowledgmentFromAnyHostForTopics: | 'all' | 'any' | string[]
  private readonly requireAcknowledgmentFromSpecificHostsForTopics: Record<string, 'all' | 'any' | string[]>
  private readonly networkPreset: 'mainnet' | 'testnet' | 'local'

  /**
   * Constructs an instance of the SHIP broadcaster.
   *
   * @param {string[]} topics - The list of SHIP topic names where transactions are to be sent.
   * @param {SHIPBroadcasterConfig} config - Configuration options for the SHIP broadcaster.
   */
  constructor (topics: string[], config: SHIPBroadcasterConfig = {}) {
    if (topics.length === 0) {
      throw new Error('At least one topic is required for broadcast.')
    }
    if (topics.some((x) => !x.startsWith('tm_'))) {
      throw new Error('Every topic must start with "tm_".')
    }
    this.topics = topics
    this.networkPreset = config.networkPreset ?? 'mainnet'
    this.facilitator = config.facilitator ?? new HTTPSOverlayBroadcastFacilitator(undefined, this.networkPreset === 'local')
    this.resolver = config.resolver ?? new LookupResolver({ networkPreset: this.networkPreset })
    this.requireAcknowledgmentFromAllHostsForTopics =
      config.requireAcknowledgmentFromAllHostsForTopics ?? []
    this.requireAcknowledgmentFromAnyHostForTopics =
      config.requireAcknowledgmentFromAnyHostForTopics ?? 'all'
    this.requireAcknowledgmentFromSpecificHostsForTopics =
      config.requireAcknowledgmentFromSpecificHostsForTopics ?? {}
  }

  /**
   * Broadcasts a transaction to Overlay Services via SHIP.
   *
   * @param {Transaction} tx - The transaction to be sent.
   * @returns {Promise<BroadcastResponse | BroadcastFailure>} A promise that resolves to either a success or failure response.
   */
  async broadcast (
    tx: Transaction
  ): Promise<BroadcastResponse | BroadcastFailure> {
    let beef: number[]
    const offChainValues = tx.metadata.get('OffChainValues') as number[]
    try {
      beef = tx.toBEEF()
    } catch (error) {
      throw new Error(
        'Transactions sent via SHIP to Overlay Services must be serializable to BEEF format.'
      )
    }
    const interestedHosts = await this.findInterestedHosts()
    if (Object.keys(interestedHosts).length === 0) {
      return {
        status: 'error',
        code: 'ERR_NO_HOSTS_INTERESTED',
        description: `No ${this.networkPreset} hosts are interested in receiving this transaction.`
      }
    }
    const hostPromises = Object.entries(interestedHosts).map(
      async ([host, topics]) => {
        try {
          const steak = await this.facilitator.send(host, {
            beef,
            offChainValues,
            topics: [...topics]
          })
          if (steak == null || Object.keys(steak).length === 0) {
            throw new Error('Steak has no topics.')
          }
          return { host, success: true, steak }
        } catch (error) {
          console.error(error)
          // Log error if needed
          return { host, success: false, error }
        }
      }
    )

    const results = await Promise.all(hostPromises)
    const successfulHosts = results.filter((result) => result.success)

    if (successfulHosts.length === 0) {
      return {
        status: 'error',
        code: 'ERR_ALL_HOSTS_REJECTED',
        description: `All ${this.networkPreset} topical hosts have rejected the transaction.`
      }
    }

    // Collect host acknowledgments
    const hostAcknowledgments: Record<string, Set<string>> = {}

    for (const result of successfulHosts) {
      const host = result.host
      const steak = result.steak as STEAK

      const acknowledgedTopics = new Set<string>()

      for (const [topic, instructions] of Object.entries(steak)) {
        const outputsToAdmit = instructions.outputsToAdmit
        const coinsToRetain = instructions.coinsToRetain
        const coinsRemoved = instructions.coinsRemoved as number[]

        if (
          outputsToAdmit?.length > 0 ||
          coinsToRetain?.length > 0 ||
          coinsRemoved?.length > 0
        ) {
          acknowledgedTopics.add(topic)
        }
      }

      hostAcknowledgments[host] = acknowledgedTopics
    }

    // Now, perform the checks

    // Check requireAcknowledgmentFromAllHostsForTopics
    let requiredTopicsAllHosts: string[]
    let requireAllHosts: 'all' | 'any'

    if (this.requireAcknowledgmentFromAllHostsForTopics === 'all') {
      requiredTopicsAllHosts = this.topics
      requireAllHosts = 'all'
    } else if (this.requireAcknowledgmentFromAllHostsForTopics === 'any') {
      requiredTopicsAllHosts = this.topics
      requireAllHosts = 'any'
    } else if (Array.isArray(this.requireAcknowledgmentFromAllHostsForTopics)) {
      requiredTopicsAllHosts = this.requireAcknowledgmentFromAllHostsForTopics
      requireAllHosts = 'all'
    } else {
      // Default to 'all' and 'all'
      requiredTopicsAllHosts = this.topics
      requireAllHosts = 'all'
    }

    if (requiredTopicsAllHosts.length > 0) {
      const allHostsAcknowledged = this.checkAcknowledgmentFromAllHosts(
        hostAcknowledgments,
        requiredTopicsAllHosts,
        requireAllHosts
      )
      if (!allHostsAcknowledged) {
        return {
          status: 'error',
          code: 'ERR_REQUIRE_ACK_FROM_ALL_HOSTS_FAILED',
          description: 'Not all hosts acknowledged the required topics.'
        }
      }
    }

    // Check requireAcknowledgmentFromAnyHostForTopics
    let requiredTopicsAnyHost: string[]
    let requireAnyHost: 'all' | 'any'

    if (this.requireAcknowledgmentFromAnyHostForTopics === 'all') {
      requiredTopicsAnyHost = this.topics
      requireAnyHost = 'all'
    } else if (this.requireAcknowledgmentFromAnyHostForTopics === 'any') {
      requiredTopicsAnyHost = this.topics
      requireAnyHost = 'any'
    } else if (Array.isArray(this.requireAcknowledgmentFromAnyHostForTopics)) {
      requiredTopicsAnyHost = this.requireAcknowledgmentFromAnyHostForTopics
      requireAnyHost = 'all'
    } else {
      // No requirement
      requiredTopicsAnyHost = []
      requireAnyHost = 'all'
    }

    if (requiredTopicsAnyHost.length > 0) {
      const anyHostAcknowledged = this.checkAcknowledgmentFromAnyHost(
        hostAcknowledgments,
        requiredTopicsAnyHost,
        requireAnyHost
      )
      if (!anyHostAcknowledged) {
        return {
          status: 'error',
          code: 'ERR_REQUIRE_ACK_FROM_ANY_HOST_FAILED',
          description: 'No host acknowledged the required topics.'
        }
      }
    }

    // Check requireAcknowledgmentFromSpecificHostsForTopics
    if (
      Object.keys(this.requireAcknowledgmentFromSpecificHostsForTopics).length >
      0
    ) {
      const specificHostsAcknowledged =
        this.checkAcknowledgmentFromSpecificHosts(
          hostAcknowledgments,
          this.requireAcknowledgmentFromSpecificHostsForTopics
        )
      if (!specificHostsAcknowledged) {
        return {
          status: 'error',
          code: 'ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED',
          description:
            'Specific hosts did not acknowledge the required topics.'
        }
      }
    }

    // If all checks pass, return success
    return {
      status: 'success',
      txid: tx.id('hex'),
      message: `Sent to ${successfulHosts.length} Overlay Services ${successfulHosts.length === 1 ? 'host' : 'hosts'}.`
    }
  }

  private checkAcknowledgmentFromAllHosts (
    hostAcknowledgments: Record<string, Set<string>>,
    requiredTopics: string[],
    require: 'all' | 'any'
  ): boolean {
    for (const acknowledgedTopics of Object.values(hostAcknowledgments)) {
      if (require === 'all') {
        for (const topic of requiredTopics) {
          if (!acknowledgedTopics.has(topic)) {
            return false
          }
        }
      } else if (require === 'any') {
        let anyAcknowledged = false
        for (const topic of requiredTopics) {
          if (acknowledgedTopics.has(topic)) {
            anyAcknowledged = true
            break
          }
        }
        if (!anyAcknowledged) {
          return false
        }
      }
    }
    return true
  }

  private checkAcknowledgmentFromAnyHost (
    hostAcknowledgments: Record<string, Set<string>>,
    requiredTopics: string[],
    require: 'all' | 'any'
  ): boolean {
    if (require === 'all') {
      // All required topics must be acknowledged by at least one host
      for (const acknowledgedTopics of Object.values(hostAcknowledgments)) {
        let acknowledgesAllRequiredTopics = true
        for (const topic of requiredTopics) {
          if (!acknowledgedTopics.has(topic)) {
            acknowledgesAllRequiredTopics = false
            break
          }
        }
        if (acknowledgesAllRequiredTopics) {
          return true
        }
      }
      return false
    } else {
      // At least one required topic must be acknowledged by at least one host
      for (const acknowledgedTopics of Object.values(hostAcknowledgments)) {
        for (const topic of requiredTopics) {
          if (acknowledgedTopics.has(topic)) {
            return true
          }
        }
      }
      return false
    }
  }

  private checkAcknowledgmentFromSpecificHosts (
    hostAcknowledgments: Record<string, Set<string>>,
    requirements: Record<string, 'all' | 'any' | string[]>
  ): boolean {
    for (const [host, requiredTopicsOrAllAny] of Object.entries(requirements)) {
      const acknowledgedTopics = hostAcknowledgments[host]
      if (acknowledgedTopics == null) {
        // Host did not respond successfully
        return false
      }
      let requiredTopics: string[]
      let require: 'all' | 'any'
      if (
        requiredTopicsOrAllAny === 'all' ||
        requiredTopicsOrAllAny === 'any'
      ) {
        require = requiredTopicsOrAllAny
        requiredTopics = this.topics
      } else if (Array.isArray(requiredTopicsOrAllAny)) {
        requiredTopics = requiredTopicsOrAllAny
        require = 'all'
      } else {
        // Invalid configuration
        continue
      }
      if (require === 'all') {
        for (const topic of requiredTopics) {
          if (!acknowledgedTopics.has(topic)) {
            return false
          }
        }
      } else if (require === 'any') {
        let anyAcknowledged = false
        for (const topic of requiredTopics) {
          if (acknowledgedTopics.has(topic)) {
            anyAcknowledged = true
            break
          }
        }
        if (!anyAcknowledged) {
          return false
        }
      }
    }
    return true
  }

  /**
   * Finds which hosts are interested in transactions tagged with the given set of topics.
   *
   * @returns A mapping of URLs for hosts interested in this transaction. Keys are URLs, values are which of our topics the specific host cares about.
   */
  private async findInterestedHosts (): Promise<Record<string, Set<string>>> {
    // Handle the local network preset
    if (this.networkPreset === 'local') {
      const resultSet = new Set<string>()
      for (let i = 0; i < this.topics.length; i++) {
        resultSet.add(this.topics[i])
      }
      return { 'http://localhost:8080': resultSet }
    }
    // TODO: cache the list of interested hosts to avoid spamming SHIP trackers.
    // TODO: Monetize the operation of the SHIP tracker system.
    // TODO: Cache ship/slap lookup with expiry (every 5min)

    // Find all SHIP advertisements for the topics we care about
    const results: Record<string, Set<string>> = {}
    const answer = await this.resolver.query(
      {
        service: 'ls_ship',
        query: {
          topics: this.topics
        }
      },
      MAX_SHIP_QUERY_TIMEOUT
    )
    if (answer.type !== 'output-list') {
      throw new Error('SHIP answer is not an output list.')
    }
    for (const output of answer.outputs) {
      try {
        const tx = Transaction.fromBEEF(output.beef)
        const script = tx.outputs[output.outputIndex].lockingScript
        const parsed = OverlayAdminTokenTemplate.decode(script)
        if (
          !this.topics.includes(parsed.topicOrService) ||
          parsed.protocol !== 'SHIP'
        ) {
          // This should make us think a LOT less highly of this SHIP tracker if it ever happens...
          continue
        }
        if (results[parsed.domain] === undefined) {
          results[parsed.domain] = new Set()
        }
        results[parsed.domain].add(parsed.topicOrService)
      } catch (e) {
        continue
      }
    }
    return results
  }
}
