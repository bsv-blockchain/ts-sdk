import { Transaction } from '../transaction/index.js'
import OverlayAdminTokenTemplate from './OverlayAdminTokenTemplate.js'
import * as Utils from '../primitives/utils.js'
import { getOverlayHostReputationTracker, HostReputationTracker } from './HostReputationTracker.js'

const defaultFetch: typeof fetch =
  typeof globalThis !== 'undefined' && typeof globalThis.fetch === 'function'
    ? globalThis.fetch.bind(globalThis)
    : fetch

/**
 * The question asked to the Overlay Services Engine when a consumer of state wishes to look up information.
 */
export interface LookupQuestion {
  /**
   * The identifier for a Lookup Service which the person asking the question wishes to use.
   */
  service: string

  /**
   * The query which will be forwarded to the Lookup Service.
   * Its type depends on that prescribed by the Lookup Service employed.
   */
  query: unknown
}

/**
 * How the Overlay Services Engine responds to a Lookup Question.
 * It may comprise either an output list or a freeform response from the Lookup Service.
 */
export type LookupAnswer =
  | {
    type: 'output-list'
    outputs: Array<{
      beef: number[]
      outputIndex: number
      context?: number[]
    }>
  }

/** Default SLAP trackers */
export const DEFAULT_SLAP_TRACKERS: string[] = [
  // BSVA clusters
  'https://overlay-us-1.bsvb.tech',
  'https://overlay-eu-1.bsvb.tech',
  'https://overlay-ap-1.bsvb.tech',

  // Babbage primary overlay service
  'https://users.bapp.dev'

  // NOTE: Other entities may submit pull requests to the library if they maintain SLAP overlay services.
  // Additional trackers run by different entities contribute to greater network resiliency.
  // It also generally doesn't hurt to have more trackers in this list.

  // DISCLAIMER:
  // Trackers known to host invalid or illegal records will be removed at the discretion of the BSV Association.
]

/** Default testnet SLAP trackers */
export const DEFAULT_TESTNET_SLAP_TRACKERS: string[] = [
  // Babbage primary testnet overlay service
  'https://testnet-users.bapp.dev'
]

const MAX_TRACKER_WAIT_TIME = 5000

/** Internal cache options. Kept optional to preserve drop-in compatibility. */
interface CacheOptions {
  /** How long (ms) a hosts entry is considered fresh. Default 5 minutes. */
  hostsTtlMs?: number
  /** How many distinct services’ hosts to cache before evicting. Default 128. */
  hostsMaxEntries?: number
  /** How long (ms) to keep txId memoization. Default 10 minutes. */
  txMemoTtlMs?: number
}

/** Configuration options for the Lookup resolver. */
export interface LookupResolverConfig {
  /**
   * The network preset to use, unless other options override it.
   * - mainnet: use mainnet SLAP trackers and HTTPS facilitator
   * - testnet: use testnet SLAP trackers and HTTPS facilitator
   * - local: directly query from localhost:8080 and a facilitator that permits plain HTTP
   */
  networkPreset?: 'mainnet' | 'testnet' | 'local'
  /** The facilitator used to make requests to Overlay Services hosts. */
  facilitator?: OverlayLookupFacilitator
  /** The list of SLAP trackers queried to resolve Overlay Services hosts for a given lookup service. */
  slapTrackers?: string[]
  /** Map of lookup service names to arrays of hosts to use in place of resolving via SLAP. */
  hostOverrides?: Record<string, string[]>
  /** Map of lookup service names to arrays of hosts to use in addition to resolving via SLAP. */
  additionalHosts?: Record<string, string[]>
  /** Optional cache tuning. */
  cache?: CacheOptions
  /** Optional storage for host reputation data. */
  reputationStorage?: 'localStorage' | { get: (key: string) => string | null | undefined, set: (key: string, value: string) => void }
}

/** Facilitates lookups to URLs that return answers. */
export interface OverlayLookupFacilitator {
  /**
   * Returns a lookup answer for a lookup question
   * @param url - Overlay Service URL to send the lookup question to.
   * @param question - Lookup question to find an answer to.
   * @param timeout - Specifics how long to wait for a lookup answer in milliseconds.
   * @returns
   */
  lookup: (
    url: string,
    question: LookupQuestion,
    timeout?: number
  ) => Promise<LookupAnswer>
}

export class HTTPSOverlayLookupFacilitator implements OverlayLookupFacilitator {
  fetchClient: typeof fetch
  allowHTTP: boolean

  constructor (httpClient = defaultFetch, allowHTTP: boolean = false) {
    if (typeof httpClient !== 'function') {
      throw new Error(
        'HTTPSOverlayLookupFacilitator requires a fetch implementation. ' +
        'In environments without fetch, provide a polyfill or custom implementation.'
      )
    }
    this.fetchClient = httpClient
    this.allowHTTP = allowHTTP
  }

  async lookup (
    url: string,
    question: LookupQuestion,
    timeout: number = 5000
  ): Promise<LookupAnswer> {
    if (!url.startsWith('https:') && !this.allowHTTP) {
      throw new Error(
        'HTTPS facilitator can only use URLs that start with "https:"'
      )
    }

    const controller = typeof AbortController !== 'undefined' ? new AbortController() : undefined
    const timer = setTimeout(() => {
      try { controller?.abort() } catch { /* noop */ }
    }, timeout)

    try {
      const fco: RequestInit = {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Aggregation': 'yes'
        },
        body: JSON.stringify({ service: question.service, query: question.query }),
        signal: controller?.signal
      }
      const response: Response = await this.fetchClient(`${url}/lookup`, fco)

      if (!response.ok) throw new Error(`Failed to facilitate lookup (HTTP ${response.status})`)
      if (response.headers.get('content-type') === 'application/octet-stream') {
        const payload = await response.arrayBuffer()
        const r = new Utils.Reader([...new Uint8Array(payload)])
        const nOutpoints = r.readVarIntNum()
        const outpoints: Array<{ txid: string, outputIndex: number, context?: number[] }> = []
        for (let i = 0; i < nOutpoints; i++) {
          const txid = Utils.toHex(r.read(32))
          const outputIndex = r.readVarIntNum()
          const contextLength = r.readVarIntNum()
          let context
          if (contextLength > 0) {
            context = r.read(contextLength)
          }
          outpoints.push({
            txid,
            outputIndex,
            context
          })
        }
        const beef = r.read()
        return {
          type: 'output-list',
          outputs: outpoints.map(x => ({
            outputIndex: x.outputIndex,
            context: x.context,
            beef: Transaction.fromBEEF(beef, x.txid).toBEEF()
          }))
        }
      } else {
        return await response.json()
      }
    } catch (e) {
      // Normalize timeouts to a consistent error message
      if ((e as any)?.name === 'AbortError') throw new Error('Request timed out')
      throw e
    } finally {
      clearTimeout(timer)
    }
  }
}

/**
 * Represents a Lookup Resolver.
 */
export default class LookupResolver {
  private readonly facilitator: OverlayLookupFacilitator
  private readonly slapTrackers: string[]
  private readonly hostOverrides: Record<string, string[]>
  private readonly additionalHosts: Record<string, string[]>
  private readonly networkPreset: 'mainnet' | 'testnet' | 'local'
  private readonly hostReputation: HostReputationTracker

  // ---- Caches / memoization ----
  private readonly hostsCache: Map<string, { hosts: string[], expiresAt: number }>
  private readonly hostsInFlight: Map<string, Promise<string[]>>
  private readonly hostsTtlMs: number
  private readonly hostsMaxEntries: number

  private readonly txMemo: Map<string, { txId: string, expiresAt: number }>
  private readonly txMemoTtlMs: number

  constructor (config: LookupResolverConfig = {}) {
    this.networkPreset = config.networkPreset ?? 'mainnet'
    this.facilitator = config.facilitator ?? new HTTPSOverlayLookupFacilitator(undefined, this.networkPreset === 'local')
    this.slapTrackers = config.slapTrackers ?? (this.networkPreset === 'mainnet' ? DEFAULT_SLAP_TRACKERS : DEFAULT_TESTNET_SLAP_TRACKERS)
    const hostOverrides = config.hostOverrides ?? {}
    this.assertValidOverrideServices(hostOverrides)
    this.hostOverrides = hostOverrides
    this.additionalHosts = config.additionalHosts ?? {}

    const rs = config.reputationStorage
    if (rs === 'localStorage') {
      this.hostReputation = new HostReputationTracker()
    } else if (typeof rs === 'object' && rs !== null && typeof rs.get === 'function' && typeof rs.set === 'function') {
      this.hostReputation = new HostReputationTracker(rs)
    } else {
      this.hostReputation = getOverlayHostReputationTracker()
    }

    // cache tuning
    this.hostsTtlMs = config.cache?.hostsTtlMs ?? 5 * 60 * 1000 // 5 min
    this.hostsMaxEntries = config.cache?.hostsMaxEntries ?? 128
    this.txMemoTtlMs = config.cache?.txMemoTtlMs ?? 10 * 60 * 1000 // 10 min

    this.hostsCache = new Map()
    this.hostsInFlight = new Map()
    this.txMemo = new Map()
  }

  /**
   * Given a LookupQuestion, returns a LookupAnswer. Aggregates across multiple services and supports resiliency.
   */
  async query (
    question: LookupQuestion,
    timeout?: number
  ): Promise<LookupAnswer> {
    let competentHosts: string[] = []
    if (question.service === 'ls_slap') {
      competentHosts = this.networkPreset === 'local' ? ['http://localhost:8080'] : this.slapTrackers
    } else if (this.hostOverrides[question.service] != null) {
      competentHosts = this.hostOverrides[question.service]
    } else if (this.networkPreset === 'local') {
      competentHosts = ['http://localhost:8080']
    } else {
      competentHosts = await this.getCompetentHostsCached(question.service)
    }
    if (this.additionalHosts[question.service]?.length > 0) {
      const extra = this.additionalHosts[question.service]
      const seen = new Set(competentHosts)
      for (const h of extra) if (!seen.has(h)) competentHosts.push(h)
    }
    if (competentHosts.length < 1) {
      throw new Error(
        `No competent ${this.networkPreset} hosts found by the SLAP trackers for lookup service: ${question.service}`
      )
    }

    const rankedHosts = this.prepareHostsForQuery(
      competentHosts,
      `lookup service ${question.service}`
    )
    if (rankedHosts.length < 1) {
      throw new Error(`All competent hosts for ${question.service} are temporarily unavailable due to backoff.`)
    }

    // Fire all hosts; resolve as soon as we have results from any host,
    // then allow a short grace window for additional hosts to contribute.
    const GRACE_MS = 80
    const answers: LookupAnswer[] = await new Promise<LookupAnswer[]>((resolve) => {
      const collected: LookupAnswer[] = []
      let pending = rankedHosts.length
      let graceTimer: ReturnType<typeof setTimeout> | null = null

      const tryResolve = (): void => {
        if (graceTimer !== null) clearTimeout(graceTimer)
        resolve(collected)
      }

      for (const host of rankedHosts) {
        this.lookupHostWithTracking(host, question, timeout)
          .then((answer) => {
            if (answer?.type === 'output-list' && Array.isArray(answer.outputs) && answer.outputs.length > 0) {
              collected.push(answer)
              // First valid response: start a grace window for others
              if (collected.length === 1 && pending > 1) {
                graceTimer = setTimeout(tryResolve, GRACE_MS)
              }
            }
          })
          .catch(() => { /* host failed; tracked by lookupHostWithTracking */ })
          .finally(() => {
            pending--
            if (pending === 0) tryResolve()
          })
      }
    })

    const outputsMap = new Map<string, { beef: number[], context?: number[], outputIndex: number }>()

    // Memo key helper for tx parsing
    const beefKey = (beef: number[]): string => {
      if (typeof beef !== 'object') return '' // The invalid BEEF has an empty key.
      return beef.join(',')
    }

    for (const response of answers) {
      for (const output of response.outputs) {
        const keyForBeef = beefKey(output.beef)
        let memo = this.txMemo.get(keyForBeef)
        const now = Date.now()
        if (typeof memo !== 'object' || memo === null || memo.expiresAt <= now) {
          try {
            const txId = Transaction.fromBEEF(output.beef).id('hex')
            memo = { txId, expiresAt: now + this.txMemoTtlMs }
            if (this.txMemo.size > 4096) this.evictOldest(this.txMemo)
            this.txMemo.set(keyForBeef, memo)
          } catch {
            continue
          }
        }

        const uniqKey = `${memo.txId}.${output.outputIndex}`
        outputsMap.set(uniqKey, output)
      }
    }
    return {
      type: 'output-list',
      outputs: Array.from(outputsMap.values())
    }
  }

  /**
   * Cached wrapper for competent host discovery with stale-while-revalidate.
   */
  private async getCompetentHostsCached (service: string): Promise<string[]> {
    const now = Date.now()
    const cached = this.hostsCache.get(service)

    // if fresh, return immediately
    if (typeof cached === 'object' && cached.expiresAt > now) {
      return cached.hosts.slice()
    }

    // if stale but present, kick off a refresh if not already in-flight and return stale
    if (typeof cached === 'object' && cached.expiresAt <= now) {
      if (!this.hostsInFlight.has(service)) {
        this.hostsInFlight.set(service, this.refreshHosts(service).finally(() => {
          this.hostsInFlight.delete(service)
        }))
      }
      return cached.hosts.slice()
    }

    // no cache: coalesce concurrent requests
    if (this.hostsInFlight.has(service)) {
      try {
        const hosts = await this.hostsInFlight.get(service)
        if (typeof hosts !== 'object') {
          throw new Error('Hosts is not defined.')
        }
        return hosts.slice()
      } catch {
        // fall through to a fresh attempt below
      }
    }

    const promise = this.refreshHosts(service).finally(() => {
      this.hostsInFlight.delete(service)
    })
    this.hostsInFlight.set(service, promise)
    const hosts = await promise
    return hosts.slice()
  }

  /**
   * Actually resolves competent hosts from SLAP trackers and updates cache.
   */
  private async refreshHosts (service: string): Promise<string[]> {
    const hosts = await this.findCompetentHosts(service)
    const expiresAt = Date.now() + this.hostsTtlMs

    // bounded cache with simple FIFO eviction
    if (!this.hostsCache.has(service) && this.hostsCache.size >= this.hostsMaxEntries) {
      const oldestKey = this.hostsCache.keys().next().value
      if (oldestKey !== undefined) this.hostsCache.delete(oldestKey)
    }
    this.hostsCache.set(service, { hosts, expiresAt })
    return hosts
  }

  /**
   * Extracts competent host domains from a SLAP tracker response.
   */
  private extractHostsFromAnswer (answer: LookupAnswer, service: string): string[] {
    const hosts: string[] = []
    if (answer.type !== 'output-list') return hosts
    for (const output of answer.outputs) {
      try {
        const tx = Transaction.fromBEEF(output.beef)
        const script = tx.outputs[output.outputIndex]?.lockingScript
        if (typeof script !== 'object' || script === null) continue
        const parsed = OverlayAdminTokenTemplate.decode(script)
        if (parsed.topicOrService !== service || parsed.protocol !== 'SLAP') continue
        if (typeof parsed.domain === 'string' && parsed.domain.length > 0) {
          hosts.push(parsed.domain)
        }
      } catch {
        continue
      }
    }
    return hosts
  }

  /**
   * Returns a list of competent hosts for a given lookup service.
   * Resolves as soon as the first SLAP tracker responds with valid hosts.
   * Remaining trackers continue in the background for reputation tracking.
   * @param service Service for which competent hosts are to be returned
   * @returns Array of hosts competent for resolving queries
   */
  private async findCompetentHosts (service: string): Promise<string[]> {
    const query: LookupQuestion = {
      service: 'ls_slap',
      query: { service }
    }

    const trackerHosts = this.prepareHostsForQuery(
      this.slapTrackers,
      'SLAP trackers'
    )
    if (trackerHosts.length === 0) return []

    // Fire all trackers, resolve as soon as any returns valid hosts.
    // Remaining trackers continue in the background for reputation tracking.
    return await new Promise<string[]>((resolve) => {
      const allHosts = new Set<string>()
      let resolved = false
      let pending = trackerHosts.length

      for (const tracker of trackerHosts) {
        this.lookupHostWithTracking(tracker, query, MAX_TRACKER_WAIT_TIME)
          .then((answer) => {
            const hosts = this.extractHostsFromAnswer(answer, service)
            for (const h of hosts) allHosts.add(h)
            if (!resolved && allHosts.size > 0) {
              resolved = true
              resolve([...allHosts])
            }
          })
          .catch(() => { /* tracker failed; tracked by lookupHostWithTracking */ })
          .finally(() => {
            pending--
            if (pending === 0 && !resolved) {
              resolved = true
              resolve([...allHosts])
            }
          })
      }
    })
  }

  /** Evict an arbitrary “oldest” entry from a Map (iteration order). */
  private evictOldest<T>(m: Map<string, T>): void {
    const firstKey = m.keys().next().value
    if (firstKey !== undefined) m.delete(firstKey)
  }

  private assertValidOverrideServices (overrides: Record<string, string[]>): void {
    for (const service of Object.keys(overrides)) {
      if (!service.startsWith('ls_')) {
        throw new Error(`Host override service names must start with "ls_": ${service}`)
      }
    }
  }

  private prepareHostsForQuery (hosts: string[], context: string): string[] {
    if (hosts.length === 0) return []
    const now = Date.now()
    const ranked = this.hostReputation.rankHosts(hosts, now)
    const available = ranked.filter((h) => h.backoffUntil <= now).map((h) => h.host)
    if (available.length > 0) return available

    const soonest = Math.min(...ranked.map((h) => h.backoffUntil))
    const waitMs = Math.max(soonest - now, 0)
    throw new Error(
      `All ${context} hosts are backing off for approximately ${waitMs}ms due to repeated failures.`
    )
  }

  private async lookupHostWithTracking (
    host: string,
    question: LookupQuestion,
    timeout?: number
  ): Promise<LookupAnswer> {
    const startedAt = Date.now()
    try {
      const answer = await this.facilitator.lookup(host, question, timeout)
      const latency = Date.now() - startedAt
      const isValid =
        typeof answer === 'object' &&
        answer !== null &&
        answer.type === 'output-list' &&
        Array.isArray((answer).outputs)

      if (isValid) {
        this.hostReputation.recordSuccess(host, latency)
      } else {
        this.hostReputation.recordFailure(host, 'Invalid lookup response')
      }

      return answer
    } catch (err) {
      this.hostReputation.recordFailure(host, err)
      throw err
    }
  }
}
