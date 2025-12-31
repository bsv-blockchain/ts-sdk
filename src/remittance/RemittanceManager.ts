import type {
  Invoice,
  IdentityVerificationRequest,
  IdentityVerificationResponse,
  IdentityVerificationAcknowledgment,
  Settlement,
  Receipt,
  Termination,
  RemittanceEnvelope,
  PeerMessage,
  ThreadId,
  UnixMillis,
  LoggerLike,
  ModuleContext,
  RemittanceKind,
  RemittanceOptionId,
  RemittanceThreadState
} from './types.js'
import { REMITTANCE_STATE_TRANSITIONS } from './types.js'
import type { CommsLayer } from './CommsLayer.js'
import type { IdentityLayer } from './IdentityLayer.js'
import type { RemittanceModule } from './RemittanceModule.js'
import { OriginatorDomainNameStringUnder250Bytes, PubKeyHex, WalletInterface } from '../wallet/Wallet.interfaces.js'
import { toBase64 } from '../primitives/utils.js'
import Random from '../primitives/Random.js'

export const DEFAULT_REMITTANCE_MESSAGEBOX = 'remittance_inbox'

export interface RemittanceManagerRuntimeOptions {
  /** Identity verification options. */
  identityOptions?: {
    /** At what point should a maker request identity verification? */
    makerRequestIdentity?: 'never' | 'beforeInvoicing' | 'beforeSettlement'
    /** At what point should a taker request identity verification? */
    takerRequestIdentity?: 'never' | 'beforeInvoicing' | 'beforeSettlement'
  }
  /** If true, payees are expected to send receipts. */
  receiptProvided: boolean
  /** If true, manager auto-sends receipts as soon as a settlement is processed. */
  autoIssueReceipt: boolean
  /** Invoice expiry in seconds, or -1 for no expiry. */
  invoiceExpirySeconds: number
  /** Identity verification timeout in milliseconds. */
  identityTimeoutMs: number
  /** Identity verification poll interval in milliseconds. */
  identityPollIntervalMs: number
}

export interface RemittanceManagerConfig {
  /** Optional message box name to use for communication. */
  messageBox?: string
  /** Optional originator forwarded to wallet APIs. */
  originator?: OriginatorDomainNameStringUnder250Bytes
  /**
   * Provide a logger. If omitted, RemittanceManager stays quiet.
   *
   * The manager itself never throws on network/message parsing errors; it will mark threads as errored.
   */
  logger?: LoggerLike

  /** Runtime options that influence core behavior. */
  options?: Partial<RemittanceManagerRuntimeOptions>

  /** Modules (remittance options) available to this manager. */
  remittanceModules: Array<RemittanceModule<any, any, any>>

  /** Optional identity layer for exchanging certificates before transacting. */
  identityLayer?: IdentityLayer

  /** Optional event callback for remittance lifecycle events. */
  onEvent?: (event: RemittanceEvent) => void
  /** Optional event callbacks keyed by process. */
  events?: RemittanceEventHandlers

  /** Persist manager state (threads). */
  stateSaver?: (state: RemittanceManagerState) => Promise<void> | void
  /** Load manager state (threads). */
  stateLoader?: () => Promise<RemittanceManagerState | undefined> | RemittanceManagerState | undefined

  /** Injectable clock for tests. */
  now?: () => UnixMillis
  /** Injectable thread id factory for tests. */
  threadIdFactory?: () => ThreadId
}

export type RemittanceEvent =
  | {
    type: 'threadCreated'
    threadId: ThreadId
    thread: Thread
  }
  | {
    type: 'stateChanged'
    threadId: ThreadId
    previous: RemittanceThreadState
    next: RemittanceThreadState
    reason?: string
  }
  | {
    type: 'envelopeSent'
    threadId: ThreadId
    envelope: RemittanceEnvelope
    transportMessageId: string
  }
  | {
    type: 'envelopeReceived'
    threadId: ThreadId
    envelope: RemittanceEnvelope
    transportMessageId: string
  }
  | {
    type: 'identityRequested'
    threadId: ThreadId
    direction: 'in' | 'out'
    request: IdentityVerificationRequest
  }
  | {
    type: 'identityResponded'
    threadId: ThreadId
    direction: 'in' | 'out'
    response: IdentityVerificationResponse
  }
  | {
    type: 'identityAcknowledged'
    threadId: ThreadId
    direction: 'in' | 'out'
    acknowledgment: IdentityVerificationAcknowledgment
  }
  | {
    type: 'invoiceSent'
    threadId: ThreadId
    invoice: Invoice
  }
  | {
    type: 'invoiceReceived'
    threadId: ThreadId
    invoice: Invoice
  }
  | {
    type: 'settlementSent'
    threadId: ThreadId
    settlement: Settlement
  }
  | {
    type: 'settlementReceived'
    threadId: ThreadId
    settlement: Settlement
  }
  | {
    type: 'receiptSent'
    threadId: ThreadId
    receipt: Receipt
  }
  | {
    type: 'receiptReceived'
    threadId: ThreadId
    receipt: Receipt
  }
  | {
    type: 'terminationSent'
    threadId: ThreadId
    termination: Termination
  }
  | {
    type: 'terminationReceived'
    threadId: ThreadId
    termination: Termination
  }
  | {
    type: 'error'
    threadId: ThreadId
    error: string
  }

export interface RemittanceEventHandlers {
  onThreadCreated?: (event: Extract<RemittanceEvent, { type: 'threadCreated' }>) => void
  onStateChanged?: (event: Extract<RemittanceEvent, { type: 'stateChanged' }>) => void
  onEnvelopeSent?: (event: Extract<RemittanceEvent, { type: 'envelopeSent' }>) => void
  onEnvelopeReceived?: (event: Extract<RemittanceEvent, { type: 'envelopeReceived' }>) => void
  onIdentityRequested?: (event: Extract<RemittanceEvent, { type: 'identityRequested' }>) => void
  onIdentityResponded?: (event: Extract<RemittanceEvent, { type: 'identityResponded' }>) => void
  onIdentityAcknowledged?: (event: Extract<RemittanceEvent, { type: 'identityAcknowledged' }>) => void
  onInvoiceSent?: (event: Extract<RemittanceEvent, { type: 'invoiceSent' }>) => void
  onInvoiceReceived?: (event: Extract<RemittanceEvent, { type: 'invoiceReceived' }>) => void
  onSettlementSent?: (event: Extract<RemittanceEvent, { type: 'settlementSent' }>) => void
  onSettlementReceived?: (event: Extract<RemittanceEvent, { type: 'settlementReceived' }>) => void
  onReceiptSent?: (event: Extract<RemittanceEvent, { type: 'receiptSent' }>) => void
  onReceiptReceived?: (event: Extract<RemittanceEvent, { type: 'receiptReceived' }>) => void
  onTerminationSent?: (event: Extract<RemittanceEvent, { type: 'terminationSent' }>) => void
  onTerminationReceived?: (event: Extract<RemittanceEvent, { type: 'terminationReceived' }>) => void
  onError?: (event: Extract<RemittanceEvent, { type: 'error' }>) => void
}

export interface Thread {
  threadId: ThreadId
  counterparty: PubKeyHex
  myRole: 'maker' | 'taker'
  theirRole: 'maker' | 'taker'
  createdAt: UnixMillis
  updatedAt: UnixMillis
  state: RemittanceThreadState
  /** State transition log for audit purposes. */
  stateLog: Array<{ at: UnixMillis, from: RemittanceThreadState, to: RemittanceThreadState, reason?: string }>

  /** Transport messageIds processed for this thread (dedupe across retries). */
  processedMessageIds: string[]

  /** Protocol envelopes received/sent (for debugging/audit). */
  protocolLog: Array<{
    direction: 'in' | 'out'
    envelope: RemittanceEnvelope
    transportMessageId: string
  }>

  identity: {
    certsSent: IdentityVerificationResponse['certificates']
    certsReceived: IdentityVerificationResponse['certificates']
    requestSent: boolean
    responseSent: boolean
    acknowledgmentSent: boolean
    acknowledgmentReceived: boolean
  }

  invoice?: Invoice
  settlement?: Settlement
  receipt?: Receipt
  termination?: Termination

  flags: {
    hasIdentified: boolean
    hasInvoiced: boolean
    hasPaid: boolean
    hasReceipted: boolean
    error: boolean
  }

  lastError?: { message: string, at: UnixMillis }
}

export interface RemittanceManagerState {
  v: 1
  threads: Thread[]
  defaultPaymentOptionId?: string
}

export interface ComposeInvoiceInput {
  /** Human note/memo. */
  note?: string
  /** Line items. */
  lineItems: Invoice['lineItems']
  /** Total amount. */
  total: Invoice['total']
  invoiceNumber?: string
  arbitrary?: Record<string, unknown>
}

/**
 * RemittanceManager.
 *
 * Responsibilities:
 * - message transport via CommsLayer
 * - thread lifecycle and persistence (via stateSaver/stateLoader)
 * - invoice creation and transmission (when invoices are used)
 * - settlement and settlement routing to the appropriate module
 * - receipt issuance and receipt routing to the appropriate module
 * - identity and identity certificate exchange (when identity layer is used)
 *
 * Non-responsibilities (left to modules):
 * - transaction structure (whether UTXO “offer” formats, token logic, BRC-98/99 specifics, etc.)
 * - validation rules for settlement (e.g. partial tx templates, UTXO validity, etc.)
 * - on-chain broadcasting strategy or non-chain settlement specifics (like legacy payment protocols)
 * - Providing option terms for invoices
 * - Building settlement artifacts
 * - Accepting/rejecting settlements
 * - Deciding which identity certificates to request
 * - Deciding about sufficiency of identity certificates
 * - Preparing/processing specific receipt formats
 * - Internal business logic like order fulfillment, refunds, etc.
 */
export class RemittanceManager {
  readonly wallet: WalletInterface
  readonly comms: CommsLayer
  readonly cfg: RemittanceManagerConfig

  private readonly messageBox: string
  private readonly now: () => UnixMillis
  private readonly threadIdFactory: () => ThreadId

  private readonly moduleRegistry: Map<string, RemittanceModule<any, any, any>>
  private readonly runtime: RemittanceManagerRuntimeOptions
  private readonly eventListeners: Set<(event: RemittanceEvent) => void>
  private readonly stateWaiters: Map<ThreadId, Array<{ state: RemittanceThreadState, resolve: () => void, reject: (err: Error) => void }>>
  private readonly eventHandlers?: RemittanceEventHandlers

  /** Default option id used when paying an invoice, if not overridden per-call. */
  private defaultPaymentOptionId?: string

  /** Mutable threads list (persisted via stateSaver). */
  threads: Thread[]

  /** Cached identity key if wallet provides it. */
  private myIdentityKey?: PubKeyHex

  constructor (cfg: RemittanceManagerConfig, wallet: WalletInterface, commsLayer: CommsLayer, threads: Thread[] = []) {
    this.cfg = cfg
    this.wallet = wallet
    this.comms = commsLayer
    this.messageBox = cfg.messageBox ?? DEFAULT_REMITTANCE_MESSAGEBOX

    this.now = cfg.now ?? (() => Date.now())
    this.threadIdFactory = cfg.threadIdFactory ?? defaultThreadIdFactory

    this.moduleRegistry = new Map(cfg.remittanceModules.map((m) => [m.id, m]))
    this.eventListeners = new Set()
    this.stateWaiters = new Map()
    this.eventHandlers = cfg.events
    if (typeof cfg.onEvent === 'function') {
      this.eventListeners.add(cfg.onEvent)
    }

    this.runtime = {
      identityOptions: cfg.options?.identityOptions ?? {
        makerRequestIdentity: 'never',
        takerRequestIdentity: 'never'
      },
      receiptProvided: cfg.options?.receiptProvided ?? true,
      autoIssueReceipt: cfg.options?.autoIssueReceipt ?? true,
      invoiceExpirySeconds: cfg.options?.invoiceExpirySeconds ?? 3600,
      identityTimeoutMs: cfg.options?.identityTimeoutMs ?? 30_000,
      identityPollIntervalMs: cfg.options?.identityPollIntervalMs ?? 500
    }

    this.threads = threads.map((thread) => this.ensureThreadState(thread))
  }

  /**
   * Loads persisted state from cfg.stateLoader (if provided).
   *
   * Safe to call multiple times.
   */
  async init (): Promise<void> {
    if (typeof this.cfg.stateLoader !== 'function') return

    const loaded = await this.cfg.stateLoader()
    if (typeof loaded !== 'object') return

    this.loadState(loaded)

    if (typeof loaded.defaultPaymentOptionId === 'string') {
      this.defaultPaymentOptionId = loaded.defaultPaymentOptionId
    }

    await this.refreshMyIdentityKey()
  }

  /**
   * Registers a remittance event listener.
   */
  onEvent (listener: (event: RemittanceEvent) => void): () => void {
    this.eventListeners.add(listener)
    return () => {
      this.eventListeners.delete(listener)
    }
  }

  /**
   * Sets a default payment option (module id) to use when paying invoices.
   */
  preselectPaymentOption (optionId: string): void {
    this.defaultPaymentOptionId = optionId
  }

  /**
   * Returns an immutable snapshot of current manager state suitable for persistence.
   */
  saveState (): RemittanceManagerState {
    return {
      v: 1,
      threads: JSON.parse(JSON.stringify(this.threads)) as Thread[],
      defaultPaymentOptionId: this.defaultPaymentOptionId
    }
  }

  /**
   * Loads state from an object previously produced by saveState().
   */
  loadState (state: RemittanceManagerState): void {
    if (state.v !== 1) throw new Error('Unsupported RemittanceManagerState version')
    this.threads = (state.threads ?? []).map((thread) => this.ensureThreadState(thread))
    this.defaultPaymentOptionId = state.defaultPaymentOptionId
  }

  /**
   * Persists current state via cfg.stateSaver (if provided).
   */
  async persistState (): Promise<void> {
    if (this.cfg.stateSaver == null) return
    await this.cfg.stateSaver(this.saveState())
  }

  /**
   * Syncs threads by fetching pending messages from the comms layer and processing them.
   *
   * Processing is idempotent using transport messageIds tracked per thread.
   * Messages are acknowledged after they are successfully applied to local state.
   */
  async syncThreads (hostOverride?: string): Promise<void> {
    await this.refreshMyIdentityKey()

    const msgs = await this.comms.listMessages({ messageBox: this.messageBox, host: hostOverride })

    for (const msg of msgs) {
      await this.handleInboundMessage(msg)
    }
  }

  /**
   * Starts listening for live messages (if the CommsLayer supports it).
   */
  async startListening (hostOverride?: string): Promise<void> {
    if (typeof this.comms.listenForLiveMessages !== 'function') {
      throw new Error('CommsLayer does not support live message listening')
    }

    await this.comms.listenForLiveMessages({
      messageBox: this.messageBox,
      overrideHost: hostOverride,
      onMessage: (msg) => {
        void this.handleInboundMessage(msg)
      }
    })
  }

  /**
   * Creates, records, and sends an invoice to a counterparty.
   *
   * Returns a handle you can use to wait for payment/receipt.
   */
  async sendInvoice (to: PubKeyHex, input: ComposeInvoiceInput, hostOverride?: string): Promise<InvoiceHandle> {
    await this.refreshMyIdentityKey()
    const threadId = this.threadIdFactory()
    const createdAt = this.now()

    const myKey = this.requireMyIdentityKey('sendInvoice requires the wallet to provide an identity key')

    const thread: Thread = {
      threadId,
      counterparty: to,
      myRole: 'maker',
      theirRole: 'taker',
      createdAt,
      updatedAt: createdAt,
      state: 'new',
      stateLog: [],
      processedMessageIds: [],
      protocolLog: [],
      identity: {
        certsSent: [],
        certsReceived: [],
        requestSent: false,
        responseSent: false,
        acknowledgmentSent: false,
        acknowledgmentReceived: false
      },
      flags: {
        hasIdentified: false,
        hasInvoiced: false,
        hasPaid: false,
        hasReceipted: false,
        error: false
      }
    }

    this.threads.push(thread)
    this.emitEvent({ type: 'threadCreated', threadId: thread.threadId, thread })

    if (thread.identity.responseSent && !thread.flags.hasIdentified) {
      await this.waitForIdentityAcknowledgment(threadId, {
        timeoutMs: this.runtime.identityTimeoutMs,
        pollIntervalMs: this.runtime.identityPollIntervalMs
      })
    }

    if (this.shouldRequestIdentity(thread, 'beforeInvoicing')) {
      await this.ensureIdentityExchange(thread, hostOverride)
    }

    const invoice = await this.composeInvoice(threadId, myKey, to, input)
    thread.invoice = invoice
    thread.flags.hasInvoiced = true
    this.transitionThreadState(thread, 'invoiced', 'invoice created')

    // Generate option terms for each configured module.
    for (const mod of this.moduleRegistry.values()) {
      if (typeof mod.createOption !== 'function') continue
      const option = await mod.createOption({ threadId, invoice }, this.moduleContext())
      invoice.options[mod.id] = option
    }

    const env = this.makeEnvelope('invoice', threadId, invoice)
    const mid = await this.sendEnvelope(to, env, hostOverride)
    thread.protocolLog.push({ direction: 'out', envelope: env, transportMessageId: mid })
    this.emitEvent({ type: 'invoiceSent', threadId: thread.threadId, invoice })
    thread.updatedAt = this.now()
    await this.persistState()

    return new InvoiceHandle(this, threadId)
  }

  /**
   * Sends an invoice for an existing thread, e.g. after an identity request was received.
   */
  async sendInvoiceForThread (threadId: ThreadId, input: ComposeInvoiceInput, hostOverride?: string): Promise<InvoiceHandle> {
    await this.refreshMyIdentityKey()
    const thread = this.getThreadOrThrow(threadId)

    if (thread.flags.error) throw new Error('Thread is in error state')
    if (thread.myRole !== 'maker') throw new Error('Only makers can send invoices')
    if (thread.invoice != null) throw new Error('Thread already has an invoice')

    if (thread.identity.responseSent && !thread.flags.hasIdentified) {
      await this.waitForIdentityAcknowledgment(threadId, {
        timeoutMs: this.runtime.identityTimeoutMs,
        pollIntervalMs: this.runtime.identityPollIntervalMs
      })
    }

    if (this.shouldRequestIdentity(thread, 'beforeInvoicing')) {
      await this.ensureIdentityExchange(thread, hostOverride)
    }

    const myKey = this.requireMyIdentityKey('sendInvoice requires the wallet to provide an identity key')
    const invoice = await this.composeInvoice(threadId, myKey, thread.counterparty, input)
    thread.invoice = invoice
    thread.flags.hasInvoiced = true
    this.transitionThreadState(thread, 'invoiced', 'invoice created')

    for (const mod of this.moduleRegistry.values()) {
      if (typeof mod.createOption !== 'function') continue
      const option = await mod.createOption({ threadId, invoice }, this.moduleContext())
      invoice.options[mod.id] = option
    }

    const env = this.makeEnvelope('invoice', threadId, invoice)
    const mid = await this.sendEnvelope(thread.counterparty, env, hostOverride)
    thread.protocolLog.push({ direction: 'out', envelope: env, transportMessageId: mid })
    this.emitEvent({ type: 'invoiceSent', threadId: thread.threadId, invoice })
    thread.updatedAt = this.now()
    await this.persistState()

    return new InvoiceHandle(this, threadId)
  }

  /**
   * Returns invoice handles that this manager can pay (we are the taker/payer).
   */
  findInvoicesPayable (counterparty?: PubKeyHex): InvoiceHandle[] {
    const hasCounterparty = typeof counterparty === 'string' && counterparty.length > 0
    return this.threads
      .filter((t) => t.myRole === 'taker' && (t.invoice != null) && (t.settlement == null) && !t.flags.error)
      .filter((t) => (hasCounterparty ? t.counterparty === counterparty : true))
      .map((t) => new InvoiceHandle(this, t.threadId))
  }

  /**
   * Returns invoice handles that we issued and are waiting to receive settlement for.
   */
  findReceivableInvoices (counterparty?: PubKeyHex): InvoiceHandle[] {
    const hasCounterparty = typeof counterparty === 'string' && counterparty.length > 0
    return this.threads
      .filter((t) => t.myRole === 'maker' && (t.invoice != null) && (t.settlement == null) && !t.flags.error)
      .filter((t) => (hasCounterparty ? t.counterparty === counterparty : true))
      .map((t) => new InvoiceHandle(this, t.threadId))
  }

  /**
   * Pays an invoice by selecting a remittance option and sending a settlement message.
   *
   * If receipts are enabled (receiptProvided), this method will optionally wait for a receipt.
   */
  async pay (threadId: ThreadId, optionId?: string, hostOverride?: string): Promise<Receipt | Termination | undefined> {
    await this.refreshMyIdentityKey()

    const thread = this.getThreadOrThrow(threadId)
    if (thread.invoice == null) throw new Error('Thread has no invoice to pay')

    if (thread.flags.error) throw new Error('Thread is in error state')
    if (thread.settlement != null) throw new Error('Invoice already paid (settlement exists)')

    if (thread.identity.responseSent && !thread.flags.hasIdentified) {
      await this.waitForIdentityAcknowledgment(threadId, {
        timeoutMs: this.runtime.identityTimeoutMs,
        pollIntervalMs: this.runtime.identityPollIntervalMs
      })
    }

    if (this.shouldRequestIdentity(thread, 'beforeSettlement')) {
      await this.ensureIdentityExchange(thread, hostOverride)
    }

    // Check expiry.
    const expiresAt = thread.invoice.expiresAt
    if (typeof expiresAt === 'number' && this.now() > expiresAt) {
      throw new Error('Invoice is expired')
    }

    const chosenOptionId = optionId ?? this.defaultPaymentOptionId ?? Object.keys(thread.invoice.options)[0]
    if (chosenOptionId == null || chosenOptionId === '') {
      throw new Error('No remittance options available on invoice')
    }

    const module = this.moduleRegistry.get(chosenOptionId)
    if (module == null) {
      throw new Error(`No configured remittance module for option: ${chosenOptionId}`)
    }

    const option = thread.invoice.options[chosenOptionId]
    const myKey = this.requireMyIdentityKey('pay() requires the wallet to provide an identity key')

    const buildResult = await module.buildSettlement(
      { threadId, invoice: thread.invoice, option, note: thread.invoice.note },
      this.moduleContext()
    )

    if (buildResult.action === 'terminate') {
      const termination = buildResult.termination
      await this.sendTermination(thread, thread.counterparty, termination.message, termination.details, termination.code)
      await this.persistState()
      return termination
    }

    const settlement: Settlement = {
      kind: 'settlement',
      threadId,
      moduleId: module.id,
      optionId: chosenOptionId,
      sender: myKey,
      createdAt: this.now(),
      artifact: buildResult.artifact,
      note: thread.invoice.note
    }

    const env = this.makeEnvelope('settlement', threadId, settlement)

    // Send settlement to payee (invoice.payee).
    const mid = await this.sendEnvelope(thread.invoice.payee, env, hostOverride)
    thread.protocolLog.push({ direction: 'out', envelope: env, transportMessageId: mid })
    this.emitEvent({ type: 'settlementSent', threadId: thread.threadId, settlement })

    thread.settlement = settlement
    thread.flags.hasPaid = true
    this.transitionThreadState(thread, 'settled', 'settlement sent')
    thread.updatedAt = this.now()
    await this.persistState()

    if (!this.runtime.receiptProvided) {
      return undefined
    }

    // Wait for receipt (polling + syncThreads) up to a default timeout.
    return await this.waitForReceipt(threadId)
  }

  /**
   * Waits for a receipt to arrive for a thread.
   *
   * Uses polling via syncThreads because live listeners are optional.
   */
  async waitForReceipt (threadId: ThreadId, opts: { timeoutMs?: number, pollIntervalMs?: number } = {}): Promise<Receipt | Termination> {
    const timeoutMs = opts.timeoutMs ?? 30_000
    const pollIntervalMs = opts.pollIntervalMs ?? 500

    const start = this.now()
    while (this.now() - start < timeoutMs) {
      const t = this.getThreadOrThrow(threadId)
      if (typeof t.receipt === 'object') return t.receipt
      if (typeof t.termination === 'object') return t.termination

      await this.syncThreads()
      await sleep(pollIntervalMs)
    }

    throw new Error('Timed out waiting for receipt')
  }

  /**
   * Waits for a thread to reach a specific state.
   */
  async waitForState (
    threadId: ThreadId,
    state: RemittanceThreadState,
    opts: { timeoutMs?: number, pollIntervalMs?: number } = {}
  ): Promise<Thread> {
    const timeoutMs = opts.timeoutMs ?? 30_000
    const pollIntervalMs = opts.pollIntervalMs ?? 500
    const start = this.now()

    const t = this.getThreadOrThrow(threadId)
    if (t.state === state) return t
    if (t.state === 'terminated' || t.state === 'errored') {
      throw new Error(`Thread entered terminal state: ${t.state}`)
    }

    let settled = false
    let timedOut = false

    let resolvePromise: () => void
    let rejectPromise: (err: Error) => void

    const entry = {
      state,
      resolve: () => {
        if (settled || timedOut) return
        settled = true
        resolvePromise()
      },
      reject: (err: Error) => {
        if (settled || timedOut) return
        settled = true
        rejectPromise(err)
      }
    }

    const waiter = new Promise<void>((resolve, reject) => {
      resolvePromise = resolve
      rejectPromise = reject
      const waiters = this.stateWaiters.get(threadId) ?? []
      waiters.push(entry)
      this.stateWaiters.set(threadId, waiters)
    })

    const removeEntry = (): void => {
      const waiters = this.stateWaiters.get(threadId)
      if (waiters == null) return
      const remaining = waiters.filter((item) => item !== entry)
      if (remaining.length === 0) {
        this.stateWaiters.delete(threadId)
      } else {
        this.stateWaiters.set(threadId, remaining)
      }
    }

    const poller = (async () => {
      while (this.now() - start < timeoutMs) {
        if (settled) return
        const current = this.getThreadOrThrow(threadId)
        if (current.state === state) {
          this.resolveStateWaiters(threadId, state)
          return
        }
        if (current.state === 'terminated' || current.state === 'errored') {
          throw new Error(`Thread entered terminal state: ${current.state}`)
        }
        await this.syncThreads()
        await sleep(pollIntervalMs)
      }
    })()

    await Promise.race([waiter, poller]).catch((err) => {
      removeEntry()
      throw err
    })

    if (this.now() - start >= timeoutMs && !settled) {
      timedOut = true
      removeEntry()
      throw new Error(`Timed out waiting for state: ${state}`)
    }

    removeEntry()
    return this.getThreadOrThrow(threadId)
  }

  /**
   * Waits for identity exchange to complete for a thread.
   */
  async waitForIdentity (threadId: ThreadId, opts?: { timeoutMs?: number, pollIntervalMs?: number }): Promise<Thread> {
    return await this.waitForState(threadId, 'identityAcknowledged', opts)
  }

  /**
   * Waits for a settlement to arrive for a thread.
   */
  async waitForSettlement (
    threadId: ThreadId,
    opts: { timeoutMs?: number, pollIntervalMs?: number } = {}
  ): Promise<Settlement | Termination> {
    const timeoutMs = opts.timeoutMs ?? 30_000
    const pollIntervalMs = opts.pollIntervalMs ?? 500

    const start = this.now()
    while (this.now() - start < timeoutMs) {
      const t = this.getThreadOrThrow(threadId)
      if (typeof t.settlement === 'object') return t.settlement
      if (typeof t.termination === 'object') return t.termination

      await this.syncThreads()
      await sleep(pollIntervalMs)
    }

    throw new Error('Timed out waiting for settlement')
  }

  /**
   * Sends an unsolicited settlement to a counterparty.
   */
  async sendUnsolicitedSettlement (
    to: PubKeyHex,
    args: { moduleId: RemittanceOptionId, option: unknown, optionId?: RemittanceOptionId, note?: string },
    hostOverride?: string
  ): Promise<ThreadHandle> {
    await this.refreshMyIdentityKey()

    const module = this.moduleRegistry.get(args.moduleId)
    if (module == null) throw new Error(`No configured remittance module for option: ${args.moduleId}`)
    if (!module.allowUnsolicitedSettlements) {
      throw new Error(`Remittance module ${args.moduleId} does not allow unsolicited settlements`)
    }

    const threadId = this.threadIdFactory()
    const createdAt = this.now()
    const myKey = this.requireMyIdentityKey('sendUnsolicitedSettlement requires the wallet to provide an identity key')

    const thread: Thread = {
      threadId,
      counterparty: to,
      myRole: 'taker',
      theirRole: 'maker',
      createdAt,
      updatedAt: createdAt,
      state: 'new',
      stateLog: [],
      processedMessageIds: [],
      protocolLog: [],
      identity: {
        certsSent: [],
        certsReceived: [],
        requestSent: false,
        responseSent: false,
        acknowledgmentSent: false,
        acknowledgmentReceived: false
      },
      flags: {
        hasIdentified: false,
        hasInvoiced: false,
        hasPaid: false,
        hasReceipted: false,
        error: false
      }
    }

    this.threads.push(thread)
    this.emitEvent({ type: 'threadCreated', threadId: thread.threadId, thread })

    if (this.shouldRequestIdentity(thread, 'beforeSettlement')) {
      await this.ensureIdentityExchange(thread, hostOverride)
    }

    const buildResult = await module.buildSettlement(
      { threadId, option: args.option, note: args.note },
      this.moduleContext()
    )

    if (buildResult.action === 'terminate') {
      await this.sendTermination(thread, to, buildResult.termination.message, buildResult.termination.details, buildResult.termination.code)
      await this.persistState()
      return new ThreadHandle(this, threadId)
    }

    const settlement: Settlement = {
      kind: 'settlement',
      threadId,
      moduleId: module.id,
      optionId: args.optionId ?? module.id,
      sender: myKey,
      createdAt: this.now(),
      artifact: buildResult.artifact,
      note: args.note
    }

    const env = this.makeEnvelope('settlement', threadId, settlement)
    const mid = await this.sendEnvelope(to, env, hostOverride)
    thread.protocolLog.push({ direction: 'out', envelope: env, transportMessageId: mid })
    this.emitEvent({ type: 'settlementSent', threadId: thread.threadId, settlement })
    thread.settlement = settlement
    thread.flags.hasPaid = true
    this.transitionThreadState(thread, 'settled', 'settlement sent')
    thread.updatedAt = this.now()
    await this.persistState()

    return new ThreadHandle(this, threadId)
  }

  /**
   * Returns a thread by id (if present).
   */
  getThread (threadId: ThreadId): Thread | undefined {
    return this.threads.find((t) => t.threadId === threadId)
  }

  /**
   * Returns a thread handle by id, or throws if the thread does not exist.
   */
  getThreadHandle (threadId: ThreadId): ThreadHandle {
    this.getThreadOrThrow(threadId)
    return new ThreadHandle(this, threadId)
  }

  /**
   * Returns a thread by id or throws.
   *
   * Public so helper handles (e.g. InvoiceHandle) can call it.
   */
  getThreadOrThrow (threadId: ThreadId): Thread {
    const t = this.getThread(threadId)
    if (typeof t !== 'object') throw new Error(`Unknown thread: ${threadId}`)
    return this.ensureThreadState(t)
  }

  // ----------------------------
  // Internal helpers
  // ----------------------------

  private moduleContext (): ModuleContext {
    return {
      wallet: this.wallet,
      originator: this.cfg.originator,
      now: this.now,
      logger: this.cfg.logger
    }
  }

  private makeEnvelope<K extends RemittanceKind, P>(kind: K, threadId: ThreadId, payload: P): RemittanceEnvelope<K, P> {
    return {
      v: 1,
      id: this.threadIdFactory(),
      kind,
      threadId,
      createdAt: this.now(),
      payload
    }
  }

  private async sendEnvelope (recipient: PubKeyHex, env: RemittanceEnvelope, hostOverride?: string): Promise<string> {
    const body = JSON.stringify(env)

    // Prefer live if available.
    if (typeof this.comms.sendLiveMessage === 'function') {
      try {
        const mid = await this.comms.sendLiveMessage({ recipient, messageBox: this.messageBox, body }, hostOverride)
        this.emitEvent({ type: 'envelopeSent', threadId: env.threadId, envelope: env, transportMessageId: mid })
        return mid
      } catch (e) {
        this.cfg.logger?.warn?.('[RemittanceManager] sendLiveMessage failed, falling back to non-live', e)
      }
    }

    const mid = await this.comms.sendMessage({ recipient, messageBox: this.messageBox, body }, hostOverride)
    this.emitEvent({ type: 'envelopeSent', threadId: env.threadId, envelope: env, transportMessageId: mid })
    return mid
  }

  private getOrCreateThreadFromInboundEnvelope (env: RemittanceEnvelope, msg: PeerMessage): Thread {
    const existing = this.getThread(env.threadId)
    if (typeof existing === 'object') return existing

    // If we didn't create the thread, infer roles from the first message kind:
    // - Receiving identity verification request/response/acknowledgment -> we are either maker or taker depending on config
    // - Receiving an invoice -> we are taker (payer)
    // - Receiving a settlement -> we are maker (payee)
    // - Receiving a receipt -> we are taker
    // - Receiving a termination -> assume we are taker
    const createdAt = this.now()

    const inferredMyRole: Thread['myRole'] = (() => {
      if (env.kind === 'invoice') return 'taker'
      if (env.kind === 'settlement') return 'maker'
      if (env.kind === 'receipt') return 'taker'
      if (env.kind === 'termination') return 'taker'

      if (
        env.kind === 'identityVerificationRequest' ||
        env.kind === 'identityVerificationResponse' ||
        env.kind === 'identityVerificationAcknowledgment'
      ) {
        const makerRequest = this.runtime.identityOptions?.makerRequestIdentity ?? 'never'
        const takerRequest = this.runtime.identityOptions?.takerRequestIdentity ?? 'never'
        const makerRequests = makerRequest !== 'never'
        const takerRequests = takerRequest !== 'never'

        let requesterRole: Thread['myRole'] | undefined
        if (makerRequests && !takerRequests) {
          requesterRole = 'maker'
        } else if (takerRequests && !makerRequests) {
          requesterRole = 'taker'
        } else if (makerRequests && takerRequests && makerRequest !== takerRequest) {
          requesterRole =
            makerRequest === 'beforeInvoicing' && takerRequest === 'beforeSettlement'
              ? 'maker'
              : makerRequest === 'beforeSettlement' && takerRequest === 'beforeInvoicing'
                ? 'taker'
                : undefined
        }

        if (typeof requesterRole !== 'string') return 'taker'

        if (env.kind === 'identityVerificationResponse') {
          return requesterRole
        }

        return requesterRole === 'maker' ? 'taker' : 'maker'
      }

      return 'taker'
    })()
    const inferredTheirRole: Thread['theirRole'] = inferredMyRole === 'maker' ? 'taker' : 'maker'

    const t: Thread = {
      threadId: env.threadId,
      counterparty: msg.sender,
      myRole: inferredMyRole,
      theirRole: inferredTheirRole,
      createdAt,
      updatedAt: createdAt,
      state: 'new',
      stateLog: [],
      processedMessageIds: [],
      protocolLog: [],
      identity: {
        certsSent: [],
        certsReceived: [],
        requestSent: false,
        responseSent: false,
        acknowledgmentSent: false,
        acknowledgmentReceived: false
      },
      flags: {
        hasIdentified: false,
        hasInvoiced: false,
        hasPaid: false,
        hasReceipted: false,
        error: false
      }
    }

    this.threads.push(t)
    this.emitEvent({ type: 'threadCreated', threadId: t.threadId, thread: t })
    return t
  }

  private async handleInboundMessage (msg: PeerMessage): Promise<void> {
    const parsed = safeParseEnvelope(msg.body)
    if (parsed == null) {
      // Not our protocol message; leave it for the application or acknowledge? Here we leave it.
      return
    }

    const thread = this.getOrCreateThreadFromInboundEnvelope(parsed, msg)
    if (thread.processedMessageIds.includes(msg.messageId)) {
      // Already applied; ack and continue.
      await this.safeAck([msg.messageId])
      return
    }

    try {
      await this.applyInboundEnvelope(thread, parsed, msg)
      thread.processedMessageIds.push(msg.messageId)
      thread.updatedAt = this.now()
      await this.persistState()
      await this.safeAck([msg.messageId])
    } catch (e: any) {
      this.markThreadError(thread, e)
      await this.persistState()
      // Do not acknowledge so it can be retried.
    }
  }

  private async applyInboundEnvelope (thread: Thread, env: RemittanceEnvelope, msg: PeerMessage): Promise<void> {
    thread.protocolLog.push({ direction: 'in', envelope: env, transportMessageId: msg.messageId })
    this.emitEvent({ type: 'envelopeReceived', threadId: thread.threadId, envelope: env, transportMessageId: msg.messageId })

    switch (env.kind) {
      case 'identityVerificationRequest': {
        const payload = env.payload as IdentityVerificationRequest
        if (typeof payload !== 'object') {
          throw new Error('Identity verification request payload missing data')
        }

        if (this.cfg.identityLayer == null) {
          await this.sendTermination(thread, msg.sender, 'Identity verification requested but no identity layer is configured')
          return
        }

        this.transitionThreadState(thread, 'identityRequested', 'identity request received')
        this.emitEvent({ type: 'identityRequested', threadId: thread.threadId, direction: 'in', request: payload })

        const response = await this.cfg.identityLayer.respondToRequest(
          { counterparty: msg.sender, threadId: thread.threadId, request: payload },
          this.moduleContext()
        )

        if (response.action === 'terminate') {
          await this.sendTermination(thread, msg.sender, response.termination.message, response.termination.details, response.termination.code)
          return
        }

        const responseEnv = this.makeEnvelope('identityVerificationResponse', thread.threadId, response.response)
        const mid = await this.sendEnvelope(msg.sender, responseEnv)
        thread.protocolLog.push({ direction: 'out', envelope: responseEnv, transportMessageId: mid })
        thread.identity.certsSent = response.response.certificates
        thread.identity.responseSent = true
        this.transitionThreadState(thread, 'identityResponded', 'identity response sent')
        this.emitEvent({ type: 'identityResponded', threadId: thread.threadId, direction: 'out', response: response.response })
        return
      }

      case 'identityVerificationResponse': {
        const payload = env.payload as IdentityVerificationResponse
        if (typeof payload !== 'object') {
          throw new Error('Identity verification response payload missing data')
        }

        if (this.cfg.identityLayer == null) {
          await this.sendTermination(thread, msg.sender, 'Identity verification response received but no identity layer is configured')
          return
        }

        thread.identity.certsReceived = payload.certificates
        this.transitionThreadState(thread, 'identityResponded', 'identity response received')
        this.emitEvent({ type: 'identityResponded', threadId: thread.threadId, direction: 'in', response: payload })
        const decision = await this.cfg.identityLayer.assessReceivedCertificateSufficiency(
          msg.sender,
          payload,
          thread.threadId
        )

        if ('message' in decision) {
          await this.sendTermination(thread, msg.sender, decision.message, decision.details, decision.code)
          return
        }

        if (decision.kind === 'identityVerificationAcknowledgment') {
          const ackEnv = this.makeEnvelope('identityVerificationAcknowledgment', thread.threadId, decision)
          const mid = await this.sendEnvelope(msg.sender, ackEnv)
          thread.protocolLog.push({ direction: 'out', envelope: ackEnv, transportMessageId: mid })
          thread.identity.acknowledgmentSent = true
          thread.flags.hasIdentified = true
          this.transitionThreadState(thread, 'identityAcknowledged', 'identity acknowledgment sent')
          this.emitEvent({ type: 'identityAcknowledged', threadId: thread.threadId, direction: 'out', acknowledgment: decision })
          return
        }
        throw new Error('Unknown identity verification decision')
      }

      case 'identityVerificationAcknowledgment': {
        const payload = env.payload as IdentityVerificationAcknowledgment
        if (typeof payload !== 'object') {
          throw new Error('Identity verification acknowledgment payload missing data')
        }

        thread.identity.acknowledgmentReceived = true
        thread.flags.hasIdentified = true
        this.transitionThreadState(thread, 'identityAcknowledged', 'identity acknowledgment received')
        this.emitEvent({ type: 'identityAcknowledged', threadId: thread.threadId, direction: 'in', acknowledgment: payload })
        return
      }

      case 'invoice': {
        const invoice = env.payload as Invoice
        if (typeof invoice !== 'object') {
          throw new Error('Invoice payload missing invoice data')
        }

        thread.invoice = invoice
        thread.flags.hasInvoiced = true
        this.transitionThreadState(thread, 'invoiced', 'invoice received')
        this.emitEvent({ type: 'invoiceReceived', threadId: thread.threadId, invoice })
        return
      }

      case 'settlement': {
        const settlement = env.payload as Settlement
        if (typeof settlement !== 'object') {
          throw new Error('Settlement payload missing settlement data')
        }

        if (this.shouldRequireIdentityBeforeSettlement(thread) && !thread.flags.hasIdentified) {
          await this.sendTermination(thread, msg.sender, 'Identity verification is required before settlement')
          return
        }

        // Persist settlement immediately (even if we later reject); it is part of the audit trail.
        thread.settlement = settlement
        thread.flags.hasPaid = true
        this.transitionThreadState(thread, 'settled', 'settlement received')
        this.emitEvent({ type: 'settlementReceived', threadId: thread.threadId, settlement })

        const module = this.moduleRegistry.get(settlement.moduleId)
        if (typeof module !== 'object') {
          await this.maybeSendTermination(thread, settlement, msg.sender, `Unsupported module: ${settlement.moduleId}`)
          return
        }

        if ((thread.invoice == null) && !module.allowUnsolicitedSettlements) {
          await this.maybeSendTermination(thread, settlement, msg.sender, 'Unsolicited settlement not supported')
          return
        }

        const result = await module.acceptSettlement({
          threadId: thread.threadId,
          invoice: thread.invoice,
          settlement: settlement.artifact,
          sender: msg.sender
        }, this.moduleContext()).catch(async (e) => {
          const errMsg = e instanceof Error ? e.message : String(e)
          await this.maybeSendTermination(thread, settlement, msg.sender, `Settlement processing failed: ${errMsg}`)
          throw e // re-throw to stop further processing
        })

        if (result.action === 'accept') {
          const myKey = this.requireMyIdentityKey('Receiving settlement requires identity key')
          const payerKey = msg.sender

          const receipt: Receipt = {
            kind: 'receipt',
            threadId: thread.threadId,
            moduleId: settlement.moduleId,
            optionId: settlement.optionId,
            payee: myKey,
            payer: payerKey,
            createdAt: this.now(),
            receiptData: result.receiptData
          }

          thread.receipt = receipt
          thread.flags.hasReceipted = true
          this.transitionThreadState(thread, 'receipted', 'receipt issued')

          if (this.runtime.receiptProvided && this.runtime.autoIssueReceipt) {
            const receiptEnv = this.makeEnvelope('receipt', thread.threadId, receipt)
            const mid = await this.sendEnvelope(msg.sender, receiptEnv)
            thread.protocolLog.push({ direction: 'out', envelope: receiptEnv, transportMessageId: mid })
            this.emitEvent({ type: 'receiptSent', threadId: thread.threadId, receipt })
          }
        } else if (result.action === 'terminate') {
          await this.maybeSendTermination(thread, settlement, msg.sender, result.termination.message, result.termination.details)
        } else {
          throw new Error('Unknown settlement acceptance action')
        }

        return
      }
      case 'receipt': {
        const receipt = env.payload as Receipt
        if (typeof receipt !== 'object') {
          throw new Error('Receipt payload missing receipt data')
        }

        thread.receipt = receipt
        thread.flags.hasReceipted = true
        this.transitionThreadState(thread, 'receipted', 'receipt received')
        this.emitEvent({ type: 'receiptReceived', threadId: thread.threadId, receipt })

        const module = this.moduleRegistry.get(receipt.moduleId)
        if (module?.processReceipt != null) {
          await module.processReceipt(
            { threadId: thread.threadId, invoice: thread.invoice, receiptData: receipt.receiptData, sender: msg.sender },
            this.moduleContext()
          )
        }

        return
      }

      case 'termination': {
        const payload = env.payload as Termination
        if (typeof payload !== 'object') {
          throw new Error('Termination payload missing data')
        }
        thread.termination = payload
        thread.lastError = { message: payload.message, at: this.now() }
        thread.flags.error = true
        this.transitionThreadState(thread, 'terminated', 'termination received')
        this.emitEvent({ type: 'terminationReceived', threadId: thread.threadId, termination: payload })
        if (thread.settlement != null) {
          const module = this.moduleRegistry.get(thread.settlement.moduleId)
          if ((module?.processTermination) != null) {
            await module.processTermination(
              { threadId: thread.threadId, invoice: thread.invoice, settlement: thread.settlement, termination: payload, sender: msg.sender },
              this.moduleContext()
            )
          }
        }
        return
      }

      default: {
        const kind = (env as { kind?: unknown }).kind
        throw new Error(`Unknown envelope kind: ${String(kind)}`)
      }
    }
  }

  private async maybeSendTermination (thread: Thread, settlement: Settlement, payer: PubKeyHex, message: string, details?: any): Promise<void> {
    const t: Termination = {
      code: 'error',
      message,
      details
    }

    const env = this.makeEnvelope('termination', thread.threadId, t)
    const mid = await this.sendEnvelope(payer, env)
    thread.protocolLog.push({ direction: 'out', envelope: env, transportMessageId: mid })
    this.emitEvent({ type: 'terminationSent', threadId: thread.threadId, termination: t })

    thread.termination = t
    thread.lastError = {
      message: `Sent termination: ${message}`,
      at: this.now()
    }
    thread.flags.error = true
    this.transitionThreadState(thread, 'terminated', 'termination sent')
  }

  private async sendTermination (
    thread: Thread,
    recipient: PubKeyHex,
    message: string,
    details?: unknown,
    code = 'error'
  ): Promise<void> {
    const t: Termination = { code, message, details }
    const env = this.makeEnvelope('termination', thread.threadId, t)
    const mid = await this.sendEnvelope(recipient, env)
    thread.protocolLog.push({ direction: 'out', envelope: env, transportMessageId: mid })
    this.emitEvent({ type: 'terminationSent', threadId: thread.threadId, termination: t })
    thread.termination = t
    thread.lastError = { message: `Sent termination: ${message}`, at: this.now() }
    thread.flags.error = true
    this.transitionThreadState(thread, 'terminated', 'termination sent')
  }

  private shouldRequestIdentity (thread: Thread, phase: 'beforeInvoicing' | 'beforeSettlement'): boolean {
    const { makerRequestIdentity = 'never', takerRequestIdentity = 'never' } = this.runtime.identityOptions ?? {}
    const requiresIdentity = thread.myRole === 'maker' ? makerRequestIdentity === phase : takerRequestIdentity === phase
    if (!requiresIdentity) return false
    if (this.cfg.identityLayer == null) {
      throw new Error('Identity layer is required by runtime options but is not configured')
    }
    return true
  }

  private shouldRequireIdentityBeforeSettlement (thread: Thread): boolean {
    if (thread.myRole !== 'maker') return false
    return (this.runtime.identityOptions?.makerRequestIdentity ?? 'never') === 'beforeSettlement'
  }

  private async ensureIdentityExchange (thread: Thread, hostOverride?: string): Promise<void> {
    if (this.cfg.identityLayer == null) return
    if (thread.flags.hasIdentified) return

    if (!thread.identity.requestSent) {
      const request = await this.cfg.identityLayer.determineCertificatesToRequest(
        { counterparty: thread.counterparty, threadId: thread.threadId },
        this.moduleContext()
      )
      const env = this.makeEnvelope('identityVerificationRequest', thread.threadId, request)
      const mid = await this.sendEnvelope(thread.counterparty, env, hostOverride)
      thread.protocolLog.push({ direction: 'out', envelope: env, transportMessageId: mid })
      thread.identity.requestSent = true
      this.transitionThreadState(thread, 'identityRequested', 'identity request sent')
      this.emitEvent({ type: 'identityRequested', threadId: thread.threadId, direction: 'out', request })
      thread.updatedAt = this.now()
      await this.persistState()
    }

    await this.waitForIdentityAcknowledgment(thread.threadId, {
      timeoutMs: this.runtime.identityTimeoutMs,
      pollIntervalMs: this.runtime.identityPollIntervalMs
    })
  }

  private async waitForIdentityAcknowledgment (
    threadId: ThreadId,
    opts: { timeoutMs?: number, pollIntervalMs?: number } = {}
  ): Promise<void> {
    await this.waitForState(threadId, 'identityAcknowledged', opts)
  }

  private async safeAck (messageIds: string[]): Promise<void> {
    try {
      await this.comms.acknowledgeMessage({ messageIds })
    } catch (e) {
      this.cfg.logger?.warn?.('[RemittanceManager] Failed to acknowledge message(s)', e)
    }
  }

  private markThreadError (thread: Thread, e: any): void {
    thread.flags.error = true
    this.transitionThreadState(thread, 'errored', 'thread error')
    thread.lastError = { message: String(e?.message ?? e), at: this.now() }
    this.cfg.logger?.error?.('[RemittanceManager] Thread error', thread.threadId, e)
    this.emitEvent({ type: 'error', threadId: thread.threadId, error: String(e?.message ?? e) })
  }

  private ensureThreadState (thread: Thread): Thread {
    thread.identity = thread.identity ?? {
      certsSent: [],
      certsReceived: [],
      requestSent: false,
      responseSent: false,
      acknowledgmentSent: false,
      acknowledgmentReceived: false
    }
    thread.identity.certsSent ??= []
    thread.identity.certsReceived ??= []
    thread.identity.requestSent ??= false
    thread.identity.responseSent ??= false
    thread.identity.acknowledgmentSent ??= false
    thread.identity.acknowledgmentReceived ??= false

    thread.flags = thread.flags ?? {
      hasIdentified: false,
      hasInvoiced: false,
      hasPaid: false,
      hasReceipted: false,
      error: false
    }
    thread.processedMessageIds ??= []
    thread.protocolLog ??= []
    thread.stateLog ??= []

    if (thread.state == null) {
      thread.state = this.deriveThreadState(thread)
    }
    return thread
  }

  private deriveThreadState (thread: Thread): RemittanceThreadState {
    if (thread.flags.error) return 'errored'
    if (thread.termination != null) return 'terminated'
    if (thread.receipt != null) return 'receipted'
    if (thread.settlement != null) return 'settled'
    if (thread.invoice != null) return 'invoiced'
    if (thread.identity.acknowledgmentReceived || thread.identity.acknowledgmentSent || thread.flags.hasIdentified) {
      return 'identityAcknowledged'
    }
    if (thread.identity.responseSent || thread.identity.certsSent.length > 0) return 'identityResponded'
    if (thread.identity.requestSent || thread.identity.certsReceived.length > 0) return 'identityRequested'
    return 'new'
  }

  private transitionThreadState (thread: Thread, next: RemittanceThreadState, reason?: string): void {
    const current = thread.state
    if (current === next) return
    const allowed = REMITTANCE_STATE_TRANSITIONS[current] ?? []
    if (!allowed.includes(next)) {
      throw new Error(`Invalid remittance state transition: ${current} -> ${next}`)
    }

    thread.state = next
    thread.updatedAt = this.now()
    thread.stateLog.push({ at: this.now(), from: current, to: next, reason })
    this.emitEvent({ type: 'stateChanged', threadId: thread.threadId, previous: current, next, reason })
    this.resolveStateWaiters(thread.threadId, next)
    if (next === 'terminated' || next === 'errored') {
      this.rejectStateWaiters(thread.threadId, new Error(`Thread entered terminal state: ${next}`))
    }
  }

  private resolveStateWaiters (threadId: ThreadId, state: RemittanceThreadState): void {
    const waiters = this.stateWaiters.get(threadId)
    if (waiters == null) return

    const remaining: Array<{ state: RemittanceThreadState, resolve: () => void, reject: (err: Error) => void }> = []
    for (const waiter of waiters) {
      if (waiter.state === state) {
        waiter.resolve()
      } else {
        remaining.push(waiter)
      }
    }
    if (remaining.length === 0) {
      this.stateWaiters.delete(threadId)
    } else {
      this.stateWaiters.set(threadId, remaining)
    }
  }

  private rejectStateWaiters (threadId: ThreadId, err: Error): void {
    const waiters = this.stateWaiters.get(threadId)
    if (waiters == null) return
    for (const waiter of waiters) {
      waiter.reject(err)
    }
    this.stateWaiters.delete(threadId)
  }

  private emitEvent (event: RemittanceEvent): void {
    const handlers = this.eventHandlers
    if (handlers != null) {
      try {
        switch (event.type) {
          case 'threadCreated':
            handlers.onThreadCreated?.(event)
            break
          case 'stateChanged':
            handlers.onStateChanged?.(event)
            break
          case 'envelopeSent':
            handlers.onEnvelopeSent?.(event)
            break
          case 'envelopeReceived':
            handlers.onEnvelopeReceived?.(event)
            break
          case 'identityRequested':
            handlers.onIdentityRequested?.(event)
            break
          case 'identityResponded':
            handlers.onIdentityResponded?.(event)
            break
          case 'identityAcknowledged':
            handlers.onIdentityAcknowledged?.(event)
            break
          case 'invoiceSent':
            handlers.onInvoiceSent?.(event)
            break
          case 'invoiceReceived':
            handlers.onInvoiceReceived?.(event)
            break
          case 'settlementSent':
            handlers.onSettlementSent?.(event)
            break
          case 'settlementReceived':
            handlers.onSettlementReceived?.(event)
            break
          case 'receiptSent':
            handlers.onReceiptSent?.(event)
            break
          case 'receiptReceived':
            handlers.onReceiptReceived?.(event)
            break
          case 'terminationSent':
            handlers.onTerminationSent?.(event)
            break
          case 'terminationReceived':
            handlers.onTerminationReceived?.(event)
            break
          case 'error':
            handlers.onError?.(event)
            break
        }
      } catch (e) {
        this.cfg.logger?.warn?.('[RemittanceManager] Event handler error', e)
      }
    }
    for (const listener of this.eventListeners) {
      try {
        listener(event)
      } catch (e) {
        this.cfg.logger?.warn?.('[RemittanceManager] Event listener error', e)
      }
    }
  }

  private async refreshMyIdentityKey (): Promise<void> {
    if (typeof this.myIdentityKey === 'string') return
    if (typeof this.wallet !== 'object') return

    const { publicKey: k } = await this.wallet.getPublicKey({ identityKey: true }, this.cfg.originator)
    if (typeof k === 'string' && k.trim() !== '') {
      this.myIdentityKey = k
    }
  }

  private requireMyIdentityKey (errMsg: string): PubKeyHex {
    if (typeof this.myIdentityKey !== 'string') {
      throw new Error(errMsg)
    }
    return this.myIdentityKey
  }

  private async composeInvoice (
    threadId: ThreadId,
    payee: PubKeyHex,
    payer: PubKeyHex,
    input: ComposeInvoiceInput
  ): Promise<Invoice> {
    const createdAt = this.now()
    const expiresAt =
      this.runtime.invoiceExpirySeconds >= 0 ? createdAt + this.runtime.invoiceExpirySeconds * 1000 : undefined

    return {
      kind: 'invoice',
      threadId,
      payee,
      payer,
      note: input.note,
      lineItems: input.lineItems,
      total: input.total,
      invoiceNumber: input.invoiceNumber ?? threadId,
      createdAt,
      expiresAt,
      arbitrary: input.arbitrary,
      options: {}
    }
  }
}

/**
 * A lightweight wrapper around a thread's invoice, with convenience methods.
 */
export class ThreadHandle {
  constructor (protected readonly manager: RemittanceManager, public readonly threadId: ThreadId) {}

  get thread (): Thread {
    return this.manager.getThreadOrThrow(this.threadId)
  }

  async waitForState (state: RemittanceThreadState, opts?: { timeoutMs?: number, pollIntervalMs?: number }): Promise<Thread> {
    return await this.manager.waitForState(this.threadId, state, opts)
  }

  async waitForIdentity (opts?: { timeoutMs?: number, pollIntervalMs?: number }): Promise<Thread> {
    return await this.manager.waitForIdentity(this.threadId, opts)
  }

  async waitForSettlement (opts?: { timeoutMs?: number, pollIntervalMs?: number }): Promise<Settlement | Termination> {
    return await this.manager.waitForSettlement(this.threadId, opts)
  }

  async waitForReceipt (opts?: { timeoutMs?: number, pollIntervalMs?: number }): Promise<Receipt | Termination> {
    return await this.manager.waitForReceipt(this.threadId, opts)
  }
}

export class InvoiceHandle extends ThreadHandle {
  get invoice (): Invoice {
    const inv = this.thread.invoice
    if (typeof inv !== 'object') throw new Error('Thread has no invoice')
    return inv
  }

  /**
   * Pays the invoice using the selected remittance option.
   */
  async pay (optionId?: string): Promise<Receipt | Termination | undefined> {
    return await this.manager.pay(this.threadId, optionId)
  }
}

function safeParseEnvelope (body: string): RemittanceEnvelope | undefined {
  try {
    const parsed = JSON.parse(body)
    if (typeof parsed !== 'object') return undefined
    if (parsed.v !== 1) return undefined
    if (typeof parsed.kind !== 'string') return undefined
    if (typeof parsed.threadId !== 'string') return undefined
    if (typeof parsed.id !== 'string') return undefined
    return parsed as RemittanceEnvelope
  } catch {
    return undefined
  }
}

function defaultThreadIdFactory (): ThreadId {
  return toBase64(Random(32))
}

async function sleep (ms: number): Promise<void> {
  return await new Promise((resolve) => setTimeout(resolve, ms))
}
