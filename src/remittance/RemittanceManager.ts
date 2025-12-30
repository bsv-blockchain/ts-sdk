import type {
  IdentityKey,
  Invoice,
  PeerMessage,
  Receipt,
  Settlement,
  ThreadId,
  UnixMillis,
  LoggerLike,
  ModuleContext
} from './types.js'
import type { CommsLayer } from './CommsLayer.js'
import type { RemittanceModule } from './RemittanceModule.js'
import { OriginatorDomainNameStringUnder250Bytes, WalletInterface } from '../wallet/Wallet.interfaces.js'
import { toBase64 } from '../primitives/utils.js'
import Random from '../primitives/Random.js'
import { VerifiableCertificate } from 'mod.js'

export const DEFAULT_REMITTANCE_MESSAGEBOX = 'remittance_inbox'

export interface RemittanceManagerRuntimeOptions {
  /** If true, exchange identity messages at the start of a thread. */
  exchangeIdentityInfo: boolean
  /** If true, payees are expected to send receipts. */
  receiptProvided: boolean
  /** If true, manager auto-sends receipts as soon as a settlement is processed. */
  autoIssueReceipt: boolean
  /** Invoice expiry in seconds, or -1 for no expiry. */
  invoiceExpirySeconds: number
}

export interface RemittanceManagerConfig {
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
    /** Optional invoice publisher for onchain invoice references. */
  /** Persist manager state (threads). */
  stateSaver?: (state: RemittanceManagerState) => Promise<void> | void
  /** Load manager state (threads). */
  stateLoader?: () => Promise<RemittanceManagerState | undefined> | RemittanceManagerState | undefined

  /** Injectable clock for tests. */
  now?: () => UnixMillis
  /** Injectable thread id factory for tests. */
  threadIdFactory?: () => ThreadId
}

export interface Thread {
  threadId: ThreadId
  counterparty: IdentityKey
  myRole: 'maker' | 'taker'
  theirRole: 'maker' | 'taker'
  createdAt: UnixMillis
  updatedAt: UnixMillis

  /** Transport messageIds processed for this thread (dedupe across retries). */
  processedMessageIds: string[]

  /** Protocol envelopes received/sent (for debugging/audit). */
  protocolLog: Array<{
    direction: 'in' | 'out'
    envelope: RemittanceEnvelope
    transportMessageId?: string
  }>

  identity: {
    certsSent: VerifiableCertificate[]
    certsReceived: VerifiableCertificate[]
  }

  invoice?: Invoice
  settlement?: Settlement
  receipt?: Receipt

  flags: {
    hasIdentified: boolean
    hasInvoiced: boolean
    hasPaid: boolean
    hasReceipted: boolean
    error: boolean
  }

  lastError?: { message: string; at: UnixMillis }
}

export interface RemittanceManagerState {
  v: 1
  threads: Thread[]
  defaultPaymentOptionId?: string
}

export interface ComposeInvoiceInput {
  /** Counterparty who will pay the invoice. */
  payer: IdentityKey
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
 * - thread lifecycle and persistence
 * - invoice creation and transmission
 * - settlement routing to the appropriate module
 * - receipt routing to the appropriate module
 * - optional identity certificate exchange
 *
 * Non-responsibilities (left to modules):
 * - transaction structure
 * - UTXO “offer” formats, token logic, BRC-98/99 specifics
 * - validation rules for partial tx templates
 * - on-chain broadcasting strategy
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

  /** Default option id used when paying an invoice, if not overridden per-call. */
  private defaultPaymentOptionId?: string

  /** Mutable threads list (persisted via stateSaver). */
  threads: Thread[]

  /** Cached identity key if wallet provides it. */
  private myIdentityKey?: IdentityKey

  constructor(cfg: RemittanceManagerConfig, wallet: WalletInterface, commsLayer: CommsLayer, threads: Thread[] = []) {
    this.cfg = cfg
    this.wallet = wallet
    this.comms = commsLayer
    this.messageBox = cfg.messageBox ?? DEFAULT_REMITTANCE_MESSAGEBOX

    this.now = cfg.now ?? (() => Date.now())
    this.threadIdFactory = cfg.threadIdFactory ?? defaultThreadIdFactory

    this.moduleRegistry = new Map(cfg.remittanceModules.map((m) => [m.id, m]))

    this.runtime = {
      exchangeIdentityInfo: cfg.options?.exchangeIdentityInfo ?? false,
      receiptProvided: cfg.options?.receiptProvided ?? true,
      autoIssueReceipt: cfg.options?.autoIssueReceipt ?? true,
      invoiceExpirySeconds: cfg.options?.invoiceExpirySeconds ?? 3600
    }

    this.threads = threads
  }

  /**
   * Loads persisted state from cfg.stateLoader (if provided).
   *
   * Safe to call multiple times.
   */
  async init(): Promise<void> {
    if (!this.cfg.stateLoader) return

    const loaded = await this.cfg.stateLoader()
    if (!loaded) return

    this.loadState(loaded)

    if (loaded.defaultPaymentOptionId) {
      this.defaultPaymentOptionId = loaded.defaultPaymentOptionId
    }

    await this.refreshMyIdentityKey()
  }

  /**
   * Sets a default payment option (module id) to use when paying invoices.
   */
  preselectPaymentOption(optionId: string): void {
    this.defaultPaymentOptionId = optionId
  }

  /**
   * Returns an immutable snapshot of current manager state suitable for persistence.
   */
  saveState(): RemittanceManagerState {
    return {
      v: 1,
      threads: JSON.parse(JSON.stringify(this.threads)) as Thread[],
      defaultPaymentOptionId: this.defaultPaymentOptionId
    }
  }

  /**
   * Loads state from an object previously produced by saveState().
   */
  loadState(state: RemittanceManagerState): void {
    if (state.v !== 1) throw new Error(`Unsupported RemittanceManagerState version: ${state.v}`)
    this.threads = state.threads ?? []
    this.defaultPaymentOptionId = state.defaultPaymentOptionId
  }

  /**
   * Persists current state via cfg.stateSaver (if provided).
   */
  async persistState(): Promise<void> {
    if (!this.cfg.stateSaver) return
    await this.cfg.stateSaver(this.saveState())
  }

  /**
   * Syncs threads by fetching pending messages from the comms layer and processing them.
   *
   * Processing is idempotent using transport messageIds tracked per thread.
   * Messages are acknowledged after they are successfully applied to local state.
   */
  async syncThreads(hostOverride?: string): Promise<void> {
    await this.refreshMyIdentityKey()

    const msgs = await this.comms.listMessages({ messageBox: this.messageBox, host: hostOverride })

    for (const msg of msgs) {
      const parsed = safeParseEnvelope(msg.body)
      if (!parsed) {
        // Not our protocol message; leave it for the application or acknowledge? Here we leave it.
        continue
      }

      const thread = this.getOrCreateThreadFromInboundEnvelope(parsed, msg)
      if (thread.processedMessageIds.includes(msg.messageId)) {
        // Already applied; ack and continue.
        await this.safeAck([msg.messageId])
        continue
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
  }

  /**
   * Creates, records, and sends an invoice to a counterparty.
   *
   * Returns a handle you can use to wait for payment/receipt.
   */
  async sendInvoice(to: IdentityKey, input: ComposeInvoiceInput, hostOverride?: string): Promise<InvoiceHandle> {
    await this.refreshMyIdentityKey()

    if (this.runtime.invoiceFormat === 'none') {
      throw new Error("invoiceFormat 'none' does not support sendInvoice(); use unsolicited settlement flows instead")
    }

    const threadId = this.threadIdFactory()
    const createdAt = this.now()

    const myKey = this.requireMyIdentityKey('sendInvoice requires the comms layer to provide an identity key')

    const thread: Thread = {
      threadId,
      counterparty: to,
      myRole: 'maker',
      theirRole: 'taker',
      createdAt,
      updatedAt: createdAt,
      processedMessageIds: [],
      protocolLog: [],
      flags: {
        hasIdentified: !this.runtime.exchangeIdentityInfo,
        hasInvoiced: false,
        hasPaid: false,
        hasReceipted: false,
        error: false
      }
    }

    this.threads.push(thread)

    // Optional identity hello exchange.
    if (this.runtime.exchangeIdentityInfo) {
      await this.ensureIdentityExchange(thread, hostOverride)
    }

    const invoice = await this.composeInvoice(threadId, myKey, to, input)
    thread.invoice = invoice
    thread.flags.hasInvoiced = true

    // Generate option terms for each configured module.
    for (const mod of this.moduleRegistry.values()) {
      const option = await mod.createOption({ threadId, invoice }, this.moduleContext())
      invoice.options[mod.id] = option
    }

    const payload = await this.serializeInvoicePayload(invoice)
    const env = this.makeEnvelope('invoice', threadId, payload)

    await this.sendEnvelope(to, env, hostOverride)
    thread.protocolLog.push({ direction: 'out', envelope: env })
    thread.updatedAt = this.now()
    await this.persistState()

    return new InvoiceHandle(this, threadId)
  }

  /**
   * Returns invoice handles that this manager can pay (we are the taker/payer).
   */
  findInvoicesPayable(counterparty?: IdentityKey): InvoiceHandle[] {
    return this.threads
      .filter((t) => t.myRole === 'taker' && t.invoice && !t.settlement && !t.flags.error)
      .filter((t) => (counterparty ? t.counterparty === counterparty : true))
      .map((t) => new InvoiceHandle(this, t.threadId))
  }

  /**
   * Returns invoice handles that we issued and are waiting to receive settlement for.
   */
  findReceivableInvoices(counterparty?: IdentityKey): InvoiceHandle[] {
    return this.threads
      .filter((t) => t.myRole === 'maker' && t.invoice && !t.settlement && !t.flags.error)
      .filter((t) => (counterparty ? t.counterparty === counterparty : true))
      .map((t) => new InvoiceHandle(this, t.threadId))
  }

  /**
   * Pays an invoice by selecting a remittance option and sending a settlement message.
   *
   * If receipts are enabled (receiptProvided), this method will optionally wait for a receipt.
   */
  async pay(threadId: ThreadId, optionId?: string, hostOverride?: string): Promise<Receipt | undefined> {
    await this.refreshMyIdentityKey()

    const thread = this.getThreadOrThrow(threadId)
    if (!thread.invoice) throw new Error('Thread has no invoice to pay')

    if (thread.flags.error) throw new Error('Thread is in error state')
    if (thread.settlement) throw new Error('Invoice already paid (settlement exists)')

    // Identity exchange is optional but may be required for some modules.
    if (this.runtime.exchangeIdentityInfo) {
      await this.ensureIdentityExchange(thread, hostOverride)
    }

    // Check expiry.
    if (thread.invoice.expiresAt && this.now() > thread.invoice.expiresAt) {
      throw new Error('Invoice is expired')
    }

    const chosenOptionId = optionId ?? this.defaultPaymentOptionId ?? Object.keys(thread.invoice.options)[0]
    if (!chosenOptionId) {
      throw new Error('No remittance options available on invoice')
    }

    const module = this.moduleRegistry.get(chosenOptionId)
    if (!module) {
      throw new Error(`No configured remittance module for option: ${chosenOptionId}`)
    }

    const option = thread.invoice.options[chosenOptionId]
    const myKey = this.requireMyIdentityKey('pay() requires the comms layer to provide an identity key')

    const artifact = await module.buildSettlement(
      { threadId, invoice: thread.invoice, option, note: thread.invoice.note },
      this.moduleContext()
    )

    const settlement: Settlement = {
      kind: 'settlement',
      threadId,
      moduleId: module.id,
      optionId: module.id,
      sender: myKey,
      createdAt: this.now(),
      artifact,
      note: thread.invoice.note
    }

    const env = this.makeEnvelope('settlement', threadId, { settlement })

    // Send settlement to payee (invoice.payee).
    await this.sendEnvelope(thread.invoice.payee, env, hostOverride)
    thread.protocolLog.push({ direction: 'out', envelope: env })

    thread.settlement = settlement
    thread.flags.hasPaid = true
    thread.updatedAt = this.now()
    await this.persistState()

    if (!this.runtime.receiptProvided) {
      return undefined
    }

    // Wait for receipt (polling + syncThreads) up to a default timeout.
    return this.waitForReceipt(threadId)
  }

  /**
   * Waits for a receipt to arrive for a thread.
   *
   * Uses polling via syncThreads because live listeners are optional.
   */
  async waitForReceipt(threadId: ThreadId, opts: { timeoutMs?: number; pollIntervalMs?: number } = {}): Promise<Receipt> {
    const timeoutMs = opts.timeoutMs ?? 30_000
    const pollIntervalMs = opts.pollIntervalMs ?? 500

    const start = this.now()
    while (this.now() - start < timeoutMs) {
      const t = this.getThreadOrThrow(threadId)
      if (t.receipt) return t.receipt

      await this.syncThreads()
      await sleep(pollIntervalMs)
    }

    throw new Error('Timed out waiting for receipt')
  }

  /**
   * Returns a thread by id (if present).
   */
  getThread(threadId: ThreadId): Thread | undefined {
    return this.threads.find((t) => t.threadId === threadId)
  }

  /**
   * Returns a thread by id or throws.
   *
   * Public so helper handles (e.g. InvoiceHandle) can call it.
   */
  getThreadOrThrow(threadId: ThreadId): Thread {
    const t = this.getThread(threadId)
    if (!t) throw new Error(`Unknown thread: ${threadId}`)
    return t
  }

  /**
   * Sends a note message within a thread.
   */
  async sendNote(threadId: ThreadId, to: IdentityKey, text: string, metadata?: Record<string, unknown>): Promise<void> {
    const env = this.makeEnvelope('note', threadId, { text, metadata } satisfies NotePayload)
    await this.sendEnvelope(to, env)
    const thread = this.getThread(threadId)
    if (thread) {
      thread.protocolLog.push({ direction: 'out', envelope: env })
      thread.updatedAt = this.now()
      await this.persistState()
    }
  }

  // ----------------------------
  // Internal helpers
  // ----------------------------

  private async serializeInvoicePayload(invoice: Invoice): Promise<InvoicePayload> {
    if (this.runtime.invoiceFormat === 'offchain') {
      return { invoice }
    }

    if (this.runtime.invoiceFormat === 'hashed') {
      const invoiceHash = hashObjectBase64(invoice)
      return { invoice, invoiceHash }
    }

    if (this.runtime.invoiceFormat === 'onchain') {
      const publisher = this.cfg.invoicePublisher
      if (!publisher) {
        throw new Error("invoiceFormat 'onchain' requires cfg.invoicePublisher")
      }
      const { txid } = await publisher.publishInvoice(invoice)
      const invoiceHash = hashObjectBase64(invoice)
      return { invoiceRef: { type: 'onchain', txid }, invoiceHash }
    }

    // invoiceFormat === 'none'
    throw new Error('serializeInvoicePayload unreachable')
  }

  private moduleContext(): ModuleContext {
    return {
      wallet: this.wallet,
      originator: this.cfg.originator,
      now: this.now,
      logger: this.cfg.logger
    }
  }

  private makeEnvelope<K extends RemittanceKind, P>(kind: K, threadId: ThreadId, payload: P): RemittanceEnvelope<K, P> {
    return {
      v: 2,
      id: this.threadIdFactory(),
      kind,
      threadId,
      createdAt: this.now(),
      payload
    }
  }

  private async sendEnvelope(recipient: IdentityKey, env: RemittanceEnvelope, hostOverride?: string): Promise<void> {
    const body = JSON.stringify(env)

    // Prefer live if available.
    if (this.comms.sendLiveMessage) {
      try {
        await this.comms.sendLiveMessage({ recipient, messageBox: this.messageBox, body }, hostOverride)
        return
      } catch (e) {
        this.cfg.logger?.warn?.('[RemittanceManager] sendLiveMessage failed, falling back to HTTP', e)
      }
    }

    await this.comms.sendMessage({ recipient, messageBox: this.messageBox, body }, hostOverride)
  }

  private getOrCreateThreadFromInboundEnvelope(env: RemittanceEnvelope, msg: PeerMessage): Thread {
    const existing = this.getThread(env.threadId)
    if (existing) return existing

    // If we didn't create the thread, infer roles from the first message kind:
    // - Receiving an invoice -> we are taker (payer)
    // - Receiving a settlement -> we are maker (payee)
    // - Receiving a receipt -> we are taker
    const createdAt = this.now()

    const inferredMyRole: Thread['myRole'] = env.kind === 'invoice' ? 'taker' : env.kind === 'settlement' ? 'maker' : 'taker'
    const inferredTheirRole: Thread['theirRole'] = inferredMyRole === 'maker' ? 'taker' : 'maker'

    const t: Thread = {
      threadId: env.threadId,
      counterparty: msg.sender,
      myRole: inferredMyRole,
      theirRole: inferredTheirRole,
      createdAt,
      updatedAt: createdAt,
      processedMessageIds: [],
      protocolLog: [],
      flags: {
        hasIdentified: !this.runtime.exchangeIdentityInfo,
        hasInvoiced: false,
        hasPaid: false,
        hasReceipted: false,
        error: false
      }
    }

    this.threads.push(t)
    return t
  }

  private async applyInboundEnvelope(thread: Thread, env: RemittanceEnvelope, msg: PeerMessage): Promise<void> {
    thread.protocolLog.push({ direction: 'in', envelope: env, transportMessageId: msg.messageId })

    switch (env.kind) {
      case 'identity.hello': {
        const payload = env.payload as IdentityHelloPayload
        thread.identity = thread.identity ?? {}
        thread.identity.theirs = payload.identity

        if (!thread.identity.mine && this.cfg.identityProvider?.getMyIdentityInfo) {
          thread.identity.mine = await this.cfg.identityProvider.getMyIdentityInfo(thread.counterparty, thread.threadId)
        }

        if (this.cfg.identityProvider?.assessIdentityInfoSufficiency) {
          await this.cfg.identityProvider.assessIdentityInfoSufficiency(thread.counterparty, payload.identity, thread.threadId)
        }

        thread.flags.hasIdentified = true
        return
      }

      case 'invoice': {
        const payload = env.payload as InvoicePayload

        let invoice: Invoice | undefined = payload.invoice

        if (!invoice && payload.invoiceRef?.type === 'onchain') {
          const fetcher = this.cfg.invoicePublisher?.fetchInvoice
          if (!fetcher) {
            throw new Error('Received onchain invoiceRef but no invoicePublisher.fetchInvoice configured')
          }
          invoice = await fetcher(payload.invoiceRef)
        }

        if (!invoice) {
          throw new Error('Invoice payload missing invoice and invoiceRef')
        }

        if (payload.invoiceHash) {
          const actualHash = hashObjectBase64(invoice)
          if (actualHash !== payload.invoiceHash) {
            throw new Error('Invoice hash mismatch')
          }
        }

        thread.invoice = invoice
        thread.flags.hasInvoiced = true
        return
      }

      case 'settlement': {
        const payload = env.payload as SettlementPayload
        const settlement = payload.settlement

        // Persist settlement immediately (even if we later reject); it is part of the audit trail.
        thread.settlement = settlement
        thread.flags.hasPaid = true

        const module = this.moduleRegistry.get(settlement.moduleId)
        if (!module) {
          await this.maybeSendErrorReceipt(thread, settlement, msg.sender, `Unsupported module: ${settlement.moduleId}`)
          return
        }

        const decision = await this.decideOnIncomingSettlement(thread, settlement, msg.sender)
        const rejectionReason = decision === 'reject' ? await this.rejectionReason(thread, settlement, msg.sender) : undefined

        const receiptData =
          decision === 'accept'
            ? await module.acceptSettlement(
                { threadId: thread.threadId, invoice: thread.invoice, settlement: settlement.artifact, sender: msg.sender },
                this.moduleContext()
              )
            : module.rejectSettlement
              ? await module.rejectSettlement(
                  {
                    threadId: thread.threadId,
                    invoice: thread.invoice,
                    settlement: settlement.artifact,
                    sender: msg.sender,
                    reason: rejectionReason
                  },
                  this.moduleContext()
                )
              : ({ rejectedReason: rejectionReason ?? 'Rejected' } as any)

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
          accepted: decision === 'accept',
          receiptData
        }

        thread.receipt = receipt
        thread.flags.hasReceipted = true

        if (this.runtime.receiptProvided && this.runtime.autoIssueReceipt) {
          const receiptEnv = this.makeEnvelope('receipt', thread.threadId, { receipt } satisfies ReceiptPayload)
          await this.sendEnvelope(msg.sender, receiptEnv)
          thread.protocolLog.push({ direction: 'out', envelope: receiptEnv })
        }

        return
      }

      case 'receipt': {
        const payload = env.payload as ReceiptPayload
        const receipt = payload.receipt

        thread.receipt = receipt
        thread.flags.hasReceipted = true

        const module = this.moduleRegistry.get(receipt.moduleId)
        if (module) {
          await module.processReceipt(
            { threadId: thread.threadId, invoice: thread.invoice, receiptData: receipt.receiptData, sender: msg.sender },
            this.moduleContext()
          )
        }

        return
      }

      case 'note': {
        // Notes are just logged.
        return
      }

      case 'error': {
        const payload = env.payload as ErrorPayload
        thread.lastError = { message: payload.message, at: this.now() }
        thread.flags.error = true
        return
      }

      default:
        throw new Error(`Unknown envelope kind: ${(env as any).kind}`)
    }
  }

  private async maybeSendErrorReceipt(thread: Thread, settlement: Settlement, payer: IdentityKey, message: string): Promise<void> {
    if (!this.runtime.receiptProvided) return

    const myKey = this.requireMyIdentityKey('maybeSendErrorReceipt requires identity key')

    const receipt: Receipt = {
      kind: 'receipt',
      threadId: thread.threadId,
      moduleId: settlement.moduleId,
      optionId: settlement.optionId,
      payee: myKey,
      payer,
      createdAt: this.now(),
      accepted: false,
      receiptData: { rejectedReason: message }
    }

    const env = this.makeEnvelope('receipt', thread.threadId, { receipt } satisfies ReceiptPayload)
    await this.sendEnvelope(payer, env)
    thread.protocolLog.push({ direction: 'out', envelope: env })

    thread.receipt = receipt
    thread.flags.hasReceipted = true
  }

  private async ensureIdentityExchange(thread: Thread, hostOverride?: string): Promise<void> {
    if (thread.flags.hasIdentified) return

    const identity = await this.cfg.identityProvider?.getMyIdentityInfo?.(thread.counterparty, thread.threadId)

    const env = this.makeEnvelope('identity.hello', thread.threadId, { identity } satisfies IdentityHelloPayload)
    await this.sendEnvelope(thread.counterparty, env, hostOverride)
    thread.protocolLog.push({ direction: 'out', envelope: env })

    thread.identity = thread.identity ?? {}
    thread.identity.mine = identity

    // “Identified” here means “we performed the identity send step”.
    // Your assessIdentityInfoSufficiency hook determines if the received identity is acceptable.
    thread.flags.hasIdentified = true
  }

  private async decideOnIncomingSettlement(thread: Thread, settlement: Settlement, sender: IdentityKey): Promise<'accept' | 'reject'> {
    const fn = this.cfg.decisionProvider?.decideOnIncomingSettlement
    if (!fn) return 'accept'
    return await fn({ thread, settlement, sender })
  }

  private async rejectionReason(thread: Thread, settlement: Settlement, sender: IdentityKey): Promise<string | undefined> {
    const fn = this.cfg.decisionProvider?.rejectionReason
    if (!fn) return undefined
    return await fn({ thread, settlement, sender })
  }

  private async safeAck(messageIds: string[]): Promise<void> {
    try {
      await this.comms.acknowledgeMessage({ messageIds })
    } catch (e) {
      this.cfg.logger?.warn?.('[RemittanceManager] Failed to acknowledge message(s)', e)
    }
  }

  private markThreadError(thread: Thread, e: any): void {
    thread.flags.error = true
    thread.lastError = { message: String(e?.message ?? e), at: this.now() }
    this.cfg.logger?.error?.('[RemittanceManager] Thread error', thread.threadId, e)
  }

  private async refreshMyIdentityKey(): Promise<void> {
    if (this.myIdentityKey) return
    if (!this.comms.getMyIdentityKey) return

    const k = await this.comms.getMyIdentityKey()
    if (typeof k === 'string' && k.trim() !== '') {
      this.myIdentityKey = k
    }
  }

  private requireMyIdentityKey(errMsg: string): IdentityKey {
    if (!this.myIdentityKey) {
      throw new Error(errMsg)
    }
    return this.myIdentityKey
  }

  private async composeInvoice(
    threadId: ThreadId,
    payee: IdentityKey,
    payer: IdentityKey,
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
      invoiceNumber: input.invoiceNumber,
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
export class InvoiceHandle {
  constructor(private readonly manager: RemittanceManager, public readonly threadId: ThreadId) {}

  get thread(): Thread {
    return this.manager.getThreadOrThrow(this.threadId)
  }

  get invoice(): Invoice {
    const inv = this.thread.invoice
    if (!inv) throw new Error('Thread has no invoice')
    return inv
  }

  /**
   * Pays the invoice using the selected remittance option.
   */
  async pay(optionId?: string): Promise<Receipt | undefined> {
    return this.manager.pay(this.threadId, optionId)
  }

  /**
   * Waits for a receipt for this invoice's thread.
   */
  async waitForReceipt(opts?: { timeoutMs?: number; pollIntervalMs?: number }): Promise<Receipt> {
    return this.manager.waitForReceipt(this.threadId, opts)
  }
}

function safeParseEnvelope(body: string): RemittanceEnvelope | undefined {
  try {
    const parsed = JSON.parse(body)
    if (!parsed || typeof parsed !== 'object') return undefined
    if (parsed.v !== 2) return undefined
    if (typeof parsed.kind !== 'string') return undefined
    if (typeof parsed.threadId !== 'string') return undefined
    if (typeof parsed.id !== 'string') return undefined
    return parsed as RemittanceEnvelope
  } catch {
    return undefined
  }
}

function defaultThreadIdFactory(): ThreadId {
  return toBase64(Random(32))
}

async function sleep(ms: number): Promise<void> {
  return await new Promise((resolve) => setTimeout(resolve, ms))
}
