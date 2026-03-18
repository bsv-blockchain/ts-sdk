import type { CommsLayer } from '../CommsLayer.js'
import type { IdentityLayer } from '../IdentityLayer.js'
import type { RemittanceModule } from '../RemittanceModule.js'
import type { ComposeInvoiceInput } from '../RemittanceManager.js'
import type { PeerMessage, RemittanceEnvelope, Termination, ThreadId } from '../types.js'
import type { WalletInterface, PubKeyHex } from '../../wallet/Wallet.interfaces.js'
import { RemittanceManager, DEFAULT_REMITTANCE_MESSAGEBOX } from '../RemittanceManager.js'

// ---------------------------------------------------------------------------
// Shared test infrastructure (mirrors the existing test file's helpers)
// ---------------------------------------------------------------------------

class MessageBus {
  private messages: PeerMessage[] = []
  private nextId = 1

  send (sender: PubKeyHex, recipient: PubKeyHex, messageBox: string, body: string): string {
    const messageId = `msg-${this.nextId++}`
    this.messages.push({ messageId, sender, recipient, messageBox, body })
    return messageId
  }

  list (recipient: PubKeyHex, messageBox: string): PeerMessage[] {
    return this.messages.filter((m) => m.recipient === recipient && m.messageBox === messageBox)
  }

  ack (recipient: PubKeyHex, messageIds: string[]): void {
    this.messages = this.messages.filter(
      (m) => m.recipient !== recipient || !messageIds.includes(m.messageId)
    )
  }

  all (): PeerMessage[] { return [...this.messages] }
}

class TestComms implements CommsLayer {
  constructor (private readonly owner: PubKeyHex, private readonly bus: MessageBus) {}

  async sendMessage (args: { recipient: PubKeyHex; messageBox: string; body: string }): Promise<string> {
    return this.bus.send(this.owner, args.recipient, args.messageBox, args.body)
  }

  async listMessages (args: { messageBox: string; host?: string }): Promise<PeerMessage[]> {
    return this.bus.list(this.owner, args.messageBox)
  }

  async acknowledgeMessage (args: { messageIds: string[] }): Promise<void> {
    this.bus.ack(this.owner, args.messageIds)
  }
}

const makeWallet = (identityKey: PubKeyHex): WalletInterface =>
  ({ getPublicKey: async () => ({ publicKey: identityKey }) } as unknown as WalletInterface)

const makeInvoiceInput = (overrides: Partial<ComposeInvoiceInput> = {}): ComposeInvoiceInput => ({
  lineItems: [],
  total: { value: '1000', unit: { namespace: 'bsv', code: 'sat', decimals: 0 } },
  note: 'Test invoice',
  invoiceNumber: 'INV-1',
  ...overrides
})

const parseEnvelope = (msg: PeerMessage): RemittanceEnvelope => JSON.parse(msg.body) as RemittanceEnvelope

const makeThreadIdFactory = (): (() => ThreadId) => {
  let i = 0
  return () => `thread-${++i}` as ThreadId
}

const tick = async (): Promise<void> => await new Promise((resolve) => setTimeout(resolve, 0))

const makeModule = (overrides: Partial<RemittanceModule<any, any, any>> = {}): RemittanceModule<any, any, any> => ({
  id: 'test-module',
  name: 'Test Module',
  allowUnsolicitedSettlements: false,
  createOption: async () => ({}),
  buildSettlement: async () => ({ action: 'settle', artifact: {} }),
  acceptSettlement: async () => ({ action: 'accept', receiptData: {} }),
  ...overrides
})

const makeIdentityLayer = (): IdentityLayer => ({
  determineCertificatesToRequest: async ({ threadId }) => ({
    kind: 'identityVerificationRequest',
    threadId,
    request: { types: { basic: ['name'] }, certifiers: ['certifier-key'] }
  }),
  respondToRequest: async ({ threadId }) => ({
    action: 'respond',
    response: {
      kind: 'identityVerificationResponse',
      threadId,
      certificates: [{
        type: 'YmFzaWM=',
        certifier: 'certifier-key',
        subject: 'subject-key',
        fields: { name: 'QWxpY2U=' },
        signature: 'deadbeef',
        serialNumber: 'c2VyaWFs',
        revocationOutpoint: 'outpoint',
        keyringForVerifier: { name: 'a2V5' }
      }]
    }
  }),
  assessReceivedCertificateSufficiency: async (_cp, _received, threadId) => ({
    kind: 'identityVerificationAcknowledgment',
    threadId
  })
})

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('RemittanceManager additional coverage', () => {
  describe('init() and state persistence', () => {
    it('init does nothing when stateLoader is not configured', async () => {
      const bus = new MessageBus()
      const manager = new RemittanceManager(
        { remittanceModules: [makeModule()], threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )
      await expect(manager.init()).resolves.toBeUndefined()
    })

    it('init loads state from stateLoader and sets defaultPaymentOptionId', async () => {
      const bus = new MessageBus()
      const state = {
        v: 1 as const,
        threads: [],
        defaultPaymentOptionId: 'test-module'
      }
      const manager = new RemittanceManager(
        {
          remittanceModules: [makeModule()],
          threadIdFactory: makeThreadIdFactory(),
          stateLoader: async () => state
        },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )
      await manager.init()
      expect((manager as any).defaultPaymentOptionId).toBe('test-module')
    })

    it('init skips state loading when stateLoader returns undefined', async () => {
      const bus = new MessageBus()
      const manager = new RemittanceManager(
        {
          remittanceModules: [makeModule()],
          threadIdFactory: makeThreadIdFactory(),
          stateLoader: async () => undefined
        },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )
      await expect(manager.init()).resolves.toBeUndefined()
      expect(manager.threads).toHaveLength(0)
    })

    it('saveState returns a serializable snapshot including threads', async () => {
      const bus = new MessageBus()
      const manager = new RemittanceManager(
        { remittanceModules: [makeModule()], threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )
      await manager.sendInvoice('k2', makeInvoiceInput())
      const state = manager.saveState()
      expect(state.v).toBe(1)
      expect(state.threads).toHaveLength(1)
    })

    it('loadState throws on unsupported version', () => {
      const bus = new MessageBus()
      const manager = new RemittanceManager(
        { remittanceModules: [makeModule()], threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )
      expect(() => manager.loadState({ v: 2 as any, threads: [] })).toThrow('Unsupported RemittanceManagerState version')
    })

    it('loadState restores threads', async () => {
      const bus = new MessageBus()
      const manager = new RemittanceManager(
        { remittanceModules: [makeModule()], threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )
      await manager.sendInvoice('k2', makeInvoiceInput())
      const snapshot = manager.saveState()

      const manager2 = new RemittanceManager(
        { remittanceModules: [makeModule()], threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )
      manager2.loadState(snapshot)
      expect(manager2.threads).toHaveLength(1)
    })

    it('persistState calls stateSaver with current state', async () => {
      const bus = new MessageBus()
      const stateSaver = jest.fn()
      const manager = new RemittanceManager(
        { remittanceModules: [makeModule()], threadIdFactory: makeThreadIdFactory(), stateSaver },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )
      await manager.persistState()
      expect(stateSaver).toHaveBeenCalledWith(expect.objectContaining({ v: 1 }))
    })

    it('persistState does nothing without stateSaver', async () => {
      const bus = new MessageBus()
      const manager = new RemittanceManager(
        { remittanceModules: [makeModule()], threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )
      await expect(manager.persistState()).resolves.toBeUndefined()
    })
  })

  describe('thread accessors', () => {
    it('getThread returns undefined for unknown threadId', async () => {
      const bus = new MessageBus()
      const manager = new RemittanceManager(
        { remittanceModules: [makeModule()], threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )
      expect(manager.getThread('does-not-exist' as ThreadId)).toBeUndefined()
    })

    it('getThreadOrThrow throws for unknown threadId', async () => {
      const bus = new MessageBus()
      const manager = new RemittanceManager(
        { remittanceModules: [makeModule()], threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )
      expect(() => manager.getThreadOrThrow('nope' as ThreadId)).toThrow('Unknown thread: nope')
    })

    it('getThreadHandle returns a handle with the correct threadId', async () => {
      const bus = new MessageBus()
      const manager = new RemittanceManager(
        { remittanceModules: [makeModule()], threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )
      const handle = await manager.sendInvoice('k2', makeInvoiceInput())
      const h2 = manager.getThreadHandle(handle.threadId)
      expect(h2.threadId).toBe(handle.threadId)
    })
  })

  describe('preselectPaymentOption', () => {
    it('uses preselectPaymentOption when no optionId is given to pay()', async () => {
      const bus = new MessageBus()
      const buildSettlement = jest.fn(async () => ({ action: 'settle' as const, artifact: {} }))
      const mod = makeModule({ id: 'selected-mod', buildSettlement })

      const maker = new RemittanceManager(
        { remittanceModules: [mod], options: { receiptProvided: false }, threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )
      const taker = new RemittanceManager(
        { remittanceModules: [mod], options: { receiptProvided: false }, threadIdFactory: makeThreadIdFactory() },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      const handle = await maker.sendInvoice('taker-key', makeInvoiceInput())
      await taker.syncThreads()

      taker.preselectPaymentOption('selected-mod')
      await taker.pay(handle.threadId)

      expect(buildSettlement).toHaveBeenCalled()
    })
  })

  describe('findInvoicesPayable and findReceivableInvoices', () => {
    it('findInvoicesPayable returns threads where we are taker and invoice not yet paid', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const maker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )
      const taker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      await maker.sendInvoice('taker-key', makeInvoiceInput())
      await taker.syncThreads()

      const payable = taker.findInvoicesPayable()
      expect(payable).toHaveLength(1)
    })

    it('findInvoicesPayable filters by counterparty when provided', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const maker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )
      const taker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      await maker.sendInvoice('taker-key', makeInvoiceInput())
      await taker.syncThreads()

      expect(taker.findInvoicesPayable('maker-key')).toHaveLength(1)
      expect(taker.findInvoicesPayable('other-key')).toHaveLength(0)
    })

    it('findReceivableInvoices returns threads where we are maker and waiting on payment', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const maker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )

      await maker.sendInvoice('taker-key', makeInvoiceInput())
      const receivable = maker.findReceivableInvoices()
      expect(receivable).toHaveLength(1)
      expect(maker.findReceivableInvoices('taker-key')).toHaveLength(1)
      expect(maker.findReceivableInvoices('other')).toHaveLength(0)
    })
  })

  describe('sendInvoiceForThread', () => {
    it('throws when called on a non-maker thread', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const maker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )
      const taker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      await maker.sendInvoice('taker-key', makeInvoiceInput())
      await taker.syncThreads()

      const takerThread = taker.threads[0]
      await expect(
        taker.sendInvoiceForThread(takerThread.threadId, makeInvoiceInput())
      ).rejects.toThrow('Only makers can send invoices')
    })

    it('throws when the thread already has an invoice', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const maker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )

      const handle = await maker.sendInvoice('taker-key', makeInvoiceInput())
      await expect(
        maker.sendInvoiceForThread(handle.threadId, makeInvoiceInput())
      ).rejects.toThrow('Thread already has an invoice')
    })

    it('throws when thread is in error state', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const maker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )

      const handle = await maker.sendInvoice('taker-key', makeInvoiceInput())
      const thread = maker.getThreadOrThrow(handle.threadId)
      // Force error state
      thread.flags.error = true

      await expect(
        maker.sendInvoiceForThread(handle.threadId, makeInvoiceInput())
      ).rejects.toThrow('Thread is in error state')
    })
  })

  describe('pay() edge cases', () => {
    it('throws when trying to pay a thread with no invoice', async () => {
      const bus = new MessageBus()
      const mod = makeModule({ allowUnsolicitedSettlements: true })

      const taker = new RemittanceManager(
        { remittanceModules: [mod], options: { receiptProvided: false }, threadIdFactory: makeThreadIdFactory() },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      const handle = await taker.sendUnsolicitedSettlement('maker-key', { moduleId: mod.id, option: {} })
      await expect(
        taker.pay(handle.threadId)
      ).rejects.toThrow('Thread has no invoice to pay')
    })

    it('throws when invoice is expired', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const maker = new RemittanceManager(
        {
          remittanceModules: [mod],
          options: { invoiceExpirySeconds: 1 },
          threadIdFactory: makeThreadIdFactory(),
          // Invoice created at t=1_000_000ms; expires at t=1_001_000ms
          now: () => 1_000_000
        },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )
      const taker = new RemittanceManager(
        {
          remittanceModules: [mod],
          options: { receiptProvided: false },
          threadIdFactory: makeThreadIdFactory(),
          // Taker's clock is at t=2_000_000ms, well past the expiry
          now: () => 2_000_000
        },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      const handle = await maker.sendInvoice('taker-key', makeInvoiceInput())
      await taker.syncThreads()

      const takerThreadId = taker.threads[0].threadId
      await expect(taker.pay(takerThreadId)).rejects.toThrow('Invoice is expired')
    })

    it('throws when no remittance options are available', async () => {
      const bus = new MessageBus()

      // Module that creates no option (no createOption fn)
      const mod: RemittanceModule<any, any, any> = {
        id: 'no-option-module',
        name: 'No Option',
        allowUnsolicitedSettlements: false,
        buildSettlement: async () => ({ action: 'settle', artifact: {} }),
        acceptSettlement: async () => ({ action: 'accept', receiptData: {} })
      }

      const maker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )
      const taker = new RemittanceManager(
        { remittanceModules: [mod], options: { receiptProvided: false }, threadIdFactory: makeThreadIdFactory() },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      const handle = await maker.sendInvoice('taker-key', makeInvoiceInput())
      await taker.syncThreads()
      const takerThread = taker.threads[0]

      await expect(taker.pay(takerThread.threadId)).rejects.toThrow('No remittance options available on invoice')
    })

    it('throws when trying to pay a thread already in error state', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const maker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )
      const taker = new RemittanceManager(
        { remittanceModules: [mod], options: { receiptProvided: false }, threadIdFactory: makeThreadIdFactory() },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      const handle = await maker.sendInvoice('taker-key', makeInvoiceInput())
      await taker.syncThreads()

      const takerThread = taker.threads[0]
      takerThread.flags.error = true

      await expect(taker.pay(takerThread.threadId)).rejects.toThrow('Thread is in error state')
    })

    it('throws when trying to pay an invoice that is already settled', async () => {
      const bus = new MessageBus()
      const mod = makeModule({ allowUnsolicitedSettlements: false })

      const maker = new RemittanceManager(
        { remittanceModules: [mod], options: { receiptProvided: false, autoIssueReceipt: false }, threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )
      const taker = new RemittanceManager(
        { remittanceModules: [mod], options: { receiptProvided: false }, threadIdFactory: makeThreadIdFactory() },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      const handle = await maker.sendInvoice('taker-key', makeInvoiceInput())
      await taker.syncThreads()

      const takerThread = taker.threads[0]
      await taker.pay(takerThread.threadId)

      await expect(taker.pay(takerThread.threadId)).rejects.toThrow('Invoice already paid')
    })

    it('throws when module is not found for the chosen option', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const maker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )
      const taker = new RemittanceManager(
        { remittanceModules: [mod], options: { receiptProvided: false }, threadIdFactory: makeThreadIdFactory() },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      const handle = await maker.sendInvoice('taker-key', makeInvoiceInput())
      await taker.syncThreads()

      const takerThread = taker.threads[0]
      await expect(taker.pay(takerThread.threadId, 'unknown-module-id')).rejects.toThrow(
        'No configured remittance module for option: unknown-module-id'
      )
    })
  })

  describe('sendUnsolicitedSettlement edge cases', () => {
    it('throws when the module does not allow unsolicited settlements', async () => {
      const bus = new MessageBus()
      const mod = makeModule({ id: 'no-unsolicited', allowUnsolicitedSettlements: false })

      const taker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      await expect(
        taker.sendUnsolicitedSettlement('maker-key', { moduleId: 'no-unsolicited', option: {} })
      ).rejects.toThrow('does not allow unsolicited settlements')
    })

    it('throws when module id is unknown', async () => {
      const bus = new MessageBus()
      const mod = makeModule({ allowUnsolicitedSettlements: true })

      const taker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      await expect(
        taker.sendUnsolicitedSettlement('maker-key', { moduleId: 'no-such-module', option: {} })
      ).rejects.toThrow('No configured remittance module for option: no-such-module')
    })

    it('sends termination when buildSettlement returns terminate for unsolicited', async () => {
      const bus = new MessageBus()
      const termination: Termination = { code: 'build.fail', message: 'build failed' }
      const mod = makeModule({
        id: 'term-mod',
        allowUnsolicitedSettlements: true,
        buildSettlement: async () => ({ action: 'terminate', termination })
      })

      const taker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      const handle = await taker.sendUnsolicitedSettlement('maker-key', { moduleId: 'term-mod', option: {} })
      const thread = taker.getThreadOrThrow(handle.threadId)
      expect(thread.state).toBe('terminated')
    })
  })

  describe('inbound message edge cases', () => {
    it('ignores messages that do not parse as valid envelopes', async () => {
      const bus = new MessageBus()
      const mod = makeModule()
      const manager = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )

      // Send an unparseable message
      bus.send('k2', 'k1', DEFAULT_REMITTANCE_MESSAGEBOX, 'not json at all')
      bus.send('k2', 'k1', DEFAULT_REMITTANCE_MESSAGEBOX, JSON.stringify({ v: 1, kind: 'invoice' })) // missing threadId
      bus.send('k2', 'k1', DEFAULT_REMITTANCE_MESSAGEBOX, JSON.stringify({ v: 2, kind: 'invoice', threadId: 't', id: 'i' })) // wrong version

      await manager.syncThreads()
      expect(manager.threads).toHaveLength(0)
    })

    it('deduplicates already-processed message IDs', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const maker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )
      const taker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      await maker.sendInvoice('taker-key', makeInvoiceInput())
      // Sync twice — second sync should see the same message re-listed (bus doesn't ack in this test manually)
      // To simulate re-delivery, don't ack by using a non-acking comms
      const msgs = bus.list('taker-key', DEFAULT_REMITTANCE_MESSAGEBOX)
      expect(msgs).toHaveLength(1)

      await taker.syncThreads()
      expect(taker.threads).toHaveLength(1)
      const threadId = taker.threads[0].threadId

      // simulate re-delivery
      await taker.syncThreads()
      // Still only one thread, not duplicated
      expect(taker.threads).toHaveLength(1)
      expect(taker.getThreadOrThrow(threadId).processedMessageIds).toHaveLength(1)
    })

    it('receives identity verification request but sends termination when no identity layer configured', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const identityLayer = makeIdentityLayer()
      const sender = new RemittanceManager(
        {
          remittanceModules: [mod],
          identityLayer,
          options: { identityOptions: { makerRequestIdentity: 'beforeInvoicing' }, identityTimeoutMs: 100, identityPollIntervalMs: 5 },
          threadIdFactory: makeThreadIdFactory()
        },
        makeWallet('sender-key'),
        new TestComms('sender-key', bus)
      )

      // receiver has NO identity layer
      const receiver = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('receiver-key'),
        new TestComms('receiver-key', bus)
      )

      // Sender sends an identity verification request
      const identityRequestEnv: RemittanceEnvelope = {
        v: 1,
        id: 'env-id-req',
        kind: 'identityVerificationRequest',
        threadId: 'thread-noid' as ThreadId,
        createdAt: 1,
        payload: {
          kind: 'identityVerificationRequest',
          threadId: 'thread-noid',
          request: { types: { basic: ['name'] }, certifiers: ['c'] }
        }
      }
      bus.send('sender-key', 'receiver-key', DEFAULT_REMITTANCE_MESSAGEBOX, JSON.stringify(identityRequestEnv))

      await receiver.syncThreads()
      // Should have sent a termination back
      const termMsgs = bus.list('sender-key', DEFAULT_REMITTANCE_MESSAGEBOX)
      const termEnv = JSON.parse(termMsgs[0].body) as RemittanceEnvelope
      expect(termEnv.kind).toBe('termination')
    })

    it('receives identity verification response but sends termination when no identity layer configured', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const receiver = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('receiver-key'),
        new TestComms('receiver-key', bus)
      )

      const identityResponseEnv: RemittanceEnvelope = {
        v: 1,
        id: 'env-id-resp',
        kind: 'identityVerificationResponse',
        threadId: 'thread-noid-resp' as ThreadId,
        createdAt: 1,
        payload: {
          kind: 'identityVerificationResponse',
          threadId: 'thread-noid-resp',
          certificates: []
        }
      }
      bus.send('sender-key', 'receiver-key', DEFAULT_REMITTANCE_MESSAGEBOX, JSON.stringify(identityResponseEnv))

      await receiver.syncThreads()
      const termMsgs = bus.list('sender-key', DEFAULT_REMITTANCE_MESSAGEBOX)
      const termEnv = JSON.parse(termMsgs[0].body) as RemittanceEnvelope
      expect(termEnv.kind).toBe('termination')
    })

    it('settlement received when module not found sends termination', async () => {
      const bus = new MessageBus()
      const mod = makeModule({ id: 'known-mod' })

      const maker = new RemittanceManager(
        { remittanceModules: [mod], options: { receiptProvided: false }, threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )

      const settlementEnv: RemittanceEnvelope = {
        v: 1,
        id: 'env-settle',
        kind: 'settlement',
        threadId: 'thread-settle-unknown' as ThreadId,
        createdAt: 1,
        payload: {
          kind: 'settlement',
          threadId: 'thread-settle-unknown',
          moduleId: 'unknown-mod', // not registered
          optionId: 'unknown-mod',
          sender: 'taker-key',
          createdAt: 1,
          artifact: {}
        }
      }

      bus.send('taker-key', 'maker-key', DEFAULT_REMITTANCE_MESSAGEBOX, JSON.stringify(settlementEnv))
      await maker.syncThreads()

      const termMsgs = bus.list('taker-key', DEFAULT_REMITTANCE_MESSAGEBOX)
      expect(termMsgs.length).toBeGreaterThan(0)
      const termEnv = JSON.parse(termMsgs[0].body) as RemittanceEnvelope
      expect(termEnv.kind).toBe('termination')
    })

    it('settlement received for a module that does not allow unsolicited settlements sends termination', async () => {
      const bus = new MessageBus()
      const mod = makeModule({ id: 'no-unsolicited', allowUnsolicitedSettlements: false })

      const maker = new RemittanceManager(
        { remittanceModules: [mod], options: { receiptProvided: false }, threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )

      const settlementEnv: RemittanceEnvelope = {
        v: 1,
        id: 'env-settle2',
        kind: 'settlement',
        threadId: 'thread-settle-nosolicited' as ThreadId,
        createdAt: 1,
        payload: {
          kind: 'settlement',
          threadId: 'thread-settle-nosolicited',
          moduleId: 'no-unsolicited',
          optionId: 'no-unsolicited',
          sender: 'taker-key',
          createdAt: 1,
          artifact: {}
        }
      }

      bus.send('taker-key', 'maker-key', DEFAULT_REMITTANCE_MESSAGEBOX, JSON.stringify(settlementEnv))
      await maker.syncThreads()

      const termMsgs = bus.list('taker-key', DEFAULT_REMITTANCE_MESSAGEBOX)
      expect(termMsgs.length).toBeGreaterThan(0)
    })

    it('termination received triggers processTermination on module when settlement exists', async () => {
      const bus = new MessageBus()
      const processTermination = jest.fn()
      const mod = makeModule({
        id: 'term-receiver',
        allowUnsolicitedSettlements: false,
        processTermination
      })

      const maker = new RemittanceManager(
        { remittanceModules: [mod], options: { receiptProvided: true, autoIssueReceipt: false }, threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )
      const taker = new RemittanceManager(
        { remittanceModules: [mod], options: { receiptProvided: false }, threadIdFactory: makeThreadIdFactory() },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      const handle = await maker.sendInvoice('taker-key', makeInvoiceInput())
      await taker.syncThreads()
      const takerThread = taker.threads[0]

      // Taker pays invoice
      await taker.pay(takerThread.threadId)

      // Maker processes settlement
      await maker.syncThreads()

      // Simulate taker receiving a termination
      const terminationEnv: RemittanceEnvelope = {
        v: 1,
        id: 'env-term',
        kind: 'termination',
        threadId: takerThread.threadId,
        createdAt: 1,
        payload: { code: 'rejected', message: 'Payment rejected' }
      }
      bus.send('maker-key', 'taker-key', DEFAULT_REMITTANCE_MESSAGEBOX, JSON.stringify(terminationEnv))
      await taker.syncThreads()

      expect(processTermination).toHaveBeenCalled()
    })

    it('unknown envelope kind causes thread to enter errored state', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const manager = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )

      const unknownEnv = {
        v: 1,
        id: 'env-unknown',
        kind: 'unknown-kind',
        threadId: 'thread-unknown',
        createdAt: 1,
        payload: {}
      }
      bus.send('k2', 'k1', DEFAULT_REMITTANCE_MESSAGEBOX, JSON.stringify(unknownEnv))
      await manager.syncThreads()

      const thread = manager.getThreadOrThrow('thread-unknown' as ThreadId)
      expect(thread.state).toBe('errored')
    })
  })

  describe('event listeners', () => {
    it('onEvent registers and fires for each remittance lifecycle event', async () => {
      const bus = new MessageBus()
      const mod = makeModule({ id: 'ev-mod', allowUnsolicitedSettlements: true })

      const events: string[] = []
      const manager = new RemittanceManager(
        {
          remittanceModules: [mod],
          onEvent: (e) => events.push(e.type),
          threadIdFactory: makeThreadIdFactory()
        },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )

      await manager.sendUnsolicitedSettlement('k2', { moduleId: 'ev-mod', option: {} })
      expect(events).toContain('threadCreated')
      expect(events).toContain('settlementSent')
    })

    it('onEvent listener can be removed via returned disposer', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const events: string[] = []
      const manager = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )

      const dispose = manager.onEvent((e) => events.push(e.type))
      dispose()

      await manager.sendInvoice('k2', makeInvoiceInput())
      expect(events).toHaveLength(0)
    })

    it('fires all event handler callbacks configured via events object', async () => {
      const bus = new MessageBus()
      const mod = makeModule({
        id: 'events-all',
        allowUnsolicitedSettlements: false,
        createOption: async () => ({}),
        buildSettlement: async () => ({ action: 'settle', artifact: {} }),
        acceptSettlement: async () => ({ action: 'accept', receiptData: {} })
      })

      const onThreadCreated = jest.fn()
      const onStateChanged = jest.fn()
      const onInvoiceSent = jest.fn()
      const onInvoiceReceived = jest.fn()
      const onSettlementSent = jest.fn()
      const onSettlementReceived = jest.fn()
      const onReceiptSent = jest.fn()
      const onReceiptReceived = jest.fn()

      const maker = new RemittanceManager(
        {
          remittanceModules: [mod],
          options: { receiptProvided: true, autoIssueReceipt: true },
          events: {
            onThreadCreated,
            onStateChanged,
            onInvoiceSent,
            onSettlementReceived,
            onReceiptSent
          },
          threadIdFactory: makeThreadIdFactory()
        },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )
      const taker = new RemittanceManager(
        {
          remittanceModules: [mod],
          options: { receiptProvided: true },
          events: {
            onInvoiceReceived,
            onSettlementSent,
            onReceiptReceived
          },
          threadIdFactory: makeThreadIdFactory()
        },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      const handle = await maker.sendInvoice('taker-key', makeInvoiceInput())
      await taker.syncThreads()
      const payPromise = taker.pay(handle.threadId, 'events-all')
      await tick()
      await maker.syncThreads()
      await payPromise

      expect(onThreadCreated).toHaveBeenCalled()
      expect(onInvoiceSent).toHaveBeenCalled()
      expect(onStateChanged).toHaveBeenCalled()
      expect(onInvoiceReceived).toHaveBeenCalled()
      expect(onSettlementSent).toHaveBeenCalled()
      expect(onSettlementReceived).toHaveBeenCalled()
      expect(onReceiptSent).toHaveBeenCalled()
      expect(onReceiptReceived).toHaveBeenCalled()
    })
  })

  describe('startListening', () => {
    it('throws when CommsLayer does not support live messages', async () => {
      const bus = new MessageBus()
      const mod = makeModule()
      const manager = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        new TestComms('k1', bus) // TestComms does not implement listenForLiveMessages
      )

      await expect(manager.startListening()).rejects.toThrow('CommsLayer does not support live message listening')
    })
  })

  describe('sendEnvelope with live message fallback', () => {
    it('falls back to sendMessage when sendLiveMessage fails', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const sendLiveMessage = jest.fn(async () => { throw new Error('live failed') })
      const sendMessage = jest.fn(async () => 'msg-123')
      const listMessages = jest.fn(async () => [])
      const acknowledgeMessage = jest.fn(async () => undefined)

      const comms: CommsLayer = { sendMessage, listMessages, acknowledgeMessage, sendLiveMessage }
      const logger = { log: jest.fn(), warn: jest.fn(), error: jest.fn() }

      const manager = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory(), logger },
        makeWallet('k1'),
        comms
      )

      await manager.sendInvoice('k2', makeInvoiceInput())
      expect(sendLiveMessage).toHaveBeenCalled()
      expect(sendMessage).toHaveBeenCalled()
    })
  })

  describe('waitForReceipt timeout', () => {
    it('throws when receipt does not arrive within the timeout', async () => {
      const bus = new MessageBus()
      const mod = makeModule({ allowUnsolicitedSettlements: false })

      const maker = new RemittanceManager(
        { remittanceModules: [mod], options: { receiptProvided: false }, threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )

      const handle = await maker.sendInvoice('k2', makeInvoiceInput())
      const thread = maker.getThreadOrThrow(handle.threadId)
      // Manually set the thread to 'settled' without an actual receipt
      thread.flags.hasPaid = true
      thread.state = 'settled'

      await expect(
        maker.waitForReceipt(handle.threadId, { timeoutMs: 10, pollIntervalMs: 5 })
      ).rejects.toThrow('Timed out waiting for receipt')
    })
  })

  describe('waitForSettlement timeout', () => {
    it('throws when settlement does not arrive within the timeout', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const maker = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )

      const handle = await maker.sendInvoice('k2', makeInvoiceInput())

      await expect(
        maker.waitForSettlement(handle.threadId, { timeoutMs: 10, pollIntervalMs: 5 })
      ).rejects.toThrow('Timed out waiting for settlement')
    })

    it('returns settlement immediately if already set', async () => {
      const bus = new MessageBus()
      const mod = makeModule({ allowUnsolicitedSettlements: false })

      const maker = new RemittanceManager(
        { remittanceModules: [mod], options: { receiptProvided: true, autoIssueReceipt: true }, threadIdFactory: makeThreadIdFactory() },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )
      const taker = new RemittanceManager(
        { remittanceModules: [mod], options: { receiptProvided: false }, threadIdFactory: makeThreadIdFactory() },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      const handle = await maker.sendInvoice('taker-key', makeInvoiceInput())
      await taker.syncThreads()
      await taker.pay(handle.threadId, 'test-module')
      await maker.syncThreads()

      const settlement = await maker.waitForSettlement(handle.threadId, { timeoutMs: 1000 })
      expect(settlement).toBeDefined()
      expect((settlement as any).kind).toBe('settlement')
    })
  })

  describe('waitForState errors', () => {
    it('throws immediately when thread is already in errored state', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const manager = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )

      const handle = await manager.sendInvoice('k2', makeInvoiceInput())
      const thread = manager.getThreadOrThrow(handle.threadId)
      thread.state = 'errored'

      await expect(
        manager.waitForState(handle.threadId, 'receipted', { timeoutMs: 50 })
      ).rejects.toThrow('Thread entered terminal state: errored')
    })

    it('throws immediately when thread is already in terminated state', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const manager = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )

      const handle = await manager.sendInvoice('k2', makeInvoiceInput())
      const thread = manager.getThreadOrThrow(handle.threadId)
      thread.state = 'terminated'

      await expect(
        manager.waitForState(handle.threadId, 'receipted', { timeoutMs: 50 })
      ).rejects.toThrow('Thread entered terminal state: terminated')
    })
  })

  describe('shouldRequestIdentity missing identityLayer', () => {
    it('throws when identityOptions requires identity but no identityLayer is set', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const maker = new RemittanceManager(
        {
          remittanceModules: [mod],
          // NO identityLayer
          options: {
            identityOptions: { makerRequestIdentity: 'beforeInvoicing' }
          },
          threadIdFactory: makeThreadIdFactory()
        },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )

      await expect(maker.sendInvoice('taker-key', makeInvoiceInput())).rejects.toThrow(
        'Identity layer is required by runtime options but is not configured'
      )
    })
  })

  describe('constructor with initial threads', () => {
    it('accepts pre-hydrated threads and restores their state', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const manager1 = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        new TestComms('k1', bus)
      )
      await manager1.sendInvoice('k2', makeInvoiceInput())
      const { threads } = manager1.saveState()

      const manager2 = new RemittanceManager(
        { remittanceModules: [mod], threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        new TestComms('k1', bus),
        threads
      )
      expect(manager2.threads).toHaveLength(1)
      expect(manager2.threads[0].state).toBe('invoiced')
    })
  })

  describe('custom messageBox', () => {
    it('uses the configured messageBox for sending and listing', async () => {
      const bus = new MessageBus()
      const mod = makeModule()

      const customBox = 'custom_inbox'
      const sendMessage = jest.fn(async (args: any, _hostOverride?: string) => {
        bus.send('k1', args.recipient, args.messageBox, args.body)
        return 'mid-custom'
      })
      const listMessages = jest.fn(async () => [])
      const acknowledgeMessage = jest.fn(async () => undefined)
      const comms: CommsLayer = { sendMessage, listMessages, acknowledgeMessage }

      const manager = new RemittanceManager(
        { remittanceModules: [mod], messageBox: customBox, threadIdFactory: makeThreadIdFactory() },
        makeWallet('k1'),
        comms
      )

      await manager.sendInvoice('k2', makeInvoiceInput())
      expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({ messageBox: customBox }), undefined)
    })
  })

  describe('identity verification response – assessReceivedCertificateSufficiency rejects', () => {
    it('sends termination when certificate assessment fails', async () => {
      const bus = new MessageBus()
      const mod = makeModule({ createOption: async () => ({}) })

      const rejectingIdentityLayer: IdentityLayer = {
        ...makeIdentityLayer(),
        assessReceivedCertificateSufficiency: async () => ({
          code: 'cert.insufficient',
          message: 'Certs not sufficient',
          details: {}
        } as any)
      }

      const maker = new RemittanceManager(
        {
          remittanceModules: [mod],
          identityLayer: rejectingIdentityLayer,
          options: {
            identityOptions: { makerRequestIdentity: 'beforeInvoicing' },
            identityTimeoutMs: 200,
            identityPollIntervalMs: 5
          },
          threadIdFactory: makeThreadIdFactory()
        },
        makeWallet('maker-key'),
        new TestComms('maker-key', bus)
      )
      const taker = new RemittanceManager(
        {
          remittanceModules: [mod],
          identityLayer: makeIdentityLayer(),
          options: { identityOptions: { makerRequestIdentity: 'beforeInvoicing' }, identityTimeoutMs: 200, identityPollIntervalMs: 5 },
          threadIdFactory: makeThreadIdFactory()
        },
        makeWallet('taker-key'),
        new TestComms('taker-key', bus)
      )

      const sendPromise = maker.sendInvoice('taker-key', makeInvoiceInput())
      await tick()

      // Taker responds to identity request
      await taker.syncThreads()

      // Maker receives response and rejects via assessReceivedCertificateSufficiency
      await maker.syncThreads()

      // The taker should receive a termination
      const takerMsgs = bus.list('taker-key', DEFAULT_REMITTANCE_MESSAGEBOX)
      const termMsg = takerMsgs.find(m => {
        const env = JSON.parse(m.body) as RemittanceEnvelope
        return env.kind === 'termination'
      })
      expect(termMsg).toBeDefined()

      // sendInvoice should timeout because identity was rejected
      await expect(sendPromise).rejects.toThrow()
    })
  })
})
