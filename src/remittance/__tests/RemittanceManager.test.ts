import type { CommsLayer } from '../CommsLayer.js'
import type { IdentityLayer } from '../IdentityLayer.js'
import type { RemittanceModule } from '../RemittanceModule.js'
import type { ComposeInvoiceInput } from '../RemittanceManager.js'
import type { PeerMessage, RemittanceEnvelope, Termination, ThreadId } from '../types.js'
import type { WalletInterface, PubKeyHex } from '../../wallet/Wallet.interfaces.js'
import { RemittanceManager } from '../RemittanceManager.js'

type StoredMessage = PeerMessage

class MessageBus {
  private messages: StoredMessage[] = []
  private nextId = 1

  send (sender: PubKeyHex, recipient: PubKeyHex, messageBox: string, body: string): string {
    const messageId = `msg-${this.nextId++}`
    this.messages.push({
      messageId,
      sender,
      recipient,
      messageBox,
      body
    })
    return messageId
  }

  list (recipient: PubKeyHex, messageBox: string): StoredMessage[] {
    return this.messages.filter((msg) => msg.recipient === recipient && msg.messageBox === messageBox)
  }

  ack (recipient: PubKeyHex, messageIds: string[]): void {
    this.messages = this.messages.filter(
      (msg) => msg.recipient !== recipient || !messageIds.includes(msg.messageId)
    )
  }
}

class TestComms implements CommsLayer {
  constructor (private readonly owner: PubKeyHex, private readonly bus: MessageBus) {}

  async sendMessage (args: { recipient: PubKeyHex; messageBox: string; body: string }): Promise<string> {
    return this.bus.send(this.owner, args.recipient, args.messageBox, args.body)
  }

  async listMessages (args: { messageBox: string }): Promise<PeerMessage[]> {
    return this.bus.list(this.owner, args.messageBox)
  }

  async acknowledgeMessage (args: { messageIds: string[] }): Promise<void> {
    this.bus.ack(this.owner, args.messageIds)
  }
}

const makeWallet = (identityKey: PubKeyHex): WalletInterface => ({
  getPublicKey: async () => ({ publicKey: identityKey })
} as unknown as WalletInterface)

const makeInvoiceInput = (overrides: Partial<ComposeInvoiceInput> = {}): ComposeInvoiceInput => ({
  lineItems: [],
  total: { value: '1000', unit: { namespace: 'bsv', code: 'sat', decimals: 0 } },
  note: 'Test invoice',
  invoiceNumber: 'INV-1',
  ...overrides
})

const parseEnvelope = (msg: StoredMessage): RemittanceEnvelope => JSON.parse(msg.body) as RemittanceEnvelope

const makeIdentityLayer = (): IdentityLayer => ({
  determineCertificatesToRequest: async ({ threadId }) => ({
    kind: 'identityVerificationRequest',
    threadId,
    request: {
      types: { basic: ['name'] },
      certifiers: ['certifier-key']
    }
  }),
  respondToRequest: async ({ threadId }) => ({
    action: 'respond',
    response: {
      kind: 'identityVerificationResponse',
      threadId,
      certificates: [
        {
          type: 'YmFzaWM=',
          certifier: 'certifier-key',
          subject: 'subject-key',
          fields: { name: 'QWxpY2U=' },
          signature: 'deadbeef',
          serialNumber: 'c2VyaWFs',
          revocationOutpoint: 'outpoint',
          keyringForVerifier: { name: 'a2V5' }
        }
      ]
    }
  }),
  assessReceivedCertificateSufficiency: async (_counterparty, _received, threadId) => ({
    kind: 'identityVerificationAcknowledgment',
    threadId
  })
})

const makeThreadIdFactory = (): (() => ThreadId) => {
  let i = 0
  return () => `thread-${++i}` as ThreadId
}

const tick = async (): Promise<void> => await new Promise((resolve) => setTimeout(resolve, 0))

const waitForKind = async (
  bus: MessageBus,
  recipient: PubKeyHex,
  kind: RemittanceEnvelope['kind'],
  timeoutMs = 2000
): Promise<void> => {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const found = bus.list(recipient, 'remittance_inbox').some((msg) => parseEnvelope(msg).kind === kind)
    if (found) return
    await tick()
  }
  throw new Error(`Timed out waiting for ${kind}`)
}

describe('RemittanceManager base flows', () => {
  it('processes an invoice, settlement, and receipt end-to-end', async () => {
    const bus = new MessageBus()
    const moduleProcessReceipt = jest.fn()
    const module: RemittanceModule<{ amountSatoshis: number }, { amountSatoshis: number }, { accepted: true }> = {
      id: 'basic-module',
      name: 'Basic Module',
      allowUnsolicitedSettlements: false,
      createOption: async ({ invoice }) => ({ amountSatoshis: Number(invoice.total.value) }),
      buildSettlement: async ({ option }) => ({ action: 'settle', artifact: option }),
      acceptSettlement: async ({ settlement }) => ({ action: 'accept', receiptData: { accepted: true } }),
      processReceipt: moduleProcessReceipt
    }

    const maker = new RemittanceManager(
      { remittanceModules: [module], options: { receiptProvided: true, autoIssueReceipt: true }, threadIdFactory: makeThreadIdFactory() },
      makeWallet('maker-key'),
      new TestComms('maker-key', bus)
    )
    const taker = new RemittanceManager(
      { remittanceModules: [module], options: { receiptProvided: true }, threadIdFactory: makeThreadIdFactory() },
      makeWallet('taker-key'),
      new TestComms('taker-key', bus)
    )

    const invoiceHandle = await maker.sendInvoice('taker-key', makeInvoiceInput())
    await taker.syncThreads()

    const payPromise = taker.pay(invoiceHandle.threadId, module.id)
    await waitForKind(bus, 'maker-key', 'settlement')
    await maker.syncThreads()
    const receipt = await payPromise

    const receiptKind = receipt != null && 'kind' in receipt ? receipt.kind : undefined
    expect(receiptKind).toBe('receipt')
    expect(taker.getThreadOrThrow(invoiceHandle.threadId).receipt).toBeDefined()
    expect(maker.getThreadOrThrow(invoiceHandle.threadId).receipt).toBeDefined()
    expect(moduleProcessReceipt).toHaveBeenCalled()
  })

  it('accepts unsolicited settlements when the module allows it', async () => {
    const bus = new MessageBus()
    const module: RemittanceModule<{ note: string }, { note: string }, { ok: true }> = {
      id: 'unsolicited-module',
      name: 'Unsolicited Module',
      allowUnsolicitedSettlements: true,
      buildSettlement: async ({ option }) => ({ action: 'settle', artifact: option }),
      acceptSettlement: async () => ({ action: 'accept', receiptData: { ok: true } })
    }

    const maker = new RemittanceManager(
      { remittanceModules: [module], options: { receiptProvided: true, autoIssueReceipt: true }, threadIdFactory: makeThreadIdFactory() },
      makeWallet('maker-key'),
      new TestComms('maker-key', bus)
    )
    const taker = new RemittanceManager(
      { remittanceModules: [module], options: { receiptProvided: true }, threadIdFactory: makeThreadIdFactory() },
      makeWallet('taker-key'),
      new TestComms('taker-key', bus)
    )

    const threadHandle = await taker.sendUnsolicitedSettlement('maker-key', { moduleId: module.id, option: { note: 'hello' } })
    await maker.syncThreads()
    await taker.syncThreads()

    const makerThread = maker.getThreadOrThrow(threadHandle.threadId)
    expect(makerThread.invoice).toBeUndefined()
    expect(makerThread.settlement).toBeDefined()
    expect(taker.getThreadOrThrow(threadHandle.threadId).settlement).toBeDefined()
  })

  it('waits for identity verification before invoicing when required', async () => {
    const bus = new MessageBus()
    const identityLayer = makeIdentityLayer()
    const module: RemittanceModule<{}, {}, {}> = {
      id: 'identity-module',
      name: 'Identity Module',
      allowUnsolicitedSettlements: false,
      createOption: async () => ({}),
      buildSettlement: async () => ({ action: 'settle', artifact: {} }),
      acceptSettlement: async () => ({ action: 'accept', receiptData: {} })
    }

    const maker = new RemittanceManager(
      {
        remittanceModules: [module],
        identityLayer,
        options: {
          identityOptions: { makerRequestIdentity: 'beforeInvoicing', takerRequestIdentity: 'never' },
          identityTimeoutMs: 2000,
          identityPollIntervalMs: 5
        },
        threadIdFactory: makeThreadIdFactory()
      },
      makeWallet('maker-key'),
      new TestComms('maker-key', bus)
    )
    const taker = new RemittanceManager(
      {
        remittanceModules: [module],
        identityLayer,
        options: {
          identityOptions: { makerRequestIdentity: 'beforeInvoicing', takerRequestIdentity: 'never' },
          identityTimeoutMs: 2000,
          identityPollIntervalMs: 5
        },
        threadIdFactory: makeThreadIdFactory()
      },
      makeWallet('taker-key'),
      new TestComms('taker-key', bus)
    )

    const sendPromise = maker.sendInvoice('taker-key', makeInvoiceInput())
    await tick()
    const preIdentity = bus.list('taker-key', 'remittance_inbox')
    expect(preIdentity).toHaveLength(1)
    expect(parseEnvelope(preIdentity[0]).kind).toBe('identityVerificationRequest')

    await taker.syncThreads()
    const invoiceHandle = await sendPromise
    const postIdentity = bus.list('taker-key', 'remittance_inbox')
    const kinds = postIdentity.map((msg) => parseEnvelope(msg).kind)
    expect(kinds).toContain('invoice')
    expect(kinds).toContain('identityVerificationAcknowledgment')

    await taker.syncThreads()
    const takerThread = taker.getThreadOrThrow(invoiceHandle.threadId)
    expect(takerThread.flags.hasIdentified).toBe(true)
  })

  it('waits for identity verification before settlement when required', async () => {
    const bus = new MessageBus()
    const identityLayer = makeIdentityLayer()
    const module: RemittanceModule<{ amount: number }, { amount: number }, {}> = {
      id: 'settlement-module',
      name: 'Settlement Module',
      allowUnsolicitedSettlements: false,
      createOption: async () => ({ amount: 1 }),
      buildSettlement: async ({ option }) => ({ action: 'settle', artifact: option }),
      acceptSettlement: async () => ({ action: 'accept', receiptData: {} })
    }

    const maker = new RemittanceManager(
      { remittanceModules: [module], identityLayer, threadIdFactory: makeThreadIdFactory() },
      makeWallet('maker-key'),
      new TestComms('maker-key', bus)
    )
    const taker = new RemittanceManager(
      {
        remittanceModules: [module],
        identityLayer,
        options: {
          identityOptions: { makerRequestIdentity: 'never', takerRequestIdentity: 'beforeSettlement' },
          receiptProvided: false,
          identityTimeoutMs: 2000,
          identityPollIntervalMs: 5
        },
        threadIdFactory: makeThreadIdFactory()
      },
      makeWallet('taker-key'),
      new TestComms('taker-key', bus)
    )

    const invoiceHandle = await maker.sendInvoice('taker-key', makeInvoiceInput())
    await taker.syncThreads()

    const payPromise = taker.pay(invoiceHandle.threadId, module.id)
    await tick()
    const preSettlement = bus.list('maker-key', 'remittance_inbox')
    expect(preSettlement).toHaveLength(1)
    expect(parseEnvelope(preSettlement[0]).kind).toBe('identityVerificationRequest')

    await maker.syncThreads()
    await payPromise
    const postSettlement = bus.list('maker-key', 'remittance_inbox')
    const kinds = postSettlement.map((msg) => parseEnvelope(msg).kind)
    expect(kinds).toContain('settlement')
  })

  it('sends termination when a module refuses to build a settlement', async () => {
    const bus = new MessageBus()
    const termination: Termination = { code: 'rejected', message: 'No thanks' }
    const module: RemittanceModule<{}, {}, {}> = {
      id: 'terminator',
      name: 'Terminator',
      allowUnsolicitedSettlements: false,
      createOption: async () => ({}),
      buildSettlement: async () => ({ action: 'terminate', termination }),
      acceptSettlement: async () => ({ action: 'accept', receiptData: {} })
    }

    const maker = new RemittanceManager(
      { remittanceModules: [module], threadIdFactory: makeThreadIdFactory() },
      makeWallet('maker-key'),
      new TestComms('maker-key', bus)
    )
    const taker = new RemittanceManager(
      { remittanceModules: [module], options: { receiptProvided: false }, threadIdFactory: makeThreadIdFactory() },
      makeWallet('taker-key'),
      new TestComms('taker-key', bus)
    )

    const invoiceHandle = await maker.sendInvoice('taker-key', makeInvoiceInput())
    await taker.syncThreads()

    const result = await taker.pay(invoiceHandle.threadId, module.id)
    expect(result).toEqual(termination)

    const messages = bus.list('maker-key', 'remittance_inbox')
    expect(messages).toHaveLength(1)
    expect(parseEnvelope(messages[0]).kind).toBe('termination')
  })

  it('records state transitions and emits events', async () => {
    const bus = new MessageBus()
    const module: RemittanceModule<{}, {}, {}> = {
      id: 'event-module',
      name: 'Event Module',
      allowUnsolicitedSettlements: false,
      createOption: async () => ({}),
      buildSettlement: async () => ({ action: 'settle', artifact: {} }),
      acceptSettlement: async () => ({ action: 'accept', receiptData: {} })
    }

    const events: string[] = []
    const maker = new RemittanceManager(
      {
        remittanceModules: [module],
        events: {
          onThreadCreated: () => events.push('threadCreated'),
          onStateChanged: (event) => events.push(`state:${event.next}`),
          onInvoiceSent: () => events.push('invoiceSent')
        },
        threadIdFactory: makeThreadIdFactory()
      },
      makeWallet('maker-key'),
      new TestComms('maker-key', bus)
    )

    const handle = await maker.sendInvoice('taker-key', makeInvoiceInput())
    const thread = maker.getThreadOrThrow(handle.threadId)
    expect(thread.stateLog.length).toBeGreaterThan(0)
    expect(thread.state).toBe('invoiced')
    expect(events).toContain('threadCreated')
    expect(events).toContain('state:invoiced')
    expect(events).toContain('invoiceSent')
  })

  it('allows waiting for thread state transitions via handles', async () => {
    const bus = new MessageBus()
    const module: RemittanceModule<{}, {}, {}> = {
      id: 'wait-module',
      name: 'Wait Module',
      allowUnsolicitedSettlements: false,
      createOption: async () => ({}),
      buildSettlement: async () => ({ action: 'settle', artifact: {} }),
      acceptSettlement: async () => ({ action: 'accept', receiptData: {} })
    }

    const maker = new RemittanceManager(
      { remittanceModules: [module], threadIdFactory: makeThreadIdFactory() },
      makeWallet('maker-key'),
      new TestComms('maker-key', bus)
    )

    const handle = await maker.sendInvoice('taker-key', makeInvoiceInput())
    const awaited = await handle.waitForState('invoiced', { timeoutMs: 50, pollIntervalMs: 5 })
    expect(awaited.threadId).toBe(handle.threadId)
  })

  it('marks a thread as errored on invalid state transition', async () => {
    const bus = new MessageBus()
    const module: RemittanceModule<{}, {}, {}> = {
      id: 'error-module',
      name: 'Error Module',
      allowUnsolicitedSettlements: false,
      createOption: async () => ({}),
      buildSettlement: async () => ({ action: 'settle', artifact: {} }),
      acceptSettlement: async () => ({ action: 'accept', receiptData: {} })
    }

    const maker = new RemittanceManager(
      { remittanceModules: [module], threadIdFactory: makeThreadIdFactory() },
      makeWallet('maker-key'),
      new TestComms('maker-key', bus)
    )

    const receiptEnv: RemittanceEnvelope = {
      v: 1,
      id: 'env-1' as ThreadId,
      kind: 'receipt',
      threadId: 'thread-1' as ThreadId,
      createdAt: 1,
      payload: {
        kind: 'receipt',
        threadId: 'thread-1',
        moduleId: 'error-module',
        optionId: 'error-module',
        payee: 'maker-key',
        payer: 'taker-key',
        createdAt: 1,
        receiptData: {}
      }
    }
    bus.send('taker-key', 'maker-key', 'remittance_inbox', JSON.stringify(receiptEnv))
    await maker.syncThreads()

    const thread = maker.getThreadOrThrow('thread-1' as ThreadId)
    expect(thread.state).toBe('errored')
    expect(thread.flags.error).toBe(true)
  })

  it('processes live messages when CommsLayer supports streaming', async () => {
    const module: RemittanceModule<{}, {}, {}> = {
      id: 'live-module',
      name: 'Live Module',
      allowUnsolicitedSettlements: false,
      createOption: async () => ({}),
      buildSettlement: async () => ({ action: 'settle', artifact: {} }),
      acceptSettlement: async () => ({ action: 'accept', receiptData: {} })
    }

    const invoiceEnv: RemittanceEnvelope = {
      v: 1,
      id: 'env-live',
      kind: 'invoice',
      threadId: 'thread-live',
      createdAt: 1,
      payload: {
        kind: 'invoice',
        threadId: 'thread-live',
        payee: 'maker-key',
        payer: 'taker-key',
        lineItems: [],
        total: { value: '1000', unit: { namespace: 'bsv', code: 'sat', decimals: 0 } },
        invoiceNumber: 'INV-LIVE',
        createdAt: 1,
        options: {}
      }
    }

    const acknowledgeMessage = jest.fn(async () => undefined)
    const comms: CommsLayer = {
      sendMessage: async () => 'noop',
      listMessages: async () => [],
      acknowledgeMessage,
      listenForLiveMessages: async ({ onMessage }) => {
        await onMessage({
          messageId: 'live-1',
          sender: 'maker-key',
          recipient: 'taker-key',
          messageBox: 'remittance_inbox',
          body: JSON.stringify(invoiceEnv)
        })
      }
    }

    const taker = new RemittanceManager(
      { remittanceModules: [module], threadIdFactory: makeThreadIdFactory() },
      makeWallet('taker-key'),
      comms
    )

    await taker.startListening()
    expect(acknowledgeMessage).toHaveBeenCalledWith({ messageIds: ['live-1'] })
    const thread = taker.getThreadOrThrow('thread-live' as ThreadId)
    expect(thread.invoice).toBeDefined()
    expect(thread.state).toBe('invoiced')
  })
})
