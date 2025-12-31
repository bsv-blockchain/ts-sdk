import type { Invoice, ModuleContext } from '../types.js'
import type { WalletInterface } from '../../wallet/Wallet.interfaces.js'
import { Brc29RemittanceModule } from '../modules/BasicBRC29.js'

const makeInvoice = (overrides: Partial<Invoice> = {}): Invoice => ({
  kind: 'invoice',
  threadId: 'thread-1',
  payee: 'payee-key',
  payer: 'payer-key',
  createdAt: 1000,
  invoiceNumber: 'INV-1',
  lineItems: [],
  total: { value: '1000', unit: { namespace: 'bsv', code: 'sat', decimals: 0 } },
  options: {},
  ...overrides
})

const makeContext = (wallet: WalletInterface): ModuleContext => ({
  wallet,
  originator: 'example.com',
  now: () => 123
})

describe('Brc29RemittanceModule', () => {
  it('creates option terms from satoshi invoice totals', async () => {
    const module = new Brc29RemittanceModule()
    const invoice = makeInvoice()
    const option = await module.createOption({ threadId: 'thread-1', invoice }, makeContext({} as WalletInterface))
    expect(option.amountSatoshis).toBe(1000)
    expect(option.outputIndex).toBe(0)
  })

  it('rejects non-satoshi invoice totals', async () => {
    const module = new Brc29RemittanceModule()
    const invoice = makeInvoice({
      total: { value: '12.50', unit: { namespace: 'iso4217', code: 'USD', decimals: 2 } }
    })
    await expect(module.createOption({ threadId: 'thread-1', invoice }, makeContext({} as WalletInterface))).rejects.toThrow(
      'BRC-29 module requires invoice.total to be denominated in bsv:sat'
    )
  })

  it('builds a settlement artifact from wallet outputs', async () => {
    const wallet = {
      getPublicKey: jest.fn(async () => ({ publicKey: '02deadbeef' })),
      createAction: jest.fn(async () => ({ tx: [1, 2, 3] }))
    } as unknown as WalletInterface

    const module = new Brc29RemittanceModule({
      protocolID: [2, 'test-protocol'],
      labels: ['label-1'],
      description: 'Test payment',
      outputDescription: 'Test output',
      nonceProvider: {
        createNonce: jest.fn()
          .mockResolvedValueOnce('prefix')
          .mockResolvedValueOnce('suffix')
      },
      lockingScriptProvider: {
        pubKeyToP2PKHLockingScript: jest.fn(async () => '76a914deadbeef88ac')
      }
    })

    const invoice = makeInvoice()
    const option = { amountSatoshis: 1000 }
    const result = await module.buildSettlement({ threadId: 'thread-1', invoice, option, note: 'note' }, makeContext(wallet))
    expect(result.action).toBe('settle')
    if (result.action !== 'settle') return

    expect(result.artifact.customInstructions).toEqual({ derivationPrefix: 'prefix', derivationSuffix: 'suffix' })
    expect(result.artifact.amountSatoshis).toBe(1000)
    expect(result.artifact.outputIndex).toBe(0)
    expect(result.artifact.transaction).toEqual([1, 2, 3])

    expect(wallet.getPublicKey).toHaveBeenCalledWith(
      {
        protocolID: [2, 'test-protocol'],
        keyID: 'prefix suffix',
        counterparty: invoice.payee
      },
      'example.com'
    )

    const createArgs = (wallet.createAction as jest.Mock).mock.calls[0][0]
    const customInstructions = JSON.parse(createArgs.outputs[0].customInstructions as string)
    expect(customInstructions).toEqual({
      derivationPrefix: 'prefix',
      derivationSuffix: 'suffix',
      payee: invoice.payee,
      threadId: 'thread-1',
      note: 'note'
    })
    expect(createArgs.outputs[0].outputDescription).toBe('Test output')
  })

  it('terminates settlement creation on invalid amounts', async () => {
    const wallet = {
      getPublicKey: jest.fn(async () => ({ publicKey: '02deadbeef' })),
      createAction: jest.fn(async () => ({ tx: [1, 2, 3] }))
    } as unknown as WalletInterface

    const module = new Brc29RemittanceModule()
    const invoice = makeInvoice()
    const option = { amountSatoshis: 0 }
    const result = await module.buildSettlement({ threadId: 'thread-1', invoice, option }, makeContext(wallet))
    expect(result.action).toBe('terminate')
  })

  it('terminates settlement creation when option data is invalid', async () => {
    const wallet = {
      getPublicKey: jest.fn(async () => ({ publicKey: '02deadbeef' })),
      createAction: jest.fn(async () => ({ tx: [1, 2, 3] }))
    } as unknown as WalletInterface

    const module = new Brc29RemittanceModule()
    const invoice = makeInvoice()
    const option = { amountSatoshis: -5, outputIndex: -1 }
    const result = await module.buildSettlement({ threadId: 'thread-1', invoice, option }, makeContext(wallet))
    expect(result.action).toBe('terminate')
    if (result.action === 'terminate') {
      expect(result.termination.code).toBe('brc29.invalid_option')
    }
  })

  it('terminates settlement creation when wallet output is missing', async () => {
    const wallet = {
      getPublicKey: jest.fn(async () => ({ publicKey: '02deadbeef' })),
      createAction: jest.fn(async () => ({}))
    } as unknown as WalletInterface

    const module = new Brc29RemittanceModule({
      nonceProvider: {
        createNonce: jest.fn()
          .mockResolvedValueOnce('prefix')
          .mockResolvedValueOnce('suffix')
      },
      lockingScriptProvider: {
        pubKeyToP2PKHLockingScript: jest.fn(async () => '76a914deadbeef88ac')
      }
    })
    const invoice = makeInvoice()
    const option = { amountSatoshis: 1000 }
    const result = await module.buildSettlement({ threadId: 'thread-1', invoice, option }, makeContext(wallet))
    expect(result.action).toBe('terminate')
    if (result.action === 'terminate') {
      expect(result.termination.code).toBe('brc29.missing_tx')
    }
  })

  it('terminates settlement creation when the invoice amount mismatches', async () => {
    const wallet = {
      getPublicKey: jest.fn(async () => ({ publicKey: '02deadbeef' })),
      createAction: jest.fn(async () => ({ tx: [1, 2, 3] }))
    } as unknown as WalletInterface

    const module = new Brc29RemittanceModule()
    const invoice = makeInvoice({ total: { value: '900', unit: { namespace: 'bsv', code: 'sat', decimals: 0 } } })
    const option = { amountSatoshis: 1000 }
    const result = await module.buildSettlement({ threadId: 'thread-1', invoice, option }, makeContext(wallet))
    expect(result.action).toBe('terminate')
    if (result.action === 'terminate') {
      expect(result.termination.code).toBe('brc29.amount_mismatch')
    }
  })

  it('accepts settlements by internalizing the payment', async () => {
    const wallet = {
      internalizeAction: jest.fn(async () => ({ ok: true }))
    } as unknown as WalletInterface

    const module = new Brc29RemittanceModule()
    const settlement = {
      customInstructions: { derivationPrefix: 'p', derivationSuffix: 's' },
      transaction: [9, 9, 9],
      amountSatoshis: 1000,
      outputIndex: 1
    }
    const result = await module.acceptSettlement(
      { threadId: 'thread-1', settlement, sender: 'payer-key' },
      makeContext(wallet)
    )
    expect(result.action).toBe('accept')
    if (result.action === 'accept') {
      expect(result.receiptData?.internalizeResult).toEqual({ ok: true })
    }

    expect(wallet.internalizeAction).toHaveBeenCalledWith(
      {
        tx: settlement.transaction,
        outputs: [
          {
            paymentRemittance: {
              derivationPrefix: 'p',
              derivationSuffix: 's',
              senderIdentityKey: 'payer-key'
            },
            outputIndex: 1,
            protocol: 'wallet payment'
          }
        ],
        labels: ['brc29'],
        description: 'BRC-29 payment received'
      },
      'example.com'
    )
  })

  it('terminates when internalization fails', async () => {
    const wallet = {
      internalizeAction: jest.fn(async () => {
        throw new Error('fail')
      })
    } as unknown as WalletInterface

    const module = new Brc29RemittanceModule()
    const settlement = {
      customInstructions: { derivationPrefix: 'p', derivationSuffix: 's' },
      transaction: [9, 9, 9],
      amountSatoshis: 1000
    }
    const result = await module.acceptSettlement(
      { threadId: 'thread-1', settlement, sender: 'payer-key' },
      makeContext(wallet)
    )
    expect(result.action).toBe('terminate')
    if (result.action === 'terminate') {
      expect(result.termination.code).toBe('brc29.internalize_failed')
    }
  })

  it('terminates when settlement data is malformed', async () => {
    const wallet = {
      internalizeAction: jest.fn(async () => ({ ok: true }))
    } as unknown as WalletInterface

    const module = new Brc29RemittanceModule()
    const settlement = {
      customInstructions: { derivationPrefix: '', derivationSuffix: '' },
      transaction: [],
      amountSatoshis: 1000
    }
    const result = await module.acceptSettlement(
      { threadId: 'thread-1', settlement, sender: 'payer-key' },
      makeContext(wallet)
    )
    expect(result.action).toBe('terminate')
    if (result.action === 'terminate') {
      expect(result.termination.code).toBe('brc29.internalize_failed')
    }
  })

  it('internalizes refunds embedded in receipt data', async () => {
    const wallet = {
      internalizeAction: jest.fn(async () => ({ ok: true }))
    } as unknown as WalletInterface

    const module = new Brc29RemittanceModule()
    await module.processReceipt(
      {
        threadId: 'thread-1',
        receiptData: {
          refund: {
            token: {
              customInstructions: { derivationPrefix: 'p', derivationSuffix: 's' },
              transaction: [4, 5, 6],
              amountSatoshis: 500,
              outputIndex: 0
            },
            feeSatoshis: 100
          }
        },
        sender: 'payee-key'
      },
      makeContext(wallet)
    )

    expect(wallet.internalizeAction).toHaveBeenCalled()
  })

  it('rejects with a reason when refund settlement data is invalid', async () => {
    const wallet = {
      internalizeAction: jest.fn(async () => ({ ok: true }))
    } as unknown as WalletInterface

    const module = new Brc29RemittanceModule()
    const receiptData = await module.rejectSettlement(
      {
        threadId: 'thread-1',
        settlement: {
          customInstructions: { derivationPrefix: '', derivationSuffix: '' },
          transaction: [],
          amountSatoshis: 1000
        },
        sender: 'payer-key'
      },
      makeContext(wallet)
    )
    expect(receiptData.rejectedReason).toContain('invalid settlement')
  })
})
