import type { ModuleContext } from '../types.js'
import type { WalletInterface } from '../../wallet/Wallet.interfaces.js'
import { Brc29RemittanceModule } from '../modules/BasicBRC29.js'

const makeContext = (wallet: WalletInterface): ModuleContext => ({
  wallet,
  originator: 'example.com',
  now: () => 123
})

describe('Brc29RemittanceModule', () => {
  describe('unsolicited settlements (no invoice)', () => {
    it('builds a settlement artifact for unsolicited payment', async () => {
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

      const option = { amountSatoshis: 1000, payee: 'payee-key' }
      const result = await module.buildSettlement({ threadId: 'thread-1', option, note: 'unsolicited payment' }, makeContext(wallet))
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
          counterparty: option.payee
        },
        'example.com'
      )

      const createArgs = (wallet.createAction as jest.Mock).mock.calls[0][0]
      const customInstructions = JSON.parse(createArgs.outputs[0].customInstructions as string)
      expect(customInstructions).toEqual({
        derivationPrefix: 'prefix',
        derivationSuffix: 'suffix',
        payee: option.payee,
        threadId: 'thread-1',
        note: 'unsolicited payment'
      })
      expect(createArgs.outputs[0].outputDescription).toBe('Test output')
    })

    it('terminates on invalid amounts for unsolicited settlements', async () => {
      const wallet = {
        getPublicKey: jest.fn(async () => ({ publicKey: '02deadbeef' })),
        createAction: jest.fn(async () => ({ tx: [1, 2, 3] }))
      } as unknown as WalletInterface

      const module = new Brc29RemittanceModule()
      const option = { amountSatoshis: 0, payee: 'payee-key' }
      const result = await module.buildSettlement({ threadId: 'thread-1', option }, makeContext(wallet))
      expect(result.action).toBe('terminate')
    })

    it('terminates on invalid option data for unsolicited settlements', async () => {
      const wallet = {
        getPublicKey: jest.fn(async () => ({ publicKey: '02deadbeef' })),
        createAction: jest.fn(async () => ({ tx: [1, 2, 3] }))
      } as unknown as WalletInterface

      const module = new Brc29RemittanceModule()
      const option = { amountSatoshis: -5, payee: 'payee-key', outputIndex: -1 }
      const result = await module.buildSettlement({ threadId: 'thread-1', option }, makeContext(wallet))
      expect(result.action).toBe('terminate')
      if (result.action === 'terminate') {
        expect(result.termination.code).toBe('brc29.invalid_option')
      }
    })
  })

  describe('settlement building edge cases', () => {
    it('terminates when wallet fails to create transaction', async () => {
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
      const option = { amountSatoshis: 1000, payee: 'payee-key' }
      const result = await module.buildSettlement({ threadId: 'thread-1', option }, makeContext(wallet))
      expect(result.action).toBe('terminate')
      if (result.action === 'terminate') {
        expect(result.termination.code).toBe('brc29.missing_tx')
      }
    })
  })

  describe('settlement acceptance', () => {
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
  })
})
