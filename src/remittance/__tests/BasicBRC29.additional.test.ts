import type { ModuleContext } from '../types.js'
import type { WalletInterface } from '../../wallet/Wallet.interfaces.js'
import {
  Brc29RemittanceModule,
  DefaultNonceProvider,
  DefaultLockingScriptProvider
} from '../modules/BasicBRC29.js'

const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation(() => { })

const makeContext = (wallet: WalletInterface): ModuleContext => ({
  wallet,
  originator: 'example.com',
  now: () => 123
})

const makeWallet = (overrides: Partial<WalletInterface> = {}): WalletInterface => ({
  getPublicKey: jest.fn(async () => ({ publicKey: '02deadbeef' })),
  createAction: jest.fn(async () => ({ tx: [1, 2, 3] })),
  internalizeAction: jest.fn(async () => ({ ok: true })),
  ...overrides
} as unknown as WalletInterface)

const validSettlement = {
  customInstructions: { derivationPrefix: 'prefix', derivationSuffix: 'suffix' },
  transaction: [1, 2, 3],
  amountSatoshis: 1000
}

// ---------------------------------------------------------------------------
// buildSettlement – option validation edge cases
// ---------------------------------------------------------------------------

describe('Brc29RemittanceModule – buildSettlement option validation', () => {
  it('terminates when option is null', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.buildSettlement(
      { threadId: 'tid', option: null as any },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
    if (result.action === 'terminate') {
      expect(result.termination.code).toBe('brc29.invalid_option')
    }
  })

  it('terminates when option is a non-object primitive', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.buildSettlement(
      { threadId: 'tid', option: 'not-an-object' as any },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('terminates when amountSatoshis is a float (non-integer)', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 1.5, payee: 'payee' } },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
    if (result.action === 'terminate') {
      expect(result.termination.code).toBe('brc29.invalid_option')
    }
  })

  it('terminates when outputIndex is a negative integer', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 100, payee: 'pk', outputIndex: -1 } },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('terminates when outputIndex is a float', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 100, payee: 'pk', outputIndex: 0.5 } },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('terminates when protocolID is not an array', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 100, payee: 'pk', protocolID: 'bad' as any } },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('terminates when protocolID has wrong array length', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 100, payee: 'pk', protocolID: [1] as any } },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('terminates when protocolID has negative protocol number', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 100, payee: 'pk', protocolID: [-1, 'proto'] as any } },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('terminates when protocolID string is empty', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 100, payee: 'pk', protocolID: [2, '   '] as any } },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('terminates when labels contains an empty string', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 100, payee: 'pk', labels: ['valid', ''] } },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('terminates when labels is not an array', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 100, payee: 'pk', labels: 'single-label' as any } },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('terminates when description is an empty string', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 100, payee: 'pk', description: '   ' } },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })
})

// ---------------------------------------------------------------------------
// buildSettlement – wallet-side failure paths
// ---------------------------------------------------------------------------

describe('Brc29RemittanceModule – buildSettlement wallet failures', () => {
  it('terminates when getPublicKey returns an empty publicKey string', async () => {
    const wallet = makeWallet({
      getPublicKey: jest.fn(async () => ({ publicKey: '' }))
    })
    const module = new Brc29RemittanceModule({
      nonceProvider: { createNonce: jest.fn().mockResolvedValue('nonce') },
      lockingScriptProvider: { pubKeyToP2PKHLockingScript: jest.fn(async () => '76a914abcd88ac') }
    })

    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 1000, payee: 'pk' } },
      makeContext(wallet)
    )
    expect(result.action).toBe('terminate')
    if (result.action === 'terminate') {
      expect(result.termination.code).toBe('brc29.public_key_missing')
    }
  })

  it('terminates when getPublicKey returns a whitespace-only publicKey', async () => {
    const wallet = makeWallet({
      getPublicKey: jest.fn(async () => ({ publicKey: '   ' }))
    })
    const module = new Brc29RemittanceModule({
      nonceProvider: { createNonce: jest.fn().mockResolvedValue('nonce') },
      lockingScriptProvider: { pubKeyToP2PKHLockingScript: jest.fn(async () => 'script') }
    })

    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 1000, payee: 'pk' } },
      makeContext(wallet)
    )
    expect(result.action).toBe('terminate')
    if (result.action === 'terminate') {
      expect(result.termination.code).toBe('brc29.public_key_missing')
    }
  })

  it('terminates when lockingScriptProvider returns an empty string', async () => {
    const wallet = makeWallet({
      getPublicKey: jest.fn(async () => ({ publicKey: '02deadbeef' }))
    })
    const module = new Brc29RemittanceModule({
      nonceProvider: { createNonce: jest.fn().mockResolvedValue('nonce') },
      lockingScriptProvider: { pubKeyToP2PKHLockingScript: jest.fn(async () => '') }
    })

    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 1000, payee: 'pk' } },
      makeContext(wallet)
    )
    expect(result.action).toBe('terminate')
    if (result.action === 'terminate') {
      expect(result.termination.code).toBe('brc29.locking_script_missing')
    }
  })

  it('terminates when lockingScriptProvider returns a whitespace-only string', async () => {
    const wallet = makeWallet({
      getPublicKey: jest.fn(async () => ({ publicKey: '02deadbeef' }))
    })
    const module = new Brc29RemittanceModule({
      nonceProvider: { createNonce: jest.fn().mockResolvedValue('nonce') },
      lockingScriptProvider: { pubKeyToP2PKHLockingScript: jest.fn(async () => '   ') }
    })

    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 1000, payee: 'pk' } },
      makeContext(wallet)
    )
    expect(result.action).toBe('terminate')
    if (result.action === 'terminate') {
      expect(result.termination.code).toBe('brc29.locking_script_missing')
    }
  })

  it('settles successfully when createAction returns signableTransaction.tx instead of direct tx', async () => {
    const wallet = makeWallet({
      getPublicKey: jest.fn(async () => ({ publicKey: '02deadbeef' })),
      createAction: jest.fn(async () => ({
        signableTransaction: { tx: [4, 5, 6], reference: 'cmVm' }
      }))
    })
    const module = new Brc29RemittanceModule({
      nonceProvider: {
        createNonce: jest.fn()
          .mockResolvedValueOnce('prefix')
          .mockResolvedValueOnce('suffix')
      },
      lockingScriptProvider: { pubKeyToP2PKHLockingScript: jest.fn(async () => '76a914deadbeef88ac') }
    })

    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 500, payee: 'pk' } },
      makeContext(wallet)
    )
    // signableTransaction.tx = [4, 5, 6] is a valid atomic BEEF array
    expect(result.action).toBe('settle')
    if (result.action === 'settle') {
      expect(result.artifact.transaction).toEqual([4, 5, 6])
    }
  })

  it('terminates when tx is not a valid byte array (contains non-byte values)', async () => {
    const wallet = makeWallet({
      getPublicKey: jest.fn(async () => ({ publicKey: '02deadbeef' })),
      createAction: jest.fn(async () => ({ tx: [256, 1, 2] })) // 256 is out of byte range
    })
    const module = new Brc29RemittanceModule({
      nonceProvider: {
        createNonce: jest.fn()
          .mockResolvedValueOnce('p')
          .mockResolvedValueOnce('s')
      },
      lockingScriptProvider: { pubKeyToP2PKHLockingScript: jest.fn(async () => '76a914abcd88ac') }
    })

    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 100, payee: 'pk' } },
      makeContext(wallet)
    )
    expect(result.action).toBe('terminate')
    if (result.action === 'terminate') {
      expect(result.termination.code).toBe('brc29.invalid_tx')
    }
  })

  it('terminates when tx is an empty array', async () => {
    const wallet = makeWallet({
      getPublicKey: jest.fn(async () => ({ publicKey: '02deadbeef' })),
      createAction: jest.fn(async () => ({ tx: [] })) // empty
    })
    const module = new Brc29RemittanceModule({
      nonceProvider: {
        createNonce: jest.fn()
          .mockResolvedValueOnce('p')
          .mockResolvedValueOnce('s')
      },
      lockingScriptProvider: { pubKeyToP2PKHLockingScript: jest.fn(async () => '76a914abcd88ac') }
    })

    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 100, payee: 'pk' } },
      makeContext(wallet)
    )
    expect(result.action).toBe('terminate')
    if (result.action === 'terminate') {
      expect(result.termination.code).toBe('brc29.invalid_tx')
    }
  })

  it('terminates when createAction throws an unexpected error', async () => {
    const wallet = makeWallet({
      getPublicKey: jest.fn(async () => ({ publicKey: '02deadbeef' })),
      createAction: jest.fn(async () => { throw new Error('unexpected wallet error') })
    })
    const module = new Brc29RemittanceModule({
      nonceProvider: {
        createNonce: jest.fn()
          .mockResolvedValueOnce('p')
          .mockResolvedValueOnce('s')
      },
      lockingScriptProvider: { pubKeyToP2PKHLockingScript: jest.fn(async () => '76a914abcd88ac') }
    })

    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 100, payee: 'pk' } },
      makeContext(wallet)
    )
    expect(result.action).toBe('terminate')
    if (result.action === 'terminate') {
      expect(result.termination.code).toBe('brc29.build_failed')
      expect(result.termination.message).toContain('unexpected wallet error')
    }
  })

  it('terminates when createNonce throws', async () => {
    const wallet = makeWallet()
    const module = new Brc29RemittanceModule({
      nonceProvider: {
        createNonce: jest.fn(async () => { throw new Error('nonce error') })
      },
      lockingScriptProvider: { pubKeyToP2PKHLockingScript: jest.fn(async () => 'script') }
    })

    const result = await module.buildSettlement(
      { threadId: 'tid', option: { amountSatoshis: 500, payee: 'pk' } },
      makeContext(wallet)
    )
    expect(result.action).toBe('terminate')
    if (result.action === 'terminate') {
      expect(result.termination.code).toBe('brc29.build_failed')
    }
  })

  it('uses option-level protocolID, labels, and description overrides', async () => {
    const wallet = makeWallet({
      createAction: jest.fn(async () => ({ tx: [7, 8, 9] }))
    })
    const module = new Brc29RemittanceModule({
      nonceProvider: {
        createNonce: jest.fn()
          .mockResolvedValueOnce('pref')
          .mockResolvedValueOnce('suf')
      },
      lockingScriptProvider: { pubKeyToP2PKHLockingScript: jest.fn(async () => '76a914abcd88ac') }
    })

    const result = await module.buildSettlement(
      {
        threadId: 'tid',
        option: {
          amountSatoshis: 777,
          payee: 'pk',
          protocolID: [1, 'custom-proto'],
          labels: ['my-label'],
          description: 'Custom description',
          outputIndex: 2
        }
      },
      makeContext(wallet)
    )
    expect(result.action).toBe('settle')
    if (result.action === 'settle') {
      expect(result.artifact.outputIndex).toBe(2)
      expect(result.artifact.amountSatoshis).toBe(777)
    }

    // Verify getPublicKey was called with the option's protocolID
    expect(wallet.getPublicKey).toHaveBeenCalledWith(
      expect.objectContaining({ protocolID: [1, 'custom-proto'] }),
      'example.com'
    )

    // Verify createAction was called with option's labels and description
    const createArgs = (wallet.createAction as jest.Mock).mock.calls[0][0]
    expect(createArgs.labels).toEqual(['my-label'])
    expect(createArgs.description).toBe('Custom description')
  })
})

// ---------------------------------------------------------------------------
// acceptSettlement – settlement validation edge cases
// ---------------------------------------------------------------------------

describe('Brc29RemittanceModule – acceptSettlement validation', () => {
  it('terminates when settlement is null', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.acceptSettlement(
      { threadId: 'tid', settlement: null as any, sender: 'pk' },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
    if (result.action === 'terminate') {
      expect(result.termination.code).toBe('brc29.internalize_failed')
    }
  })

  it('terminates when settlement is a non-object primitive', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.acceptSettlement(
      { threadId: 'tid', settlement: 'not-an-object' as any, sender: 'pk' },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('terminates when customInstructions is missing', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.acceptSettlement(
      {
        threadId: 'tid',
        settlement: { transaction: [1, 2, 3], amountSatoshis: 100 } as any,
        sender: 'pk'
      },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('terminates when derivationPrefix is empty', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.acceptSettlement(
      {
        threadId: 'tid',
        settlement: {
          customInstructions: { derivationPrefix: '', derivationSuffix: 'suffix' },
          transaction: [1, 2, 3],
          amountSatoshis: 100
        },
        sender: 'pk'
      },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('terminates when derivationSuffix is empty', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.acceptSettlement(
      {
        threadId: 'tid',
        settlement: {
          customInstructions: { derivationPrefix: 'prefix', derivationSuffix: '' },
          transaction: [1, 2, 3],
          amountSatoshis: 100
        },
        sender: 'pk'
      },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('terminates when amountSatoshis is zero', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.acceptSettlement(
      {
        threadId: 'tid',
        settlement: {
          customInstructions: { derivationPrefix: 'p', derivationSuffix: 's' },
          transaction: [1, 2, 3],
          amountSatoshis: 0
        },
        sender: 'pk'
      },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('terminates when amountSatoshis is negative', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.acceptSettlement(
      {
        threadId: 'tid',
        settlement: {
          customInstructions: { derivationPrefix: 'p', derivationSuffix: 's' },
          transaction: [1, 2, 3],
          amountSatoshis: -1
        },
        sender: 'pk'
      },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('terminates when outputIndex is negative', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.acceptSettlement(
      {
        threadId: 'tid',
        settlement: {
          customInstructions: { derivationPrefix: 'p', derivationSuffix: 's' },
          transaction: [1, 2, 3],
          amountSatoshis: 1000,
          outputIndex: -2
        },
        sender: 'pk'
      },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('terminates when transaction is not a byte array (invalid bytes)', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.acceptSettlement(
      {
        threadId: 'tid',
        settlement: {
          customInstructions: { derivationPrefix: 'p', derivationSuffix: 's' },
          transaction: [256, 0, 1], // 256 is out of range
          amountSatoshis: 1000
        },
        sender: 'pk'
      },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('terminates when transaction is an empty array', async () => {
    const module = new Brc29RemittanceModule()
    const result = await module.acceptSettlement(
      {
        threadId: 'tid',
        settlement: {
          customInstructions: { derivationPrefix: 'p', derivationSuffix: 's' },
          transaction: [],
          amountSatoshis: 1000
        },
        sender: 'pk'
      },
      makeContext(makeWallet())
    )
    expect(result.action).toBe('terminate')
  })

  it('uses outputIndex=0 by default when outputIndex is undefined', async () => {
    const internalizeAction = jest.fn(async () => ({ accepted: true as const }))
    const wallet = makeWallet({ internalizeAction })
    const module = new Brc29RemittanceModule()

    const result = await module.acceptSettlement(
      { threadId: 'tid', settlement: { ...validSettlement }, sender: 'sender-key' },
      makeContext(wallet)
    )
    expect(result.action).toBe('accept')
    expect(internalizeAction).toHaveBeenCalledWith(
      expect.objectContaining({
        outputs: [expect.objectContaining({ outputIndex: 0 })]
      }),
      'example.com'
    )
  })

  it('uses basket insertion internalizeProtocol when configured', async () => {
    const internalizeAction = jest.fn(async () => ({ accepted: true as const }))
    const wallet = makeWallet({ internalizeAction })
    const module = new Brc29RemittanceModule({ internalizeProtocol: 'basket insertion' })

    const result = await module.acceptSettlement(
      { threadId: 'tid', settlement: { ...validSettlement }, sender: 'sender-key' },
      makeContext(wallet)
    )
    expect(result.action).toBe('accept')
    expect(internalizeAction).toHaveBeenCalledWith(
      expect.objectContaining({
        outputs: [expect.objectContaining({ protocol: 'basket insertion' })]
      }),
      'example.com'
    )
  })
})

// ---------------------------------------------------------------------------
// Constructor defaults
// ---------------------------------------------------------------------------

describe('Brc29RemittanceModule – constructor defaults', () => {
  it('has expected default property values', () => {
    const module = new Brc29RemittanceModule()
    expect(module.id).toBe('brc29.p2pkh')
    expect(module.name).toBe('BSV (BRC-29 derived P2PKH)')
    expect(module.allowUnsolicitedSettlements).toBe(true)
    expect((module as any).protocolID).toEqual([2, '3241645161d8'])
    expect((module as any).labels).toEqual(['brc29'])
    expect((module as any).description).toBe('BRC-29 payment')
    expect((module as any).outputDescription).toBe('Payment for remittance invoice')
    expect((module as any).refundFeeSatoshis).toBe(1000)
    expect((module as any).minRefundSatoshis).toBe(1000)
    expect((module as any).internalizeProtocol).toBe('wallet payment')
  })

  it('accepts config overrides for all properties', () => {
    const customNonce = { createNonce: jest.fn() }
    const customScript = { pubKeyToP2PKHLockingScript: jest.fn() }
    const module = new Brc29RemittanceModule({
      protocolID: [1, 'custom'],
      labels: ['lbl'],
      description: 'desc',
      outputDescription: 'out-desc',
      refundFeeSatoshis: 500,
      minRefundSatoshis: 200,
      internalizeProtocol: 'basket insertion',
      nonceProvider: customNonce,
      lockingScriptProvider: customScript
    })
    expect((module as any).protocolID).toEqual([1, 'custom'])
    expect((module as any).labels).toEqual(['lbl'])
    expect((module as any).description).toBe('desc')
    expect((module as any).outputDescription).toBe('out-desc')
    expect((module as any).refundFeeSatoshis).toBe(500)
    expect((module as any).minRefundSatoshis).toBe(200)
    expect((module as any).internalizeProtocol).toBe('basket insertion')
    expect((module as any).nonceProvider).toBe(customNonce)
    expect((module as any).lockingScriptProvider).toBe(customScript)
  })
})

// ---------------------------------------------------------------------------
// DefaultNonceProvider and DefaultLockingScriptProvider are exported;
// test that they satisfy the interfaces (smoke tests only – actual crypto
// tested elsewhere).
// ---------------------------------------------------------------------------

describe('DefaultNonceProvider and DefaultLockingScriptProvider', () => {
  it('DefaultNonceProvider.createNonce delegates to createNonce util', async () => {
    const fakeWallet = {
      createHmac: jest.fn(async () => ({ data: new Array(32).fill(0) }))
    } as unknown as WalletInterface
    // createNonce will fail without real wallet; just ensure the function exists and is async
    await expect(
      DefaultNonceProvider.createNonce(fakeWallet, 'self', 'example.com')
    ).rejects.toBeDefined() // real createNonce needs full wallet
  })

  it('DefaultLockingScriptProvider has pubKeyToP2PKHLockingScript method', () => {
    expect(typeof DefaultLockingScriptProvider.pubKeyToP2PKHLockingScript).toBe('function')
  })
})
