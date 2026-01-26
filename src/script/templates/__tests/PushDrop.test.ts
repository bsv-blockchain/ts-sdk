/* eslint-env jest */
import PushDrop from '../../../script/templates/PushDrop'
import { CompletedProtoWallet } from '../../../auth/certificates/__tests/CompletedProtoWallet'
import { PrivateKey, Utils } from '../../../primitives/index'
import { Script, Spend } from '../../../script/index'
import { Transaction } from '../../../transaction/index'

describe('PushDrop', () => {
  let wallet
  let pushDrop: PushDrop

  const createDecodeRedeem = async (
    fields: number[][] = [],
    protocolID: [0 | 1 | 2, string] = [0, 'tests'],
    keyID: string = 'test-key',
    counterparty: string = 'self',
    signOutputs: 'all' | 'none' | 'single' = 'all',
    anyoneCanPay: boolean = false
  ): Promise<void> => {
    const lockingScript = await pushDrop.lock(
      fields,
      protocolID,
      keyID,
      counterparty
    )
    expect(lockingScript).toBeInstanceOf(Script)
    const decoded = await PushDrop.decode(lockingScript)
    expect(decoded.fields).toEqual(fields)
    const expectedPublicKey = (
      await wallet.getPublicKey({ protocolID, keyID, counterparty })
    ).publicKey
    expect(decoded.lockingPublicKey.toString()).toEqual(expectedPublicKey)
    const satoshis = 1
    const unlockingTemplate = await pushDrop.unlock(
      protocolID,
      keyID,
      counterparty,
      signOutputs,
      anyoneCanPay
    )
    const sourceTx = new Transaction(
      1,
      [],
      [
        {
          lockingScript,
          satoshis
        }
      ],
      0
    )
    const spendTx = new Transaction(
      1,
      [
        {
          sourceTransaction: sourceTx,
          sourceOutputIndex: 0,
          sequence: 0xffffffff
        }
      ],
      [],
      0
    )
    const unlockingScript = await unlockingTemplate.sign(spendTx, 0)
    expect(await unlockingTemplate.estimateLength()).toEqual(73)
    const spend = new Spend({
      sourceTXID: sourceTx.id('hex'),
      sourceOutputIndex: 0,
      sourceSatoshis: satoshis,
      lockingScript,
      transactionVersion: 1,
      otherInputs: [],
      inputIndex: 0,
      unlockingScript,
      outputs: [],
      inputSequence: 0xffffffff,
      lockTime: 0
    })
    const valid = spend.validate()
    expect(valid).toBe(true)
  }

  beforeEach(() => {
    const privateKey = PrivateKey.fromRandom()
    wallet = new CompletedProtoWallet(privateKey)
    pushDrop = new PushDrop(wallet)
  })

  it('Passes various test vectors', async () => {
    await createDecodeRedeem()
    await createDecodeRedeem([[0]])
    await createDecodeRedeem([[1]])
    await createDecodeRedeem([[0x81]])
    await createDecodeRedeem([[3, 1, 4, 1, 5, 9]])
    await createDecodeRedeem([new Array(200).fill(0xff)])
    await createDecodeRedeem([new Array(400).fill(0xff)])
    await createDecodeRedeem([new Array(70000).fill(0xff)])
    await createDecodeRedeem([[0], [1], [2]])
    await createDecodeRedeem([[0], [1], [2], [3]])
    await createDecodeRedeem(
      [[3, 1, 4, 1, 5, 9]],
      undefined,
      undefined,
      undefined,
      'none',
      false
    )
    await createDecodeRedeem(
      [[3, 1, 4, 1, 5, 9]],
      undefined,
      undefined,
      undefined,
      'single',
      false
    )
    await createDecodeRedeem(
      [[3, 1, 4, 1, 5, 9]],
      undefined,
      undefined,
      undefined,
      'all',
      true
    )
    await createDecodeRedeem(
      [[3, 1, 4, 1, 5, 9]],
      undefined,
      undefined,
      undefined,
      'none',
      true
    )
    await createDecodeRedeem(
      [[3, 1, 4, 1, 5, 9]],
      undefined,
      undefined,
      undefined,
      'single',
      true
    )
  })

  describe('lock', () => {
    it('creates a correct locking script', async () => {
      const fields = [
        Utils.toArray('hello world', 'utf8'),
        Utils.toArray('This is a field', 'utf8'),
        [0xde, 0xad, 0xbe, 0xef]
      ]
      const protocolID: [0 | 1 | 2, string] = [0, 'tests']
      const keyID = 'test-key'
      const counterparty = 'self'
      const lockingScript = await pushDrop.lock(
        fields,
        protocolID,
        keyID,
        counterparty
      )

      // Check that the locking script is not null
      expect(lockingScript).toBeInstanceOf(Script)

      // Decode the locking script and check the fields and locking public key
      const decoded = await PushDrop.decode(lockingScript)
      expect(decoded.fields).toEqual(fields)
      const expectedPublicKey = (
        await wallet.getPublicKey({ protocolID, keyID, counterparty })
      ).publicKey
      expect(decoded.lockingPublicKey.toString()).toEqual(expectedPublicKey)
    })
  })

  describe('unlock', () => {
    it('creates a correct unlocking script', async () => {
      const fields = [
        Utils.toArray('hello world', 'utf8'),
        Utils.toArray('This is a field', 'utf8'),
        [0xde, 0xad, 0xbe, 0xef]
      ]
      const protocolID: [0 | 1 | 2, string] = [0, 'tests']
      const keyID = 'test-key'
      const counterparty = 'self'
      const lockingScript = await pushDrop.lock(
        fields,
        protocolID,
        keyID,
        counterparty
      )
      const satoshis = 1
      const unlockingTemplate = await pushDrop.unlock(
        protocolID,
        keyID,
        counterparty
      )
      const sourceTx = new Transaction(
        1,
        [],
        [
          {
            lockingScript,
            satoshis
          }
        ],
        0
      )
      const spendTx = new Transaction(
        1,
        [
          {
            sourceTransaction: sourceTx,
            sourceOutputIndex: 0,
            sequence: 0xffffffff
          }
        ],
        [],
        0
      )
      const unlockingScript = await unlockingTemplate.sign(spendTx, 0)
      expect(await unlockingTemplate.estimateLength()).toEqual(73)
      const spend = new Spend({
        sourceTXID: sourceTx.id('hex'),
        sourceOutputIndex: 0,
        sourceSatoshis: satoshis,
        lockingScript,
        transactionVersion: 1,
        otherInputs: [],
        inputIndex: 0,
        unlockingScript,
        outputs: [],
        inputSequence: 0xffffffff,
        lockTime: 0
      })
      const valid = spend.validate()
      expect(valid).toBe(true)
    })
  })

  describe('decode', () => {
    it('decodes the locking script correctly', async () => {
      const fields = [
        Utils.toArray('hello world', 'utf8'),
        Utils.toArray('This is a field', 'utf8'),
        [0xde, 0xad, 0xbe, 0xef]
      ]
      const protocolID: [0 | 1 | 2, string] = [0, 'tests']
      const keyID = 'test-key'
      const counterparty = 'self'

      const lockingScript = await pushDrop.lock(
        fields,
        protocolID,
        keyID,
        counterparty
      )

      const decoded = await PushDrop.decode(lockingScript)
      expect(decoded.fields).toEqual(fields)
      const expectedPublicKey = (
        await wallet.getPublicKey({ protocolID, keyID, counterparty })
      ).publicKey
      expect(decoded.lockingPublicKey.toString()).toEqual(expectedPublicKey)
    })

    it('decodes the locking script correctly with lockPosition after', async () => {
      const fields = [
        Utils.toArray('hello world', 'utf8'),
        Utils.toArray('This is a field', 'utf8'),
        [0xde, 0xad, 0xbe, 0xef]
      ]
      const protocolID: [0 | 1 | 2, string] = [0, 'tests']
      const keyID = 'test-key'
      const counterparty = 'self'

      const lockingScript = await pushDrop.lock(
        fields,
        protocolID,
        keyID,
        counterparty,
        false,
        true,
        'after'
      )

      const decoded = await PushDrop.decode(lockingScript, 'after')
      expect(decoded.fields).toEqual(fields)
      const expectedPublicKey = (
        await wallet.getPublicKey({ protocolID, keyID, counterparty })
      ).publicKey
      expect(decoded.lockingPublicKey.toString()).toEqual(expectedPublicKey)
    })
  })
})
