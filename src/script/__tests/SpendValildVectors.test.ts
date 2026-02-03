import PrivateKey from '../../primitives/PrivateKey'
import { hash160, hash256 } from '../../primitives/Hash'
import Curve from '../../primitives/Curve'
import Spend from '../Spend'
import P2PKH from '../templates/P2PKH'
import RPuzzle from '../templates/RPuzzle'
import Transaction from '../../transaction/Transaction'
import LockingScript from '../LockingScript'
import UnlockingScript from '../UnlockingScript'

import { preChronicle as spendValid1, chronicle as spendValid2 } from './spend.valid.vectors'

describe('Spend Valid Vectors 1', () => {
  for (let i = 0; i < spendValid1.length; i++) {
    const a = spendValid1[i]
    if (a.length === 1) {
      continue
    }
    it(`${i} ${a[2]}`, () => {
      const spend = new Spend({
        sourceTXID:
          '0000000000000000000000000000000000000000000000000000000000000000',
        sourceOutputIndex: 0,
        sourceSatoshis: 1,
        lockingScript: LockingScript.fromHex(a[1]),
        transactionVersion: 1,
        otherInputs: [],
        outputs: [],
        inputIndex: 0,
        unlockingScript: UnlockingScript.fromHex(a[0]),
        inputSequence: 0xffffffff,
        lockTime: 0
      })
      expect(spend.validate()).toBe(true)
    })
  }
})

describe('Spend Valid Vectors 2', () => {
  for (let i = 0; i < spendValid2.length; i++) {
    const a = spendValid2[i]
    if (a.length === 1) {
      continue
    }
    it(`${i} ${a[2]}`, () => {
      const spend = new Spend({
        sourceTXID:
          '0000000000000000000000000000000000000000000000000000000000000000',
        sourceOutputIndex: 0,
        sourceSatoshis: 1,
        lockingScript: LockingScript.fromHex(a[1]),
        transactionVersion: 1,
        otherInputs: [],
        outputs: [],
        inputIndex: 0,
        unlockingScript: UnlockingScript.fromHex(a[0]),
        inputSequence: 0xffffffff,
        lockTime: 0
      })
      expect(spend.validate()).toBe(true)
    })
  }
})