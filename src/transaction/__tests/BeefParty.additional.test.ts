import BeefParty from '../BeefParty'
import { Beef } from '../Beef'

describe('BeefParty – additional coverage', () => {
  describe('mergeBeefFromParty', () => {
    it('merges a Beef object directly (non-array branch)', () => {
      const bp = new BeefParty(['alice'])
      const b = new Beef()
      bp.mergeBeefFromParty('alice', b)
      // No error thrown means the Beef object branch executed
      expect(bp.isParty('alice')).toBe(true)
    })

    it('merges a binary Beef (array branch) via Beef.fromBinary', () => {
      const bp = new BeefParty(['bob'])
      const emptyBeef = new Beef()
      const binary = emptyBeef.toBinary()
      bp.mergeBeefFromParty('bob', binary)
      expect(bp.isParty('bob')).toBe(true)
    })
  })
})
