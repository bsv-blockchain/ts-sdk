import Script from '../Script'
import OP from '../OP'
import BigNumber from '../../primitives/BigNumber'

describe('Script – additional coverage', () => {
  describe('fromHex', () => {
    it('throws for odd-length hex string', () => {
      expect(() => Script.fromHex('abc')).toThrow()
    })

    it('throws for non-hex characters', () => {
      expect(() => Script.fromHex('gggg')).toThrow()
    })
  })

  describe('isLockingScript / isUnlockingScript on base Script', () => {
    it('throws NotImplemented for isLockingScript', () => {
      const script = new Script()
      expect(() => script.isLockingScript()).toThrow('Not implemented')
    })

    it('throws NotImplemented for isUnlockingScript', () => {
      const script = new Script()
      expect(() => script.isUnlockingScript()).toThrow('Not implemented')
    })
  })

  describe('writeScript', () => {
    it('appends all chunks from another script', () => {
      const s1 = Script.fromASM('OP_1 OP_2')
      const s2 = Script.fromASM('OP_3')
      s1.writeScript(s2)
      expect(s1.toASM()).toBe('OP_1 OP_2 OP_3')
    })
  })

  describe('setChunkOpCode', () => {
    it('replaces the opcode at the given index', () => {
      const script = Script.fromASM('OP_1 OP_2 OP_3')
      script.setChunkOpCode(1, OP.OP_NOP)
      expect(script.chunks[1].op).toBe(OP.OP_NOP)
    })
  })

  describe('writeBn', () => {
    it('pushes OP_0 for zero', () => {
      const script = new Script().writeBn(new BigNumber(0))
      expect(script.chunks[0].op).toBe(OP.OP_0)
    })

    it('pushes OP_1NEGATE for -1', () => {
      const script = new Script().writeBn(new BigNumber(-1))
      expect(script.chunks[0].op).toBe(OP.OP_1NEGATE)
    })

    it('pushes OP_1..OP_16 for 1..16', () => {
      for (let n = 1; n <= 16; n++) {
        const script = new Script().writeBn(new BigNumber(n))
        expect(script.chunks[0].op).toBe(OP.OP_1 + (n - 1))
      }
    })

    it('pushes encoded binary for numbers > 16', () => {
      const script = new Script().writeBn(new BigNumber(1000))
      expect(script.chunks[0].data).toBeDefined()
    })
  })

  describe('writeNumber', () => {
    it('writes a number to the script', () => {
      const script = new Script().writeNumber(5)
      expect(script.chunks[0].op).toBe(OP.OP_5)
    })
  })

  describe('writeBin', () => {
    it('uses OP_PUSHDATA1 for data 76..255 bytes', () => {
      const data = new Array(76).fill(0x01)
      const script = new Script().writeBin(data)
      expect(script.chunks[0].op).toBe(OP.OP_PUSHDATA1)
    })

    it('uses OP_PUSHDATA2 for data 256..65535 bytes', () => {
      const data = new Array(256).fill(0x02)
      const script = new Script().writeBin(data)
      expect(script.chunks[0].op).toBe(OP.OP_PUSHDATA2)
    })
  })

  describe('findAndDelete – PUSHDATA1 target', () => {
    it('deletes chunks encoded with OP_PUSHDATA1 (76-255 bytes)', () => {
      const data = new Array(76).fill(0xab)
      const target = new Script().writeBin(data)
      const source = new Script().writeBin(data).writeBin(data).writeOpCode(OP.OP_1)
      source.findAndDelete(target)
      expect(source.chunks).toHaveLength(1)
      expect(source.chunks[0].op).toBe(OP.OP_1)
    })
  })
})
