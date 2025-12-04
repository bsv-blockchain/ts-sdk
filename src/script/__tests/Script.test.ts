import Script from '../../script/Script'
import PrivateKey from '../../primitives/PrivateKey'
import P2PKH from '../../script/templates/P2PKH'
import OP from '../../script/OP'
import { toHex } from '../../primitives/utils'

import scriptInvalid from './script.invalid.vectors'
import scriptValid from './script.valid.vectors'

describe('Script', () => {
  it('should make a new script', () => {
    const script = new Script()
    expect(script).toBeDefined()
    expect(new Script().toASM()).toEqual('')
  })

  describe('fromHex', () => {
    it('should parse this hex string containing an OP code', () => {
      const buf = Buffer.alloc(1)
      buf[0] = OP.OP_0
      const script = Script.fromHex(buf.toString('hex'))
      expect(script.chunks).toHaveLength(1)
      expect(script.chunks[0].op).toBe(buf[0])
    })
  })

  describe('fromAddress', () => {
    it('should parse this mainnet Base58Check encoded address string and result in a P2PKH Script', () => {
      const priv = PrivateKey.fromRandom()
      const address = priv.toAddress()
      const publicKey = priv.toPublicKey()
      const pkh = publicKey.toHash()
      const lockingScriptFromTemplate = new P2PKH().lock(pkh).toASM()
      const script = new P2PKH().lock(address).toASM()
      expect(script).toBe(lockingScriptFromTemplate)
    })

    it('should parse this testnet Base58Check encoded address string and result in a P2PKH Script', () => {
      const priv = PrivateKey.fromRandom()
      const address = priv.toAddress([0x6f])
      const publicKey = priv.toPublicKey()
      const pkh = publicKey.toHash()
      const lockingScriptFromTemplate = new P2PKH().lock(pkh).toASM()
      const script = new P2PKH().lock(address).toASM()
      expect(script).toBe(lockingScriptFromTemplate)
    })

    it('should error when attempting to parse this strange Base58Check encoded string', () => {
      const priv = PrivateKey.fromRandom()
      const address = priv.toAddress([0x88])
      function attemptToDeriveAddress (): string {
        const script = new P2PKH().lock(address).toASM()
        return script
      }
      expect(attemptToDeriveAddress).toThrow('only P2PKH is supported')
    })
  })

  describe('fromBinary', () => {
    it('should parse this buffer containing an OP code', () => {
      const buf = Buffer.alloc(1)
      buf[0] = OP.OP_0
      const script = Script.fromBinary([...buf])
      expect(script.chunks).toHaveLength(1)
      expect(script.chunks[0].op).toBe(buf[0])
    })

    it('should parse this buffer containing another OP code', () => {
      const buf = Buffer.alloc(1)
      buf[0] = OP.OP_CHECKMULTISIG
      const script = Script.fromBinary([...buf])
      expect(script.chunks).toHaveLength(1)
      expect(script.chunks[0].op).toBe(buf[0])
    })

    it('should parse this buffer containing three bytes of data', () => {
      const buf = [3, 1, 2, 3]
      const script = Script.fromBinary([...buf])
      expect(script.chunks).toHaveLength(1)
      expect(script.chunks[0].data).toEqual([1, 2, 3])
    })

    it('should parse this buffer containing OP_PUSHDATA1 and zero bytes of data', () => {
      const buf = [0]
      buf[0] = OP.OP_PUSHDATA1
      const script = Script.fromBinary([...buf])
      expect(script.chunks.length).toEqual(1)
      expect(script.chunks[0].data).toEqual([])
    })

    it('should parse this buffer containing OP_PUSHDATA2 and zero bytes of data', () => {
      const buf = [0]
      buf[0] = OP.OP_PUSHDATA2
      const script = Script.fromBinary([...buf])
      expect(script.chunks.length).toEqual(1)
      expect(script.chunks[0].data).toEqual([])
    })

    it('should parse this buffer containing OP_PUSHDATA2 and three bytes of data', () => {
      const buf = [OP.OP_PUSHDATA2, 3, 0, 1, 2, 3]
      const script = Script.fromBinary([...buf])
      expect(script.chunks.length).toEqual(1)
      expect(script.chunks[0].data).toEqual([1, 2, 3])
    })

    it('should parse this buffer containing OP_PUSHDATA4 and zero bytes of data', () => {
      const buf = [0, 0]
      buf[0] = OP.OP_PUSHDATA4
      const script = Script.fromBinary([...buf])
      expect(script.chunks.length).toEqual(1)
      expect(script.chunks[0].data).toEqual([])
    })

    it('should parse this buffer containing OP_PUSHDATA4 and three bytes of data', () => {
      const buf = [OP.OP_PUSHDATA4, 3, 0, 0, 0, 1, 2, 3]
      const script = Script.fromBinary([...buf])
      expect(script.chunks.length).toEqual(1)
      expect(script.chunks[0].data).toEqual([1, 2, 3])
    })

    it('should parse this buffer an OP code, data, and another OP code', () => {
      const buf = [OP.OP_0, OP.OP_PUSHDATA4, 3, 0, 0, 0, 1, 2, 3, OP.OP_0]
      const script = Script.fromBinary([...buf])
      expect(script.chunks.length).toEqual(3)
      expect(script.chunks[0].op).toEqual(buf[0])
      expect(script.chunks[1].data).toEqual([1, 2, 3])
      expect(script.chunks[2].op).toEqual(buf[buf.length - 1])
    })

    it('should output this hex string containing an OP code', () => {
      const buf = Buffer.alloc(1)
      buf[0] = OP.OP_0
      const script = Script.fromHex(buf.toString('hex'))
      expect(script.chunks.length).toEqual(1)
      expect(script.chunks[0].op).toEqual(buf[0])
      expect(script.toHex()).toEqual(buf.toString('hex'))
    })

    it('should output this buffer containing an OP code', () => {
      const buf = Buffer.alloc(1)
      buf[0] = OP.OP_0
      const script = Script.fromBinary([...buf])
      expect(script.chunks.length).toEqual(1)
      expect(script.chunks[0].op).toEqual(buf[0])
      expect(script.toHex()).toEqual(buf.toString('hex'))
    })

    it('should output this buffer containing another OP code', () => {
      const buf = Buffer.alloc(1)
      buf[0] = OP.OP_CHECKMULTISIG
      const script = Script.fromBinary([...buf])
      expect(script.chunks.length).toEqual(1)
      expect(script.chunks[0].op).toEqual(buf[0])
      expect(script.toHex()).toEqual(buf.toString('hex'))
    })

    it('should output this buffer containing three bytes of data', () => {
      const buf = Buffer.from([3, 1, 2, 3])
      const script = Script.fromBinary([...buf])
      expect(script.chunks.length).toEqual(1)
      expect(script.chunks[0].data).toEqual([1, 2, 3])
      expect(script.toHex()).toEqual(buf.toString('hex'))
    })

    it('should output this buffer containing OP_PUSHDATA1 and three bytes of data', () => {
      const buf = Buffer.from([0, 0, 1, 2, 3])
      buf[0] = OP.OP_PUSHDATA1
      buf.writeUInt8(3, 1)
      const script = Script.fromBinary([...buf])
      expect(script.chunks.length).toEqual(1)
      expect(script.chunks[0].data).toEqual([1, 2, 3])
      expect(script.toHex()).toEqual(buf.toString('hex'))
    })

    it('should output this buffer containing OP_PUSHDATA2 and three bytes of data', () => {
      const buf = Buffer.from([0, 0, 0, 1, 2, 3])
      buf[0] = OP.OP_PUSHDATA2
      buf.writeUInt16LE(3, 1)
      const script = Script.fromBinary([...buf])
      expect(script.chunks.length).toEqual(1)
      expect(script.chunks[0].data).toEqual([1, 2, 3])
      expect(script.toHex()).toEqual(buf.toString('hex'))
    })

    it('should output this buffer containing OP_PUSHDATA4 and three bytes of data', () => {
      const buf = Buffer.from([0, 0, 0, 0, 0, 1, 2, 3])
      buf[0] = OP.OP_PUSHDATA4
      buf.writeUInt16LE(3, 1)
      const script = Script.fromBinary([...buf])
      expect(script.chunks.length).toEqual(1)
      expect(script.chunks[0].data).toEqual([1, 2, 3])
      expect(script.toHex()).toEqual(buf.toString('hex'))
    })

    it('should output this buffer an OP code, data, and another OP code', () => {
      const buf = Buffer.from([0, 0, 0, 0, 0, 0, 1, 2, 3, 0])
      buf[0] = OP.OP_0
      buf[1] = OP.OP_PUSHDATA4
      buf.writeUInt16LE(3, 2)
      buf[buf.length - 1] = OP.OP_0
      const script = Script.fromBinary([...buf])
      expect(script.chunks.length).toEqual(3)
      expect(script.chunks[0].op).toEqual(buf[0])
      expect(script.chunks[1].data).toEqual([1, 2, 3])
      expect(script.chunks[2].op).toEqual(buf[buf.length - 1])
      expect(script.toHex()).toEqual(buf.toString('hex'))
    })
  })

  describe('toASM', () => {
    it('should output this buffer an OP code, data, and another OP code', () => {
      const buf = Buffer.from([0, 0, 0, 0, 0, 0, 1, 2, 3, 0])
      buf[0] = OP.OP_0
      buf[1] = OP.OP_PUSHDATA4
      buf.writeUInt16LE(3, 2)
      buf[buf.length - 1] = OP.OP_0
      const script = Script.fromBinary([...buf])
      expect(script.chunks.length).toEqual(3)
      expect(script.chunks[0].op).toEqual(buf[0])
      expect(script.chunks[1].data).toEqual([1, 2, 3])
      expect(script.chunks[2].op).toEqual(buf[buf.length - 1])
      expect(script.toASM()).toEqual('OP_0 010203 OP_0')
    })
  })

  describe('fromASM', () => {
    it('should parse these known scripts', () => {
      expect(Script.fromASM('OP_0 010203 OP_0').toASM()).toEqual(
        'OP_0 010203 OP_0'
      )
      expect(
        Script.fromASM(
          'OP_DUP OP_HASH160 1451baa3aad777144a0759998a03538018dd7b4b OP_EQUALVERIFY OP_CHECKSIG'
        ).toASM()
      ).toEqual(
        'OP_DUP OP_HASH160 1451baa3aad777144a0759998a03538018dd7b4b OP_EQUALVERIFY OP_CHECKSIG'
      )
      expect(
        Script.fromASM(
          'OP_SHA256 8cc17e2a2b10e1da145488458a6edec4a1fdb1921c2d5ccbc96aa0ed31b4d5f8 OP_EQUALVERIFY OP_DUP OP_HASH160 1451baa3aad777144a0759998a03538018dd7b4b OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_EQUALVERIFY OP_DUP OP_HASH160 1451baa3aad777144a0759998a03538018dd7b4b OP_EQUALVERIFY OP_CHECKSIG'
        ).toASM()
      ).toEqual(
        'OP_SHA256 8cc17e2a2b10e1da145488458a6edec4a1fdb1921c2d5ccbc96aa0ed31b4d5f8 OP_EQUALVERIFY OP_DUP OP_HASH160 1451baa3aad777144a0759998a03538018dd7b4b OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_EQUALVERIFY OP_DUP OP_HASH160 1451baa3aad777144a0759998a03538018dd7b4b OP_EQUALVERIFY OP_CHECKSIG'
      )
      expect(Script.fromASM('OP_0 010203 OP_0').toASM()).toEqual(
        'OP_0 010203 OP_0'
      )
      expect(Script.fromASM('OP_0 010203 OP_0').toASM()).toEqual(
        'OP_0 010203 OP_0'
      )
      expect(Script.fromASM('OP_0 3 010203 OP_0').toASM()).toEqual(
        'OP_0 03 010203 OP_0'
      )
      expect(Script.fromASM('').toASM()).toEqual('')
    })
    it('should parse this known script in ASM', () => {
      const asm =
        'OP_DUP OP_HASH160 f4c03610e60ad15100929cc23da2f3a799af1725 OP_EQUALVERIFY OP_CHECKSIG'
      const script = Script.fromASM(asm)

      expect(script.chunks[0].op).toEqual(OP.OP_DUP)
      expect(script.chunks[1].op).toEqual(OP.OP_HASH160)
      expect(script.chunks[2].op).toEqual(20)

      // Ensure `data` is defined before calling `toHex`
      expect(toHex(script.chunks[2].data ?? [])).toEqual(
        'f4c03610e60ad15100929cc23da2f3a799af1725'
      )

      expect(script.chunks[3].op).toEqual(OP.OP_EQUALVERIFY)
      expect(script.chunks[4].op).toEqual(OP.OP_CHECKSIG)
    })

    it('should parse this known problematic script in ASM', () => {
      const asm = 'OP_RETURN 026d02 0568656c6c6f'
      const script = Script.fromASM(asm)
      expect(script.toASM()).toEqual(asm)
    })

    it('should know this is invalid hex', () => {
      const asm = 'OP_RETURN 026d02 0568656c6c6fzz'

      const createScript = (): string => {
        const script = Script.fromASM(asm)
        return script.toASM()
      }

      // Expect the function to throw an error with the specified message
      expect(createScript).toThrow('Invalid hex string')
    })

    it('should parse this long PUSHDATA1 script in ASM', () => {
      const buf = Buffer.alloc(220, 0)
      const asm = 'OP_RETURN ' + buf.toString('hex')
      const script = Script.fromASM(asm)
      expect(script.chunks[1].op).toEqual(OP.OP_PUSHDATA1)
      expect(script.toASM()).toEqual(asm)
    })

    it('should parse this long PUSHDATA2 script in ASM', () => {
      const buf = Buffer.alloc(1024, 0)
      const asm = 'OP_RETURN ' + buf.toString('hex')
      const script = Script.fromASM(asm)
      expect(script.chunks[1].op).toEqual(OP.OP_PUSHDATA2)
      expect(script.toASM()).toEqual(asm)
    })

    it('should parse this long PUSHDATA4 script in ASM', () => {
      const buf = Buffer.alloc(Math.pow(2, 17), 0)
      const asm = 'OP_RETURN ' + buf.toString('hex')
      const script = Script.fromASM(asm)
      expect(script.chunks[1].op).toEqual(OP.OP_PUSHDATA4)
      expect(script.toASM()).toEqual(asm)
    })

    it('should return this script correctly', () => {
      const asm1 = 'OP_FALSE'
      const asm2 = 'OP_0'
      const asm3 = '0'
      expect(Script.fromASM(asm1).toASM()).toEqual(asm2)
      expect(Script.fromASM(asm2).toASM()).toEqual(asm2)
      expect(Script.fromASM(asm3).toASM()).toEqual(asm2)
    })

    it('should return this script correctly', () => {
      const asm1 = 'OP_1NEGATE'
      const asm2 = '-1'
      expect(Script.fromASM(asm1).toASM()).toEqual(asm1)
      expect(Script.fromASM(asm2).toASM()).toEqual(asm1)
    })
  })

  describe('#removeCodeseparators', () => {
    it('should remove any OP_CODESEPARATORs', () => {
      expect(
        Script.fromASM('OP_CODESEPARATOR OP_0 OP_CODESEPARATOR')
          .removeCodeseparators()
          .toASM()
      ).toEqual('OP_0')
    })
  })

  describe('#isPushOnly', () => {
    it("should know these scripts are or aren't push only", () => {
      expect(Script.fromASM('OP_0').isPushOnly()).toEqual(true)
      expect(Script.fromASM('OP_0 OP_RETURN').isPushOnly()).toEqual(false)
      expect(Script.fromASM('OP_PUSHDATA1 5 1010101010').isPushOnly()).toEqual(
        true
      )

      // like bitcoind, we regard OP_RESERVED as being "push only"
      expect(Script.fromASM('OP_RESERVED').isPushOnly()).toEqual(true)
    })
  })

  describe('#findAndDelete', () => {
    it('should find and delete this buffer', () => {
      expect(
        Script.fromASM('OP_RETURN f0f0')
          .findAndDelete(Script.fromASM('f0f0'))
          .toASM()
      ).toEqual('OP_RETURN')
    })
  })

  describe('vectors', () => {
    scriptValid.forEach((a, i) => {
      if (a.length === 1) {
        return
      }
      it(`should not fail when reading scriptValid vector ${i}`, () => {
        expect(() => {
          Script.fromHex(a[0]).toHex()
          Script.fromHex(a[0]).toASM()
        }).not.toThrow()

        expect(() => {
          Script.fromHex(a[1]).toHex()
          Script.fromHex(a[1]).toASM()
        }).not.toThrow()

        // should be able to return the same output over and over
        let str = Script.fromHex(a[0]).toASM()
        expect(Script.fromASM(str).toASM()).toEqual(str)
        str = Script.fromHex(a[1]).toASM()
        expect(Script.fromASM(str).toASM()).toEqual(str)
      })
    })

    scriptInvalid.forEach((a, i) => {
      if (a.length === 1) {
        return
      }

      it(`should not fail when reading scriptInvalid vector ${i}`, () => {
        // Test that no errors are thrown for the first item
        expect(() => {
          const scriptA = Script.fromHex(a[0])
          scriptA.toHex()
          scriptA.toASM()
        }).not.toThrow()

        // Test that no errors are thrown for the second item
        expect(() => {
          const scriptB = Script.fromHex(a[1])
          scriptB.toHex()
          scriptB.toASM()
        }).not.toThrow()

        // Test that it should be able to return the same output over and over for the first item
        const strA = Script.fromHex(a[0]).toASM()
        expect(Script.fromASM(strA).toASM()).toEqual(strA)

        // Test that it should be able to return the same output over and over for the second item
        const strB = Script.fromHex(a[1]).toASM()
        expect(Script.fromASM(strB).toASM()).toEqual(strB)
      })
    })
  })

  describe('Empty binarys should equal OP_0', () => {
    it('should correctly write empty binary arrays', () => {
      const script = new Script().writeBin([])
      expect(
        script.toASM()
      ).toEqual('OP_0')
    })
  })
})
