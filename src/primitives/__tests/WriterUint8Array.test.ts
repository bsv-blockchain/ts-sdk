import BigNumber from '../BigNumber'
import { Reader, encode, WriterUint8Array } from '../utils'

describe('WriterUint8Array', () => {
  it('should create a new buffer writer', () => {
    const bw = new WriterUint8Array()
    expect(bw).toBeDefined()
  })

  describe('#getLength', () => {
    it('should compute length correctly of two 2-byte buffers', () => {
      const buf1 = Buffer.from('0000', 'hex')
      const buf2 = Buffer.from('0000', 'hex')
      const bw = new WriterUint8Array().write([...buf1]).write([...buf2])
      expect(bw.getLength()).toEqual(4)
    })
  })

  describe('#toArray', () => {
    it('should concat these two bufs', () => {
      const buf1 = [0]
      const buf2 = [1]
      const bw = new WriterUint8Array([buf1, buf2])
      expect(encode(bw.toArray(), 'hex')).toEqual('0001')
    })
  })

  describe('#write', () => {
    it('should write a buffer', () => {
      const buf = [0]
      const bw = new WriterUint8Array()
      bw.write(buf)
      expect(encode(bw.toArray(), 'hex')).toEqual('00')
    })
  })

  describe('#writeReverse', () => {
    it('should write a buffer in reverse', () => {
      const buf = [0, 1]
      const bw = new WriterUint8Array()
      bw.writeReverse(buf)
      expect(encode(bw.toArray(), 'hex')).toEqual('0100')
    })
  })

  describe('#writeUInt8', () => {
    it('should write 1', () => {
      const bw = new WriterUint8Array()
      expect(encode(bw.writeUInt8(1).toArray(), 'hex')).toEqual('01')
    })
  })

  describe('#writeInt8', () => {
    it('should write 1', () => {
      const bw = new WriterUint8Array()
      expect(encode(bw.writeInt8(1).toArray(), 'hex')).toEqual('01')
      expect(encode(new WriterUint8Array().writeInt8(-1).toArray(), 'hex')).toEqual('ff')
    })
  })

  describe('#writeUInt16BE', () => {
    it('should write 1', () => {
      const bw = new WriterUint8Array()
      expect(encode(bw.writeUInt16BE(1).toArray(), 'hex')).toEqual('0001')
    })
  })

  describe('#writeInt16BE', () => {
    it('should write 1', () => {
      const bw = new WriterUint8Array()
      expect(encode(bw.writeInt16BE(1).toArray(), 'hex')).toEqual('0001')
      expect(encode(new WriterUint8Array().writeInt16BE(-1).toArray(), 'hex')).toEqual(
        'ffff'
      )
    })
  })

  describe('#writeUInt16LE', () => {
    it('should write 1', () => {
      const bw = new WriterUint8Array()
      expect(encode(bw.writeUInt16LE(1).toArray(), 'hex')).toEqual('0100')
    })
  })

  describe('#writeInt16LE', () => {
    it('should write 1', () => {
      const bw = new WriterUint8Array()
      expect(encode(bw.writeInt16LE(1).toArray(), 'hex')).toEqual('0100')
      expect(encode(new WriterUint8Array().writeInt16LE(-1).toArray(), 'hex')).toEqual(
        'ffff'
      )
    })
  })

  describe('#writeUInt32BE', () => {
    it('should write 1', () => {
      const bw = new WriterUint8Array()
      expect(encode(bw.writeUInt32BE(1).toArray(), 'hex')).toEqual('00000001')
    })
  })

  describe('#writeInt32BE', () => {
    it('should write 1', () => {
      const bw = new WriterUint8Array()
      expect(encode(bw.writeInt32BE(1).toArray(), 'hex')).toEqual('00000001')
      expect(encode(new WriterUint8Array().writeInt32BE(-1).toArray(), 'hex')).toEqual(
        'ffffffff'
      )
    })
  })

  describe('#writeUInt32LE', () => {
    it('should write 1', () => {
      const bw = new WriterUint8Array()
      expect(encode(bw.writeUInt32LE(1).toArray(), 'hex')).toEqual('01000000')
    })
  })

  describe('#writeInt32LE', () => {
    it('should write 1', () => {
      const bw = new WriterUint8Array()
      expect(encode(bw.writeInt32LE(1).toArray(), 'hex')).toEqual('01000000')
      expect(encode(new WriterUint8Array().writeInt32LE(-1).toArray(), 'hex')).toEqual(
        'ffffffff'
      )
    })
  })

  describe('#writeUInt64BEBn', () => {
    it('should write 1', () => {
      const bw = new WriterUint8Array()
      expect(
        encode(bw.writeUInt64BEBn(new BigNumber(1)).toArray(), 'hex')
      ).toEqual('0000000000000001')
    })
  })

  describe('#writeUInt64LEBn', () => {
    it('should write 1', () => {
      const bw = new WriterUint8Array()
      expect(
        encode(bw.writeUInt64LEBn(new BigNumber(1)).toArray(), 'hex')
      ).toEqual('0100000000000000')
    })
  })

  describe('#writeVarInt', () => {
    it('should write a 1 byte varInt', () => {
      const bw = new WriterUint8Array()
      bw.writeVarIntNum(1)
      expect(bw.toArray().length).toEqual(1)
    })

    it('should write a 3 byte varInt', () => {
      const bw = new WriterUint8Array()
      bw.writeVarIntNum(1000)
      expect(bw.toArray().length).toEqual(3)
    })

    it('should write a 5 byte varInt', () => {
      const bw = new WriterUint8Array()
      bw.writeVarIntNum(Math.pow(2, 16 + 1))
      expect(bw.toArray().length).toEqual(5)
    })

    it('should write a 9 byte varInt', () => {
      const bw = new WriterUint8Array()
      bw.writeVarIntNum(Math.pow(2, 32 + 1))
      expect(bw.toArray().length).toEqual(9)
    })

    it('should read back the same value it wrote for a 9 byte varInt', () => {
      const bw = new WriterUint8Array()
      const n = Math.pow(2, 53)
      expect(n).toEqual(n + 1) // javascript number precision limit
      bw.writeVarIntNum(n)
      const br = new Reader(bw.toArray())
      expect(br.readVarIntBn().toHex()).toEqual('20000000000000')
    })
  })

  describe('#writeVarIntBn', () => {
    it('should write a 1 byte varInt', () => {
      const bw = new WriterUint8Array()
      bw.writeVarIntBn(new BigNumber(1))
      expect(bw.toArray().length).toEqual(1)
    })

    it('should write a 3 byte varInt', () => {
      const bw = new WriterUint8Array()
      bw.writeVarIntBn(new BigNumber(1000))
      expect(bw.toArray().length).toEqual(3)
    })

    it('should write a 5 byte varInt', () => {
      const bw = new WriterUint8Array()
      const bn = new BigNumber(Math.pow(2, 16 + 1))
      bw.writeVarIntBn(bn)
      expect(bw.toArray().length).toEqual(5)
    })

    it('should write a 9 byte varInt', () => {
      const bw = new WriterUint8Array()
      bw.writeVarIntBn(new BigNumber(Math.pow(2, 32 + 1)))
      expect(bw.toArray().length).toEqual(9)
    })
  })
})
