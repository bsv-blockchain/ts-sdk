import BigNumber from '../BigNumber'
import { ReaderUint8Array, Writer, toHex } from '../utils'

describe('ReaderUint8Array', () => {
  it('should make a new Br', () => {
    let br = new ReaderUint8Array()
    expect(br).toBeDefined()
    br = new ReaderUint8Array()
    expect(br).toBeDefined()
  })

  it('should create a new ReaderUint8Array with an Array', () => {
    const arr: number[] = []
    const br = new ReaderUint8Array(arr)
    expect(br).toBeDefined()
    expect(br.bin instanceof Uint8Array).toBeTruthy()
  })

  describe('#eof', () => {
    it('should return true for a blank br', () => {
      const br = new ReaderUint8Array([...Buffer.from([])])
      expect(br.eof()).toBeTruthy()
    })
  })

  describe('#read', () => {
    it('should return the same buffer', () => {
      const buf = Buffer.from([0])
      const br = new ReaderUint8Array([...buf])
      expect(Buffer.from(br.read()).toString('hex')).toEqual(
        buf.toString('hex')
      )
    })
  })

  it('should return a buffer of this length', () => {
    const buf = Buffer.alloc(10)
    buf.fill(0)
    const br = new ReaderUint8Array([...buf])
    const buf2 = br.read(2)
    expect(buf2.length).toEqual(2)
    expect(br.eof()).toBeFalsy()
    expect(br.pos).toEqual(2)
  })

  it('should be able to read 0 bytes', () => {
    const buf = Buffer.from('0101', 'hex')
    expect(new ReaderUint8Array([...buf]).read(0).length).toEqual(0)
  })
})

describe('#readReverse', () => {
  it('should reverse this [0, 1]', () => {
    const buf = Buffer.from([0, 1])
    const br = new ReaderUint8Array([...buf])
    expect(toHex(br.readReverse())).toEqual('0100')
  })

  it('should be able to read 0 bytes', () => {
    const buf = Buffer.from('0101', 'hex')
    expect(new ReaderUint8Array([...buf]).readReverse(0).length).toEqual(0)
  })
})

describe('#readUInt8', () => {
  it('should return 1', () => {
    const buf = Buffer.alloc(1)
    buf.writeUInt8(1, 0)
    const br = new ReaderUint8Array([...buf])
    expect(br.readUInt8()).toEqual(1)
  })
})

describe('#readInt8', () => {
  it('should return 1', () => {
    const buf = Buffer.alloc(1)
    buf.writeInt8(1, 0)
    const br = new ReaderUint8Array([...buf])
    expect(br.readInt8()).toEqual(1)
    const bufNegative = Buffer.from('ff', 'hex')
    const brNegative = new ReaderUint8Array([...bufNegative])
    expect(brNegative.readInt8()).toEqual(-1)
  })
})

describe('#readUInt16BE', () => {
  it('should return 1', () => {
    const buf = Buffer.alloc(2)
    buf.writeUInt16BE(1, 0)
    const br = new ReaderUint8Array([...buf])
    expect(br.readUInt16BE()).toEqual(1)
  })
})

describe('#readInt16BE', () => {
  it('should return 1', () => {
    const buf = Buffer.alloc(2)
    buf.writeInt16BE(1, 0)
    const br = new ReaderUint8Array([...buf])
    expect(br.readInt16BE()).toEqual(1)
    const bufNegative = Buffer.from('ffff', 'hex')
    const brNegative = new ReaderUint8Array([...bufNegative])
    expect(brNegative.readInt8()).toEqual(-1)
  })
})

describe('#readUInt16LE', () => {
  it('should return 1', () => {
    const buf = Buffer.alloc(2)
    buf.writeUInt16LE(1, 0)
    const br = new ReaderUint8Array([...buf])
    expect(br.readUInt16LE()).toEqual(1)
  })
})

describe('#readInt16LE', () => {
  it('should return 1', () => {
    const buf = Buffer.alloc(2)
    buf.writeInt16LE(1, 0)
    const br = new ReaderUint8Array([...buf])
    expect(br.readInt16LE()).toEqual(1)
    const bufNegative = Buffer.from('ffff', 'hex')
    const brNegative = new ReaderUint8Array([...bufNegative])
    expect(brNegative.readInt8()).toEqual(-1)
  })
})

describe('#readUInt32BE', () => {
  it('should return 1', () => {
    const buf = Buffer.alloc(4)
    buf.writeUInt32BE(1, 0)
    const br = new ReaderUint8Array([...buf])
    expect(br.readUInt32BE()).toEqual(1)
  })
})

describe('#readInt32BE', () => {
  it('should return 1', () => {
    const buf = Buffer.alloc(4)
    buf.writeInt32BE(1, 0)
    const br = new ReaderUint8Array([...buf])
    expect(br.readInt32BE()).toEqual(1)
    const bufNegative = Buffer.from('ffffffff', 'hex')
    const brNegative = new ReaderUint8Array([...bufNegative])
    expect(brNegative.readInt8()).toEqual(-1)
  })
})

describe('#readUInt32LE', () => {
  it('should return 1', () => {
    const buf = Buffer.alloc(4)
    buf.writeUInt32LE(1, 0)
    const br = new ReaderUint8Array([...buf])
    expect(br.readUInt32LE()).toEqual(1)
  })
})

describe('#readInt32LE', () => {
  it('should return 1', () => {
    const buf = Buffer.alloc(4)
    buf.writeInt32LE(1, 0)
    const br = new ReaderUint8Array([...buf])
    expect(br.readInt32LE()).toEqual(1)
    expect(
      new ReaderUint8Array([...Buffer.from('ffffffff', 'hex')]).readInt32LE()
    ).toEqual(-1)
  })
})

describe('#readUInt64BEBn', () => {
  it('should return 1', () => {
    const buf = Buffer.alloc(8)
    buf.fill(0)
    buf.writeUInt32BE(1, 4)
    const br = new ReaderUint8Array([...buf])
    expect(br.readUInt64BEBn().toNumber()).toEqual(1)
  })

  it('should return 2^64', () => {
    const buf = Buffer.alloc(8)
    buf.fill(0xff)
    const br = new ReaderUint8Array([...buf])
    expect(br.readUInt64BEBn().toHex()).toEqual('ffffffffffffffff')
  })
})

describe('#readUInt64LEBn', () => {
  it('should return 1', () => {
    const buf = Buffer.alloc(8)
    buf.fill(0)
    buf.writeUInt32LE(1, 0)
    const br = new ReaderUint8Array([...buf])
    expect(br.readUInt64LEBn().toNumber()).toEqual(1)
  })

  it('should return 2^30', () => {
    const buf = Buffer.alloc(8)
    buf.fill(0)
    buf.writeUInt32LE(Math.pow(2, 30), 0)
    const br = new ReaderUint8Array([...buf])
    expect(br.readUInt64LEBn().toNumber()).toEqual(Math.pow(2, 30))
  })

  it('should return 0', () => {
    const buf = Buffer.alloc(8)
    buf.fill(0)
    const br = new ReaderUint8Array([...buf])
    expect(br.readUInt64LEBn().toNumber()).toEqual(0)
  })

  it('should return 2^64', () => {
    const buf = Buffer.alloc(8)
    buf.fill(0xff)
    const br = new ReaderUint8Array([...buf])
    expect(br.readUInt64LEBn().toHex()).toEqual('ffffffffffffffff')
  })
})

describe('#readVarInt', () => {
  it('should read a 1 byte varInt', () => {
    const buf = Buffer.from([50])
    const br = new ReaderUint8Array([...buf])
    expect(br.readVarInt().length).toEqual(1)
  })

  it('should read a 3 byte varInt', () => {
    const buf = Buffer.from([253, 253, 0])
    const br = new ReaderUint8Array([...buf])
    expect(br.readVarInt().length).toEqual(3)
  })

  it('should read a 5 byte varInt', () => {
    const buf = Buffer.from([254, 0, 0, 0, 0])
    buf.writeUInt32LE(50000, 1)
    const br = new ReaderUint8Array([...buf])
    expect(br.readVarInt().length).toEqual(5)
  })

  it('should read a 9 byte varInt', () => {
    const buf = new Writer()
      .writeVarIntBn(new BigNumber(Math.pow(2, 54).toString()))
      .toArray()
    const br = new ReaderUint8Array([...buf])
    expect(br.readVarInt().length).toEqual(9)
  })
})

describe('#readVarIntNum', () => {
  it('should read a 1 byte varInt', () => {
    const buf = Buffer.from([50])
    const br = new ReaderUint8Array([...buf])
    expect(br.readVarIntNum()).toEqual(50)
  })

  it('should read a 3 byte varInt', () => {
    const buf = Buffer.from([253, 253, 0])
    const br = new ReaderUint8Array([...buf])
    expect(br.readVarIntNum()).toEqual(253)
  })

  it('should read a 5 byte varInt', () => {
    const buf = Buffer.from([254, 0, 0, 0, 0])
    buf.writeUInt32LE(50000, 1)
    const br = new ReaderUint8Array([...buf])
    expect(br.readVarIntNum()).toEqual(50000)
  })

  it('should throw an error on a 9 byte varInt over the javascript uint precision limit', () => {
    const buf = new Writer()
      .writeVarIntBn(new BigNumber(Math.pow(2, 54).toString()))
      .toArray()
    const br = new ReaderUint8Array([...buf])
    expect(() => {
      br.readVarIntNum()
    }).toThrow('number too large to retain precision - use readVarIntBn')
  })

  it('should not throw an error on a 9 byte varInt not over the javascript uint precision limit', () => {
    const buf = new Writer()
      .writeVarIntBn(new BigNumber(Math.pow(2, 53).toString()))
      .toArray()
    const br = new ReaderUint8Array([...buf])
    expect(() => {
      br.readVarIntNum()
    }).not.toThrow('number too large to retain precision - use readVarIntBn')
  })
})

describe('#readVarIntBn', () => {
  it('should read a 1 byte varInt', () => {
    const buf = Buffer.from([50])
    const br = new ReaderUint8Array([...buf])
    expect(br.readVarIntBn().toNumber()).toEqual(50)
  })

  it('should read a 3 byte varInt', () => {
    const buf = Buffer.from([253, 253, 0])
    const br = new ReaderUint8Array([...buf])
    expect(br.readVarIntBn().toNumber()).toEqual(253)
  })

  it('should read a 5 byte varInt', () => {
    const buf = Buffer.from([254, 0, 0, 0, 0])
    buf.writeUInt32LE(50000, 1)
    const br = new ReaderUint8Array([...buf])
    expect(br.readVarIntBn().toNumber()).toEqual(50000)
  })

  it('should read a 9 byte varInt', () => {
    const buf = Buffer.concat([
      Buffer.from([255]),
      Buffer.from('ffffffffffffffff', 'hex')
    ])
    const br = new ReaderUint8Array([...buf])
    expect(br.readVarIntBn().toHex()).toEqual('ffffffffffffffff')
  })
})
