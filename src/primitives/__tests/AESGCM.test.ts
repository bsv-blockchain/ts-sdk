/* eslint-env jest */
import {
  AES,
  AESGCM,
  ghash,
  rightShift,
  multiply,
  incrementLeastSignificantThirtyTwoBits,
  checkBit,
  getBytes,
  exclusiveOR,
  AESGCMDecrypt
} from '../../primitives/AESGCM'
import { toArray } from '../../primitives/utils'

describe('AES', () => {
  it('should encrypt: AES-128', () => {
    expect(toArray('69c4e0d86a7b0430d8cdb78070b4c55a', 'hex')).toEqual(
      AES(
        toArray('00112233445566778899aabbccddeeff', 'hex'),
        toArray('000102030405060708090a0b0c0d0e0f', 'hex')
      )
    )
  })

  it('should encrypt: AES-192', () => {
    expect(toArray('dda97ca4864cdfe06eaf70a0ec0d7191', 'hex')).toEqual(
      AES(
        toArray('00112233445566778899aabbccddeeff', 'hex'),
        toArray('000102030405060708090a0b0c0d0e0f1011121314151617', 'hex')
      )
    )
  })

  it('should encrypt: AES-256', () => {
    expect(toArray('8ea2b7ca516745bfeafc49904b496089', 'hex')).toEqual(
      AES(
        toArray('00112233445566778899aabbccddeeff', 'hex'),
        toArray(
          '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
          'hex'
        )
      )
    )
  })

  it('should encrypt', () => {
    expect(toArray('66e94bd4ef8a2c3b884cfa59ca342b2e', 'hex')).toEqual(
      AES(
        toArray('00000000000000000000000000000000', 'hex'),
        toArray('00000000000000000000000000000000', 'hex')
      )
    )
    expect(toArray('c6a13b37878f5b826f4f8162a1c8d879', 'hex')).toEqual(
      AES(
        toArray('00000000000000000000000000000000', 'hex'),
        toArray('000102030405060708090a0b0c0d0e0f', 'hex')
      )
    )
    expect(toArray('73a23d80121de2d5a850253fcf43120e', 'hex')).toEqual(
      AES(
        toArray('00000000000000000000000000000000', 'hex'),
        toArray('ad7a2bd03eac835a6f620fdcb506b345', 'hex')
      )
    )
  })
})

describe('ghash', () => {
  it('should ghash', () => {
    expect(toArray('f38cbb1ad69223dcc3457ae5b6b0f885', 'hex')).toEqual(
      ghash(
        toArray(
          '000000000000000000000000000000000388dace60b6a392f328c2b971b2fe780000000000000000000000' +
            '0000000080',
          'hex'
        ),
        toArray('66e94bd4ef8a2c3b884cfa59ca342b2e', 'hex')
      )
    )
  })
})

describe('AESGCM', () => {
  it('should encrypt: Test Case 1', () => {
    const output = AESGCM(
      [],
      [],
      toArray('000000000000000000000000', 'hex'),
      toArray('00000000000000000000000000000000', 'hex')
    )

    expect([]).toEqual(output.result)
    expect(toArray('58e2fccefa7e3061367f1d57a4e7455a', 'hex')).toEqual(
      output.authenticationTag
    )
  })

  it('should encrypt: Test Case 2', () => {
    const output = AESGCM(
      toArray('00000000000000000000000000000000', 'hex'),
      [],
      toArray('000000000000000000000000', 'hex'),
      toArray('00000000000000000000000000000000', 'hex')
    )

    expect(toArray('0388dace60b6a392f328c2b971b2fe78', 'hex')).toEqual(
      output.result
    )
    expect(toArray('ab6e47d42cec13bdf53a67b21257bddf', 'hex')).toEqual(
      output.authenticationTag
    )
  })

  it('should encrypt: Test Case 3', () => {
    const output = AESGCM(
      toArray(
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956' +
          '809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
        'hex'
      ),
      [],
      toArray('cafebabefacedbaddecaf888', 'hex'),
      toArray('feffe9928665731c6d6a8f9467308308', 'hex')
    )

    expect(
      toArray(
        '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8' +
          'f6a5aac84aa051ba30b396a0aac973d58e091473f5985',
        'hex'
      )
    ).toEqual(output.result)
    expect(toArray('4d5c2af327cd64a62cf35abd2ba6fab4', 'hex')).toEqual(
      output.authenticationTag
    )
  })

  it('should encrypt: Test Case 4', () => {
    const output = AESGCM(
      toArray(
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956' +
          '809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'hex'
      ),
      toArray('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex'),
      toArray('cafebabefacedbaddecaf888', 'hex'),
      toArray('feffe9928665731c6d6a8f9467308308', 'hex')
    )
    expect(
      toArray(
        '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8' +
          'f6a5aac84aa051ba30b396a0aac973d58e091',
        'hex'
      )
    ).toEqual(output.result)
    expect(toArray('5bc94fbc3221a5db94fae95ae7121a47', 'hex')).toEqual(
      output.authenticationTag
    )
  })

  it('should encrypt: Test Case 5', () => {
    const output = AESGCM(
      toArray(
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956' +
          '809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'hex'
      ),
      toArray('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex'),
      toArray('cafebabefacedbad', 'hex'),
      toArray('feffe9928665731c6d6a8f9467308308', 'hex')
    )

    expect(
      toArray(
        '61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b0' +
          '97544d4896b424989b5e1ebac0f07c23f4598',
        'hex'
      )
    ).toEqual(output.result)
    expect(toArray('3612d2e79e3b0785561be14aaca2fccb', 'hex')).toEqual(
      output.authenticationTag
    )
  })

  it('should encrypt: Test Case 6', () => {
    const output = AESGCM(
      toArray(
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956' +
          '809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'hex'
      ),
      toArray('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex'),
      toArray(
        '9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416' +
          'aedbf5a0de6a57a637b39b',
        'hex'
      ),
      toArray('feffe9928665731c6d6a8f9467308308', 'hex')
    )

    expect(
      toArray(
        '8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccd' +
          'cb281d48c7c6fd62875d2aca417034c34aee5',
        'hex'
      )
    ).toEqual(output.result)
    expect(toArray('619cc5aefffe0bfa462af43c1699d050', 'hex')).toEqual(
      output.authenticationTag
    )
  })

  it('should encrypt: Test Case 7', () => {
    const output = AESGCM(
      [],
      [],
      toArray('000000000000000000000000', 'hex'),
      toArray('000000000000000000000000000000000000000000000000', 'hex')
    )

    expect([]).toEqual(output.result)
    expect(toArray('cd33b28ac773f74ba00ed1f312572435', 'hex')).toEqual(
      output.authenticationTag
    )
  })

  it('should encrypt: Test Case 8', () => {
    const output = AESGCM(
      toArray('00000000000000000000000000000000', 'hex'),
      [],
      toArray('000000000000000000000000', 'hex'),
      toArray('000000000000000000000000000000000000000000000000', 'hex')
    )

    expect(toArray('98e7247c07f0fe411c267e4384b0f600', 'hex')).toEqual(
      output.result
    )
    expect(toArray('2ff58d80033927ab8ef4d4587514f0fb', 'hex')).toEqual(
      output.authenticationTag
    )
  })

  it('should encrypt: Test Case 9', () => {
    const output = AESGCM(
      toArray(
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956' +
          '809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
        'hex'
      ),
      [],
      toArray('cafebabefacedbaddecaf888', 'hex'),
      toArray('feffe9928665731c6d6a8f9467308308feffe9928665731c', 'hex')
    )

    expect(
      toArray(
        '3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac6' +
          '19d18c84a3f4718e2448b2fe324d9ccda2710acade256',
        'hex'
      )
    ).toEqual(output.result)
    expect(toArray('9924a7c8587336bfb118024db8674a14', 'hex')).toEqual(
      output.authenticationTag
    )
  })

  it('should encrypt: Test Case 10', () => {
    const output = AESGCM(
      toArray(
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956' +
          '809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'hex'
      ),
      toArray('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex'),
      toArray('cafebabefacedbaddecaf888', 'hex'),
      toArray('feffe9928665731c6d6a8f9467308308feffe9928665731c', 'hex')
    )

    expect(
      toArray(
        '3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac6' +
          '19d18c84a3f4718e2448b2fe324d9ccda2710',
        'hex'
      )
    ).toEqual(output.result)
    expect(toArray('2519498e80f1478f37ba55bd6d27618c', 'hex')).toEqual(
      output.authenticationTag
    )
  })

  it('should encrypt: Test Case 11', () => {
    const output = AESGCM(
      toArray(
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956' +
          '809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'hex'
      ),
      toArray('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex'),
      toArray('cafebabefacedbad', 'hex'),
      toArray('feffe9928665731c6d6a8f9467308308feffe9928665731c', 'hex')
    )

    expect(
      toArray(
        '0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66' +
          '541d4d4dad1c9e93a19a58e8b473fa0f062f7',
        'hex'
      )
    ).toEqual(output.result)
    expect(toArray('65dcc57fcf623a24094fcca40d3533f8', 'hex')).toEqual(
      output.authenticationTag
    )
  })

  it('should encrypt: Test Case 12', () => {
    const output = AESGCM(
      toArray(
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956' +
          '809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'hex'
      ),
      toArray('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex'),
      toArray(
        '9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b5254' +
          '16aedbf5a0de6a57a637b39b',
        'hex'
      ),
      toArray('feffe9928665731c6d6a8f9467308308feffe9928665731c', 'hex')
    )

    expect(
      toArray(
        'd27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f' +
          '037589b292db3e67c036745fa22e7e9b7373b',
        'hex'
      )
    ).toEqual(output.result)
    expect(toArray('dcf566ff291c25bbb8568fc3d376a6d9', 'hex')).toEqual(
      output.authenticationTag
    )
  })

  it('should encrypt: Test Case 13', () => {
    const output = AESGCM(
      [],
      [],
      toArray('000000000000000000000000', 'hex'),
      toArray(
        '0000000000000000000000000000000000000000000000000000000000000000',
        'hex'
      )
    )

    expect([]).toEqual(output.result)
    expect(toArray('530f8afbc74536b9a963b4f1c4cb738b', 'hex')).toEqual(
      output.authenticationTag
    )
  })

  it('should encrypt: Test Case 14', () => {
    const output = AESGCM(
      toArray('00000000000000000000000000000000', 'hex'),
      [],
      toArray('000000000000000000000000', 'hex'),
      toArray(
        '0000000000000000000000000000000000000000000000000000000000000000',
        'hex'
      )
    )

    expect(toArray('cea7403d4d606b6e074ec5d3baf39d18', 'hex')).toEqual(
      output.result
    )
    expect(toArray('d0d1c8a799996bf0265b98b5d48ab919', 'hex')).toEqual(
      output.authenticationTag
    )
  })

  it('should encrypt: Test Case 15', () => {
    const output = AESGCM(
      toArray(
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956' +
          '809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
        'hex'
      ),
      [],
      toArray('cafebabefacedbaddecaf888', 'hex'),
      toArray(
        'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
        'hex'
      )
    )

    expect(
      toArray(
        '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b' +
          '08b1056828838c5f61e6393ba7a0abcc9f662898015ad',
        'hex'
      )
    ).toEqual(output.result)
    expect(toArray('b094dac5d93471bdec1a502270e3cc6c', 'hex')).toEqual(
      output.authenticationTag
    )
  })

  it('should encrypt: Test Case 16', () => {
    const output = AESGCM(
      toArray(
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956' +
          '809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'hex'
      ),
      toArray('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex'),
      toArray('cafebabefacedbaddecaf888', 'hex'),
      toArray(
        'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
        'hex'
      )
    )

    expect(
      toArray(
        '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b' +
          '08b1056828838c5f61e6393ba7a0abcc9f662',
        'hex'
      )
    ).toEqual(output.result)
    expect(toArray('76fc6ece0f4e1768cddf8853bb2d551b', 'hex')).toEqual(
      output.authenticationTag
    )
  })

  it('should encrypt: Test Case 17', () => {
    const output = AESGCM(
      toArray(
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956' +
          '809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'hex'
      ),
      toArray('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex'),
      toArray('cafebabefacedbad', 'hex'),
      toArray(
        'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
        'hex'
      )
    )

    expect(
      toArray(
        'c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954' +
          'cc2363bc73f7862ac430e64abe499f47c9b1f',
        'hex'
      )
    ).toEqual(output.result)
    expect(toArray('3a337dbf46a792c45e454913fe2ea8f2', 'hex')).toEqual(
      output.authenticationTag
    )
  })

  it('should encrypt: Test Case 18', () => {
    const output = AESGCM(
      toArray(
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956' +
          '809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'hex'
      ),
      toArray('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex'),
      toArray(
        '9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416' +
          'aedbf5a0de6a57a637b39b',
        'hex'
      ),
      toArray(
        'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
        'hex'
      )
    )

    expect(
      toArray(
        '5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da' +
          '3ebf1c5d82cdea2418997200ef82e44ae7e3f',
        'hex'
      )
    ).toEqual(output.result)
    expect(toArray('a44a8266ee1c8eb0c8b5d4cf5ae9f19a', 'hex')).toEqual(
      output.authenticationTag
    )
  })
})

describe('exclusiveOR', () => {
  it('should exclusiveOR', () => {
    expect([
      0xff, 0xf7, 0x7f, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00
    ]).toEqual(
      exclusiveOR(
        [
          0xf0, 0xf8, 0x7f, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00
        ],
        [0x0f, 0x0f, 0x00, 0xf0]
      )
    )

    expect([0xff, 0xf7, 0x7f, 0x0f]).toEqual(
      exclusiveOR([0xf0, 0xf8, 0x7f, 0xff], [0x0f, 0x0f, 0x00, 0xf0])
    )
  })
})

describe('rightShift', () => {
  it('should rightShift', () => {
    expect(toArray('3dadaa32b9ba2b32b1ba37b92ea9a3ae', 'hex')).toEqual(
      rightShift(toArray('7b5b54657374566563746f725d53475d', 'hex'))
    )
  })
})

describe('multiply', () => {
  it('should multiply', () => {
    expect(toArray('da53eb0ad2c55bb64fc4802cc3feda60', 'hex')).toEqual(
      multiply(
        toArray('952b2a56a5604ac0b32b6656a05b40b6', 'hex'),
        toArray('dfa6bf4ded81db03ffcaff95f830f061', 'hex')
      )
    )
  })

  it('should commutatively multiply', () => {
    expect(
      multiply(
        toArray('48692853686179295b477565726f6e5d', 'hex'),
        toArray('7b5b54657374566563746f725d53475d', 'hex')
      )
    ).toEqual(
      multiply(
        toArray('7b5b54657374566563746f725d53475d', 'hex'),
        toArray('48692853686179295b477565726f6e5d', 'hex')
      )
    )
  })
})

describe('incrementLeastSignificantThirtyTwoBits', () => {
  it('should incrementLeastSignificantThirtyTwoBits', () => {
    expect(toArray('00000000000000000000000000000001', 'hex')).toEqual(
      incrementLeastSignificantThirtyTwoBits(
        toArray('00000000000000000000000000000000', 'hex')
      )
    )
    expect(toArray('00000000000000000000000000000100', 'hex')).toEqual(
      incrementLeastSignificantThirtyTwoBits(
        toArray('000000000000000000000000000000ff', 'hex')
      )
    )
    expect(toArray('00000000000000000000000001000000', 'hex')).toEqual(
      incrementLeastSignificantThirtyTwoBits(
        toArray('00000000000000000000000000ffffff', 'hex')
      )
    )
    expect(toArray('00000000000000000000000000000000', 'hex')).toEqual(
      incrementLeastSignificantThirtyTwoBits(
        toArray('000000000000000000000000ffffffff', 'hex')
      )
    )
  })
})

describe('checkBit', () => {
  it('should checkBit', () => {
    let i
    let j
    let k = 0
    let block = toArray('7b5b54657374566563746f725d53475d', 'hex')
    const expected = [
      0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0,
      1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1,
      0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1,
      1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1,
      1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1,
      1, 0, 1
    ]
    const expectedLSB = expected.slice().reverse()

    for (i = 0; i < 16; i++) {
      for (j = 7; j !== -1; j--) {
        expect(expected[k++]).toEqual(checkBit(block, i, j))
      }
    }

    for (i = 0; i < 128; i++) {
      expect(expectedLSB[i]).toEqual(checkBit(block, 15, 0))
      block = rightShift(block)
    }
  })
  it('should get bit', () => {
    expect(0).toEqual(checkBit([0], 0, 7))
    expect(0).toEqual(checkBit([0], 0, 6))
    expect(0).toEqual(checkBit([0], 0, 5))
    expect(0).toEqual(checkBit([0], 0, 4))
    expect(0).toEqual(checkBit([0], 0, 3))
    expect(0).toEqual(checkBit([0], 0, 2))
    expect(0).toEqual(checkBit([0], 0, 1))
    expect(0).toEqual(checkBit([0], 0, 0))

    expect(0).toEqual(checkBit([85], 0, 7))
    expect(1).toEqual(checkBit([85], 0, 6))
    expect(0).toEqual(checkBit([85], 0, 5))
    expect(1).toEqual(checkBit([85], 0, 4))
    expect(0).toEqual(checkBit([85], 0, 3))
    expect(1).toEqual(checkBit([85], 0, 2))
    expect(0).toEqual(checkBit([85], 0, 1))
    expect(1).toEqual(checkBit([85], 0, 0))

    expect(1).toEqual(checkBit([170], 0, 7))
    expect(0).toEqual(checkBit([170], 0, 6))
    expect(1).toEqual(checkBit([170], 0, 5))
    expect(0).toEqual(checkBit([170], 0, 4))
    expect(1).toEqual(checkBit([170], 0, 3))
    expect(0).toEqual(checkBit([170], 0, 2))
    expect(1).toEqual(checkBit([170], 0, 1))
    expect(0).toEqual(checkBit([170], 0, 0))

    expect(1).toEqual(checkBit([255], 0, 7))
    expect(1).toEqual(checkBit([255], 0, 6))
    expect(1).toEqual(checkBit([255], 0, 5))
    expect(1).toEqual(checkBit([255], 0, 4))
    expect(1).toEqual(checkBit([255], 0, 3))
    expect(1).toEqual(checkBit([255], 0, 2))
    expect(1).toEqual(checkBit([255], 0, 1))
    expect(1).toEqual(checkBit([255], 0, 0))
  })
})

describe('getBytes', () => {
  it('should getBytes', () => {
    expect([0x00, 0x00, 0x00, 0x00]).toEqual(getBytes(0x00))
    expect([0x00, 0x00, 0x02, 0x01]).toEqual(getBytes(0x0201))
    expect([0x04, 0x03, 0x02, 0x01]).toEqual(getBytes(0x04030201))
    expect([0x04, 0x03, 0x02, 0x01]).toEqual(getBytes(0x0504030201))
  })
})

describe('AESGCM IV validation', () => {
  const key = new Array(16).fill(0x01)
  const aad: number[] = []
  const plaintext = [1, 2, 3, 4]

  it('AESGCM throws when IV is empty', () => {
    expect(() => {
      AESGCM(plaintext, aad, [], key)
    }).toThrow(new Error('Initialization vector must not be empty'))
  })

  it('AESGCMDecrypt throws when IV is empty', () => {
    const iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    const { result: ciphertext, authenticationTag } = AESGCM(plaintext, aad, iv, key)

    // Now call decrypt but with an empty IV – this should be rejected
    expect(() => {
      AESGCMDecrypt(ciphertext, aad, [], authenticationTag, key)
    }).toThrow(new Error('Initialization vector must not be empty'))
  })

  it('AESGCM throws when key is empty', () => {
    const iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]

    expect(() => {
      AESGCM(plaintext, aad, iv, [])
    }).toThrow(new Error('Key must not be empty'))
  })

  it('AESGCMDecrypt throws when key is empty', () => {
    const iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    const { result: ciphertext, authenticationTag } = AESGCM(plaintext, aad, iv, key)

    expect(() => {
      AESGCMDecrypt(ciphertext, aad, iv, authenticationTag, [])
    }).toThrow(new Error('Key must not be empty'))
  })

  it('AESGCMDecrypt throws when cipher text is empty', () => {
    const iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]

    expect(() => {
      AESGCMDecrypt([], aad, iv, [], key)
    }).toThrow(new Error('Cipher text must not be empty'))
  })

  it('AESGCM still work with a valid IV', () => {
    const iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    const { result: ciphertext, authenticationTag } = AESGCM(plaintext, aad, iv, key)
    const decrypted = AESGCMDecrypt(ciphertext, aad, iv, authenticationTag, key)

    expect(decrypted).toEqual(plaintext)
  })
})
