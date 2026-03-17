import BigNumber from '../../primitives/BigNumber'

describe('BN.js/Constructor', () => {
  describe('with Smi input', () => {
    it('should accept one limb number', () => {
      expect(new BigNumber(12345).toString(16)).toEqual('3039')
    })

    it('should accept two-limb number', () => {
      expect(new BigNumber(0x4123456).toString(16)).toEqual('4123456')
    })

    it('should accept 52 bits of precision', () => {
      const num = Math.pow(2, 52)
      expect(new BigNumber(num, 10).toString(10)).toEqual(num.toString(10))
    })

    it('should accept max safe integer', () => {
      const num = Math.pow(2, 53) - 1
      expect(new BigNumber(num, 10).toString(10)).toEqual(num.toString(10))
    })

    it('should not accept an unsafe integer', () => {
      const num = Math.pow(2, 53)

      expect(() => {
        return new BigNumber(num, 10)
      }).toThrow(new Error('The number is larger than 2 ^ 53 (unsafe)'))
    })

    it('should accept two-limb LE number', () => {
      expect(new BigNumber(0x4123456, undefined, 'le').toString(16)).toEqual(
        '56341204'
      )
    })
  })

  describe('with String input', () => {
    it('should accept base-16', () => {
      expect(new BigNumber('1A6B765D8CDF', 16).toString(16)).toEqual(
        '1a6b765d8cdf'
      )
      expect(new BigNumber('1A6B765D8CDF', 16).toString()).toEqual(
        '29048849665247'
      )
    })

    it('should accept base-hex', () => {
      expect(new BigNumber('FF', 'hex').toString()).toEqual('255')
    })

    it('should accept base-16 with spaces', () => {
      const num = 'a89c e5af8724 c0a23e0e 0ff77500'
      expect(new BigNumber(num, 16).toString(16)).toEqual(
        num.replace(/ /g, '')
      )
    })

    it('should accept long base-16', () => {
      const num = '123456789abcdef123456789abcdef123456789abcdef'
      expect(new BigNumber(num, 16).toString(16)).toEqual(num)
    })

    it('should accept positive base-10', () => {
      expect(new BigNumber('10654321').toString()).toEqual('10654321')
      expect(new BigNumber('29048849665247').toString(16)).toEqual(
        '1a6b765d8cdf'
      )
    })

    it('should accept negative base-10', () => {
      expect(new BigNumber('-29048849665247').toString(16)).toEqual(
        '-1a6b765d8cdf'
      )
    })

    it('should accept long base-10', () => {
      const num = '10000000000000000'
      expect(new BigNumber(num).toString(10)).toEqual(num)
    })

    it('should accept base-2', () => {
      const base2 = '11111111111111111111111111111111111111111111111111111'
      expect(new BigNumber(base2, 2).toString(2)).toEqual(base2)
    })

    it('should accept base-36', () => {
      const base36 = 'zzZzzzZzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'
      expect(new BigNumber(base36, 36).toString(36)).toEqual(
        base36.toLowerCase()
      )
    })

    it('should not overflow limbs during base-10', () => {
      const num =
        '65820182292848241686198767302293' + '20890292528855852623664389292032'
      expect(new BigNumber(num).words[0]).toBeLessThan(0x4000000)
    })

    it('should accept base-16 LE integer', () => {
      expect(new BigNumber('1A6B765D8CDF', 16, 'le').toString(16)).toEqual(
        'df8c5d766b1a'
      )
    })

    it('should accept base-16 LE integer with leading zeros', () => {
      expect(new BigNumber('0010', 16, 'le').toNumber()).toEqual(4096)
      expect(new BigNumber('-010', 16, 'le').toNumber()).toEqual(-4096)
      expect(new BigNumber('010', 16, 'le').toNumber()).toEqual(4096)
    })

    it('should not accept wrong characters for base', () => {
      expect(() => {
        return new BigNumber('01FF')
      }).toThrow(new Error('Invalid character'))
    })

    it('should not accept decimal', () => {
      expect(() => {
        return new BigNumber('10.00', 10)
      }).toThrow(new Error('Invalid character'))

      expect(() => {
        return new BigNumber('16.00', 16)
      }).toThrow(/* new Error('Invalid character') */)
    })

    it('should not accept non-hex characters', () => {
      [
        '0000000z',
        '000000gg',
        '0000gg00',
        'fffggfff',
        '/0000000',
        '0-000000', // if -, is first, that is OK
        'ff.fffff',
        'hexadecimal'
      ].forEach(function (str) {
        expect(() => {
          return new BigNumber(str, 16)
        }).toThrow(/* Invalid character in */)
      })
    })
  })

  describe('with Array input', () => {
    it('should not fail on empty array', () => {
      expect(new BigNumber([]).toString(16)).toEqual('0')
    })

    it('should import/export big endian', () => {
      expect(new BigNumber([0, 1], 16).toString(16)).toEqual('1')
      expect(new BigNumber([1, 2, 3]).toString(16)).toEqual('10203')
      expect(new BigNumber([1, 2, 3, 4]).toString(16)).toEqual('1020304')
      expect(new BigNumber([1, 2, 3, 4, 5]).toString(16)).toEqual('102030405')
      expect(new BigNumber([1, 2, 3, 4, 5, 6, 7, 8]).toString(16)).toEqual(
        '102030405060708'
      )
      expect(new BigNumber([1, 2, 3, 4]).toArray().join(',')).toEqual(
        '1,2,3,4'
      )
      expect(
        new BigNumber([1, 2, 3, 4, 5, 6, 7, 8]).toArray().join(',')
      ).toEqual('1,2,3,4,5,6,7,8')
    })

    it('should import little endian', () => {
      expect(new BigNumber([0, 1], 16, 'le').toString(16)).toEqual('100')
      expect(new BigNumber([1, 2, 3], 16, 'le').toString(16)).toEqual('30201')
      expect(new BigNumber([1, 2, 3, 4], 16, 'le').toString(16)).toEqual(
        '4030201'
      )
      expect(new BigNumber([1, 2, 3, 4, 5], 16, 'le').toString(16)).toEqual(
        '504030201'
      )
      expect(
        new BigNumber([1, 2, 3, 4, 5, 6, 7, 8], 'le').toString(16)
      ).toEqual('807060504030201')
      expect(new BigNumber([1, 2, 3, 4]).toArray('le').join(',')).toEqual(
        '4,3,2,1'
      )
      expect(
        new BigNumber([1, 2, 3, 4, 5, 6, 7, 8]).toArray('le').join(',')
      ).toEqual('8,7,6,5,4,3,2,1')
    })

    it('should import big endian with implicit base', () => {
      expect(new BigNumber([1, 2, 3, 4, 5], 'le').toString(16)).toEqual(
        '504030201'
      )
    })
  })

  describe('with Buffer input', () => {
    it('should not fail on empty Buffer', () => {
      expect(
        new BigNumber(Buffer.alloc(0).toString('hex') === '' ? '0' : Buffer.alloc(0).toString('hex')).toString(16)
      ).toEqual('0')
    })

    it('should import/export big endian', () => {
      expect(
        new BigNumber(
          Buffer.from('010203', 'hex').toString('hex'),
          16
        ).toString(16)
      ).toEqual('10203')
    })

    it('should import little endian', () => {
      expect(
        new BigNumber([...Buffer.from('010203', 'hex')], 'le').toString(16)
      ).toEqual('30201')
    })
  })
})
