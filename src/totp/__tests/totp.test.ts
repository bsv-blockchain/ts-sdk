import { toArray } from '../../primitives/utils'
import { TOTP } from '../../totp/totp'

const secret = toArray('48656c6c6f21deadbeef', 'hex')
const period = 30 // sec
const periodMS = 30 * 1000 // ms
const options = {
  digits: 6,
  period,
  algorithm: 'SHA-1' as const
}

describe('totp generation and validation', () => {
  beforeEach(() => jest.useFakeTimers())
  afterEach(() => jest.resetAllMocks())

  test.each([
    {
      time: 0,
      expected: '282760',
      description: 'should generate token at Unix epoch start'
    },
    {
      time: 1465324707000,
      expected: '341128',
      description: 'should generate token for a specific timestamp in 2016'
    },
    {
      time: 1665644340000 + 1,
      expected: '886842',
      description: 'should generate correct token at the start of the cycle'
    },
    {
      time: 1665644340000 - 1,
      expected: '134996',
      description: 'should generate correct token at the end of the cycle'
    },
    {
      time: 1365324707000,
      expected: '089029',
      description: 'should generate token with a leading zero'
    }
  ])('$description', async ({ time, expected }) => {
    jest.setSystemTime(time)

    // check if expected passcode is generated
    const passcode = TOTP.generate(secret, options)
    expect(passcode).toEqual(expected)

    expect(TOTP.validate(secret, '000000', options)).toEqual(false) // this passcode should not be valid for any of above test cases

    // should not be valid for only a part of passcode
    expect(TOTP.validate(secret, passcode.slice(1), options)).toEqual(false)

    expect(TOTP.validate(secret, passcode, options)).toEqual(true)

    const checkAdjacentWindow = (
      timeOfGeneration: number,
      expected: boolean
    ): void => {
      jest.setSystemTime(timeOfGeneration)
      const adjacentTimewindowPasscode = TOTP.generate(secret, options)

      jest.setSystemTime(time)
      expect(
        TOTP.validate(secret, adjacentTimewindowPasscode, options)
      ).toEqual(expected)
    }

    // because the 'skew' is '1' by default, the passcode for the next window also should be valid
    checkAdjacentWindow((time as number) + periodMS, true)

    checkAdjacentWindow(time - periodMS, true)

    // for 'skew': 1, other passcodes for further timewindows should not be valid
    for (let i = 2; i < 10; i++) {
      checkAdjacentWindow((time as number) + i * periodMS, false)
      checkAdjacentWindow(time - i * periodMS, false)
    }
  })

  test('should reject wrong passcode with same length', () => {
    jest.setSystemTime(0)

    const correct = TOTP.generate(secret, options)

    // Same length but definitely wrong
    const wrong = correct === '123456' ? '654321' : '123456'

    expect(wrong.length).toBe(correct.length)
    expect(TOTP.validate(secret, wrong, options)).toBe(false)
  })

  test('should validate correct passcode using constant-time comparison', () => {
    jest.setSystemTime(0)

    const correct = TOTP.generate(secret, options)

    // Ensure the code path executes constantTimeEquals and returns true
    expect(TOTP.validate(secret, correct, options)).toBe(true)
  })
})
