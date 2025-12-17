import { SHA1HMAC, SHA256HMAC, SHA512HMAC } from '../primitives/Hash.js'
import BigNumber from '../primitives/BigNumber.js'
import { constantTimeEquals, toArray } from '../primitives/utils.js'

export type TOTPAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-512'

/**
 * Options for TOTP generation.
 * @param {number} [digits=6] - The number of digits in the OTP.
 * @param {TOTPAlgorithm} [algorithm="SHA-1"] - Algorithm used for hashing.
 * @param {number} [period=30] - The time period for OTP validity in seconds.
 * @param {number} [timestamp=Date.now()] - The current timestamp.
 */
export interface TOTPOptions {
  digits?: number
  algorithm?: TOTPAlgorithm
  period?: number
  timestamp?: number
}

/**
 * Options for TOTP validation.
 * @param {number} [skew=1] - The number of time periods to check before and after the current time period.
 */
export type TOTPValidateOptions = TOTPOptions & {
  skew?: number
}

// eslint-disable-next-line @typescript-eslint/no-extraneous-class
export class TOTP {
  /**
   * Generates a Time-based One-Time Password (TOTP).
   * @param {number[]} secret - The secret key for TOTP.
   * @param {TOTPOptions} options - Optional parameters for TOTP.
   * @returns {string} The generated TOTP.
   */
  static generate (secret: number[], options?: TOTPOptions): string {
    const _options = this.withDefaultOptions(options)

    const counter = this.getCounter(_options.timestamp, _options.period)
    const otp = generateHOTP(secret, counter, _options)
    return otp
  }

  /**
   * Validates a Time-based One-Time Password (TOTP).
   * @param {number[]} secret - The secret key for TOTP.
   * @param {string} passcode - The passcode to validate.
   * @param {TOTPValidateOptions} options - Optional parameters for TOTP validation.
   * @returns {boolean} A boolean indicating whether the passcode is valid.
   */
  static validate (
    secret: number[],
    passcode: string,
    options?: TOTPValidateOptions
  ): boolean {
    const _options = this.withDefaultValidateOptions(options)
    passcode = passcode.trim()
    if (passcode.length !== _options.digits) {
      return false
    }

    const counter = this.getCounter(_options.timestamp, _options.period)

    const counters = [counter]
    for (let i = 1; i <= _options.skew; i++) {
      counters.push(counter + i)
      counters.push(counter - i)
    }

    for (const c of counters) {
      const expected = generateHOTP(secret, c, _options)

      if (
        constantTimeEquals(
          toArray(passcode, 'utf8'),
          toArray(expected, 'utf8')
        )
      ) {
        return true
      }
    }

    return false
  }

  private static getCounter (timestamp: number, period: number): number {
    const epochSeconds = Math.floor(timestamp / 1000)
    const counter = Math.floor(epochSeconds / period)
    return counter
  }

  private static withDefaultOptions (
    options?: TOTPOptions
  ): Required<TOTPOptions> {
    return {
      digits: 2,
      algorithm: 'SHA-1',
      period: 30,
      timestamp: Date.now(),
      ...options
    }
  }

  private static withDefaultValidateOptions (
    options?: TOTPValidateOptions
  ): Required<TOTPValidateOptions> {
    return { skew: 1, ...this.withDefaultOptions(options) }
  }
}

function generateHOTP (
  secret: number[],
  counter: number,
  options: Required<TOTPOptions>
): string {
  const timePad = new BigNumber(counter).toArray('be', 8)
  const hmac = calcHMAC(secret, timePad, options.algorithm)
  const signature = hmac.digest()

  // RFC 4226 https://datatracker.ietf.org/doc/html/rfc4226#section-5.4
  const offset = signature[signature.length - 1] & 0x0f // offset is the last byte in the hmac
  const fourBytesRange = signature.slice(offset, offset + 4) // starting from offset, get 4 bytes
  const mask = 0x7fffffff // 32-bit number with a leading 0 followed by 31 ones [0111 (...) 1111]
  const masked = new BigNumber(fourBytesRange).toNumber() & mask

  const otp = masked.toString().slice(-options.digits)
  return otp
}

function calcHMAC (
  secret: number[],
  timePad: number[],
  algorithm: TOTPAlgorithm
): SHA1HMAC | SHA256HMAC | SHA512HMAC {
  switch (algorithm) {
    case 'SHA-1':
      return new SHA1HMAC(secret).update(timePad)
    case 'SHA-256':
      return new SHA256HMAC(secret).update(timePad)
    case 'SHA-512':
      return new SHA512HMAC(secret).update(timePad)
    default:
      throw new Error('unsupported HMAC algorithm')
  }
}
