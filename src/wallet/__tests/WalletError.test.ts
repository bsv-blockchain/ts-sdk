import { WalletError, walletErrors } from '../WalletError'
import { WERR_REVIEW_ACTIONS } from '../WERR_REVIEW_ACTIONS'
import { WERR_INVALID_PARAMETER } from '../WERR_INVALID_PARAMETER'
import { WERR_INSUFFICIENT_FUNDS } from '../WERR_INSUFFICIENT_FUNDS'

describe('WalletError', () => {
  describe('constructor', () => {
    it('sets message from the first argument', () => {
      const err = new WalletError('something went wrong')
      expect(err.message).toBe('something went wrong')
    })

    it('defaults code to 1 when not supplied', () => {
      const err = new WalletError('oops')
      expect(err.code).toBe(1)
    })

    it('accepts an explicit code', () => {
      const err = new WalletError('bad parameter', 6)
      expect(err.code).toBe(6)
    })

    it('sets name to the constructor name (WalletError)', () => {
      const err = new WalletError('msg')
      expect(err.name).toBe('WalletError')
    })

    it('sets isError to true', () => {
      const err = new WalletError('msg')
      expect(err.isError).toBe(true)
    })

    it('is an instance of Error', () => {
      const err = new WalletError('msg')
      expect(err).toBeInstanceOf(Error)
    })

    it('uses the provided stack when supplied', () => {
      const customStack = 'custom stack trace line 1\ncustom stack trace line 2'
      const err = new WalletError('msg', 1, customStack)
      expect(err.stack).toBe(customStack)
    })

    it('calls Error.captureStackTrace when stack is not provided', () => {
      const spy = jest.spyOn(Error, 'captureStackTrace')
      const err = new WalletError('msg')
      expect(spy).toHaveBeenCalledWith(err, WalletError)
      spy.mockRestore()
    })

    it('calls Error.captureStackTrace when stack is empty string', () => {
      const spy = jest.spyOn(Error, 'captureStackTrace')
      const err = new WalletError('msg', 1, '')
      expect(spy).toHaveBeenCalledWith(err, WalletError)
      spy.mockRestore()
    })

    it('calls Error.captureStackTrace when stack is null (cast as undefined path)', () => {
      // null is coerced via the (stack !== null) guard → falls through to captureStackTrace
      const spy = jest.spyOn(Error, 'captureStackTrace')
      const err = new WalletError('msg', 1, null as unknown as string)
      expect(spy).toHaveBeenCalledWith(err, WalletError)
      spy.mockRestore()
    })
  })

  describe('walletErrors enum', () => {
    it('has value 1 for unknownError', () => {
      expect(walletErrors.unknownError).toBe(1)
    })

    it('has value 2 for unsupportedAction', () => {
      expect(walletErrors.unsupportedAction).toBe(2)
    })

    it('has value 3 for invalidHmac', () => {
      expect(walletErrors.invalidHmac).toBe(3)
    })

    it('has value 4 for invalidSignature', () => {
      expect(walletErrors.invalidSignature).toBe(4)
    })

    it('has value 5 for reviewActions', () => {
      expect(walletErrors.reviewActions).toBe(5)
    })

    it('has value 6 for invalidParameter', () => {
      expect(walletErrors.invalidParameter).toBe(6)
    })

    it('has value 7 for insufficientFunds', () => {
      expect(walletErrors.insufficientFunds).toBe(7)
    })

    it('all values are within the UInt8 range (0-255)', () => {
      for (const val of Object.values(walletErrors).filter(v => typeof v === 'number')) {
        expect(val as number).toBeGreaterThanOrEqual(0)
        expect(val as number).toBeLessThanOrEqual(255)
      }
    })
  })

  describe('unknownToJson', () => {
    it('returns valid JSON for every error type', () => {
      const err = new WalletError('test', 1)
      const json = WalletError.unknownToJson(err)
      expect(() => JSON.parse(json)).not.toThrow()
    })

    describe('with a WERR_REVIEW_ACTIONS error', () => {
      const reviewActionResults = [{ txid: 'abc123', status: 'success' as const }]
      const sendWithResults = [{ txid: 'def456', status: 'unproven' as const }]

      it('serializes name and isError', () => {
        const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults)
        const parsed = JSON.parse(WalletError.unknownToJson(err))
        expect(parsed.name).toBe('WERR_REVIEW_ACTIONS')
        expect(parsed.isError).toBe(true)
      })

      it('includes code 5', () => {
        const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults)
        const parsed = JSON.parse(WalletError.unknownToJson(err))
        expect(parsed.code).toBe(5)
      })

      it('includes reviewActionResults and sendWithResults', () => {
        const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults)
        const parsed = JSON.parse(WalletError.unknownToJson(err))
        expect(parsed.reviewActionResults).toEqual(reviewActionResults)
        expect(parsed.sendWithResults).toEqual(sendWithResults)
      })

      it('includes optional txid when provided', () => {
        const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults, 'txid999')
        const parsed = JSON.parse(WalletError.unknownToJson(err))
        expect(parsed.txid).toBe('txid999')
      })

      it('includes optional tx when provided', () => {
        const tx = [1, 2, 3]
        const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults, undefined, tx)
        const parsed = JSON.parse(WalletError.unknownToJson(err))
        expect(parsed.tx).toEqual(tx)
      })

      it('includes optional noSendChange when provided', () => {
        const noSendChange = ['outpoint1', 'outpoint2']
        const err = new WERR_REVIEW_ACTIONS(
          reviewActionResults,
          sendWithResults,
          undefined,
          undefined,
          noSendChange
        )
        const parsed = JSON.parse(WalletError.unknownToJson(err))
        expect(parsed.noSendChange).toEqual(noSendChange)
      })

      it('omits optional fields when not provided', () => {
        const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults)
        const parsed = JSON.parse(WalletError.unknownToJson(err))
        expect(parsed.txid).toBeUndefined()
        expect(parsed.tx).toBeUndefined()
        expect(parsed.noSendChange).toBeUndefined()
      })

      it('includes message', () => {
        const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults)
        const parsed = JSON.parse(WalletError.unknownToJson(err))
        expect(typeof parsed.message).toBe('string')
        expect(parsed.message.length).toBeGreaterThan(0)
      })
    })

    describe('with a WERR_INVALID_PARAMETER error', () => {
      it('serializes name, isError, code 6, and parameter', () => {
        const err = new WERR_INVALID_PARAMETER('myParam', 'a non-empty string')
        const parsed = JSON.parse(WalletError.unknownToJson(err))
        expect(parsed.name).toBe('WERR_INVALID_PARAMETER')
        expect(parsed.isError).toBe(true)
        expect(parsed.code).toBe(6)
        expect(parsed.parameter).toBe('myParam')
      })

      it('includes message', () => {
        const err = new WERR_INVALID_PARAMETER('myParam', 'a valid value')
        const parsed = JSON.parse(WalletError.unknownToJson(err))
        expect(typeof parsed.message).toBe('string')
        expect(parsed.message).toContain('myParam')
      })
    })

    describe('with a WERR_INSUFFICIENT_FUNDS error', () => {
      it('serializes name, isError, code 7, totalSatoshisNeeded, and moreSatoshisNeeded', () => {
        const err = new WERR_INSUFFICIENT_FUNDS(1000, 500)
        const parsed = JSON.parse(WalletError.unknownToJson(err))
        expect(parsed.name).toBe('WERR_INSUFFICIENT_FUNDS')
        expect(parsed.isError).toBe(true)
        expect(parsed.code).toBe(7)
        expect(parsed.totalSatoshisNeeded).toBe(1000)
        expect(parsed.moreSatoshisNeeded).toBe(500)
      })

      it('includes message with satoshi amounts', () => {
        const err = new WERR_INSUFFICIENT_FUNDS(2000, 800)
        const parsed = JSON.parse(WalletError.unknownToJson(err))
        expect(parsed.message).toContain('2000')
        expect(parsed.message).toContain('800')
      })
    })

    describe('with a WalletError whose name does NOT start with WERR_', () => {
      it('falls through to the instanceof Error branch', () => {
        const err = new WalletError('plain wallet error', 1)
        // WalletError has isError=true but name='WalletError' (does not start with WERR_)
        const parsed = JSON.parse(WalletError.unknownToJson(err))
        expect(parsed.name).toBe('WalletError')
        expect(parsed.isError).toBe(true)
        expect(parsed.message).toBe('plain wallet error')
        // code should NOT be set by the WERR_ branch
        expect(parsed.code).toBeUndefined()
      })
    })

    describe('with a WERR_ name not matching any known subtype', () => {
      it('enters the WERR_ branch but skips all named sub-branches', () => {
        // Craft an object that satisfies isError===true and name starts with WERR_
        // but is not one of the three recognised subtypes.
        const syntheticErr = {
          isError: true,
          name: 'WERR_UNKNOWN_SUBTYPE',
          message: 'custom werr error'
        }
        const parsed = JSON.parse(WalletError.unknownToJson(syntheticErr))
        expect(parsed.name).toBe('WERR_UNKNOWN_SUBTYPE')
        expect(parsed.isError).toBe(true)
        expect(parsed.message).toBe('custom werr error')
        // No code is added because none of the named sub-branches matched
        expect(parsed.code).toBeUndefined()
      })
    })

    describe('with a plain Error', () => {
      it('serializes name, message, and isError=true', () => {
        const err = new Error('plain error')
        const parsed = JSON.parse(WalletError.unknownToJson(err))
        expect(parsed.name).toBe('Error')
        expect(parsed.message).toBe('plain error')
        expect(parsed.isError).toBe(true)
      })

      it('uses the constructor name, not the name property', () => {
        class CustomError extends Error {
          constructor (msg: string) {
            super(msg)
            this.name = 'CustomError'
          }
        }
        const err = new CustomError('custom')
        const parsed = JSON.parse(WalletError.unknownToJson(err))
        // unknownToJson uses error.constructor.name
        expect(parsed.name).toBe('CustomError')
      })
    })

    describe('with a non-Error value (string / unknown)', () => {
      it('serializes a string with name WERR_UNKNOWN', () => {
        const parsed = JSON.parse(WalletError.unknownToJson('just a string'))
        expect(parsed.name).toBe('WERR_UNKNOWN')
        expect(parsed.message).toBe('just a string')
        expect(parsed.isError).toBe(true)
      })

      it('serializes a number with name WERR_UNKNOWN', () => {
        const parsed = JSON.parse(WalletError.unknownToJson(42))
        expect(parsed.name).toBe('WERR_UNKNOWN')
        expect(parsed.message).toBe('42')
        expect(parsed.isError).toBe(true)
      })

      it('serializes a plain object with name WERR_UNKNOWN', () => {
        const parsed = JSON.parse(WalletError.unknownToJson({ weird: true }))
        expect(parsed.name).toBe('WERR_UNKNOWN')
        expect(parsed.isError).toBe(true)
      })
    })
  })
})
