import { WERR_REVIEW_ACTIONS } from '../WERR_REVIEW_ACTIONS'
import { WERR_INSUFFICIENT_FUNDS } from '../WERR_INSUFFICIENT_FUNDS'
import { WERR_INVALID_PARAMETER } from '../WERR_INVALID_PARAMETER'
import type { ReviewActionResult, SendWithResult } from '../Wallet.interfaces'

// ---------------------------------------------------------------------------
// WERR_REVIEW_ACTIONS
// ---------------------------------------------------------------------------
describe('WERR_REVIEW_ACTIONS', () => {
  const reviewActionResults: ReviewActionResult[] = [
    { txid: 'aaaa', status: 'success' }
  ]
  const sendWithResults: SendWithResult[] = [
    { txid: 'bbbb', status: 'unproven' }
  ]

  it('is an instance of Error', () => {
    const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults)
    expect(err).toBeInstanceOf(Error)
  })

  it('has the fixed message about review requirements', () => {
    const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults)
    expect(err.message).toBe(
      'Undelayed createAction or signAction results require review.'
    )
  })

  it('has code 5', () => {
    const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults)
    expect(err.code).toBe(5)
  })

  it('has name WERR_REVIEW_ACTIONS', () => {
    const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults)
    expect(err.name).toBe('WERR_REVIEW_ACTIONS')
  })

  it('has isError true', () => {
    const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults)
    expect(err.isError).toBe(true)
  })

  it('stores reviewActionResults on the instance', () => {
    const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults)
    expect(err.reviewActionResults).toEqual(reviewActionResults)
  })

  it('stores sendWithResults on the instance', () => {
    const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults)
    expect(err.sendWithResults).toEqual(sendWithResults)
  })

  it('txid defaults to undefined when not provided', () => {
    const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults)
    expect(err.txid).toBeUndefined()
  })

  it('stores optional txid when provided', () => {
    const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults, 'txid123')
    expect(err.txid).toBe('txid123')
  })

  it('tx defaults to undefined when not provided', () => {
    const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults)
    expect(err.tx).toBeUndefined()
  })

  it('stores optional tx when provided', () => {
    const tx = [0xde, 0xad, 0xbe, 0xef]
    const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults, undefined, tx)
    expect(err.tx).toEqual(tx)
  })

  it('noSendChange defaults to undefined when not provided', () => {
    const err = new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults)
    expect(err.noSendChange).toBeUndefined()
  })

  it('stores optional noSendChange when provided', () => {
    const noSendChange = ['outpoint:0', 'outpoint:1']
    const err = new WERR_REVIEW_ACTIONS(
      reviewActionResults,
      sendWithResults,
      undefined,
      undefined,
      noSendChange
    )
    expect(err.noSendChange).toEqual(noSendChange)
  })

  it('all five optional/required fields are accessible together', () => {
    const tx = [1, 2, 3]
    const noSendChange = ['out:0']
    const err = new WERR_REVIEW_ACTIONS(
      reviewActionResults,
      sendWithResults,
      'txid_full',
      tx,
      noSendChange
    )
    expect(err.reviewActionResults).toEqual(reviewActionResults)
    expect(err.sendWithResults).toEqual(sendWithResults)
    expect(err.txid).toBe('txid_full')
    expect(err.tx).toEqual(tx)
    expect(err.noSendChange).toEqual(noSendChange)
  })
})

// ---------------------------------------------------------------------------
// WERR_INSUFFICIENT_FUNDS
// ---------------------------------------------------------------------------
describe('WERR_INSUFFICIENT_FUNDS', () => {
  it('is an instance of Error', () => {
    const err = new WERR_INSUFFICIENT_FUNDS(1000, 500)
    expect(err).toBeInstanceOf(Error)
  })

  it('has code 7', () => {
    const err = new WERR_INSUFFICIENT_FUNDS(1000, 500)
    expect(err.code).toBe(7)
  })

  it('has name WERR_INSUFFICIENT_FUNDS', () => {
    const err = new WERR_INSUFFICIENT_FUNDS(1000, 500)
    expect(err.name).toBe('WERR_INSUFFICIENT_FUNDS')
  })

  it('has isError true', () => {
    const err = new WERR_INSUFFICIENT_FUNDS(1000, 500)
    expect(err.isError).toBe(true)
  })

  it('stores totalSatoshisNeeded on the instance', () => {
    const err = new WERR_INSUFFICIENT_FUNDS(2500, 1200)
    expect(err.totalSatoshisNeeded).toBe(2500)
  })

  it('stores moreSatoshisNeeded on the instance', () => {
    const err = new WERR_INSUFFICIENT_FUNDS(2500, 1200)
    expect(err.moreSatoshisNeeded).toBe(1200)
  })

  it('message contains moreSatoshisNeeded value', () => {
    const err = new WERR_INSUFFICIENT_FUNDS(3000, 750)
    expect(err.message).toContain('750')
  })

  it('message contains totalSatoshisNeeded value', () => {
    const err = new WERR_INSUFFICIENT_FUNDS(3000, 750)
    expect(err.message).toContain('3000')
  })

  it('message contains both values and key phrase', () => {
    const err = new WERR_INSUFFICIENT_FUNDS(1000, 500)
    expect(err.message).toMatch(/500 more satoshis are needed/)
    expect(err.message).toMatch(/total of 1000/)
  })

  it('handles zero values', () => {
    const err = new WERR_INSUFFICIENT_FUNDS(0, 0)
    expect(err.totalSatoshisNeeded).toBe(0)
    expect(err.moreSatoshisNeeded).toBe(0)
    expect(err.message).toContain('0')
  })
})

// ---------------------------------------------------------------------------
// WERR_INVALID_PARAMETER
// ---------------------------------------------------------------------------
describe('WERR_INVALID_PARAMETER', () => {
  it('is an instance of Error', () => {
    const err = new WERR_INVALID_PARAMETER('myParam', 'a valid string')
    expect(err).toBeInstanceOf(Error)
  })

  it('has code 6', () => {
    const err = new WERR_INVALID_PARAMETER('myParam', 'a valid string')
    expect(err.code).toBe(6)
  })

  it('has name WERR_INVALID_PARAMETER', () => {
    const err = new WERR_INVALID_PARAMETER('myParam', 'a valid string')
    expect(err.name).toBe('WERR_INVALID_PARAMETER')
  })

  it('has isError true', () => {
    const err = new WERR_INVALID_PARAMETER('myParam', 'a valid string')
    expect(err.isError).toBe(true)
  })

  it('stores parameter on the instance', () => {
    const err = new WERR_INVALID_PARAMETER('outputValue', 'a positive number')
    expect(err.parameter).toBe('outputValue')
  })

  it('message includes the parameter name and mustBe description', () => {
    const err = new WERR_INVALID_PARAMETER('amount', 'greater than zero')
    expect(err.message).toBe('The amount parameter must be greater than zero')
  })

  it('uses default mustBe text ("valid.") when mustBe is not provided', () => {
    const err = new WERR_INVALID_PARAMETER('lockingScript')
    expect(err.message).toBe('The lockingScript parameter must be valid.')
  })

  it('handles an empty string for parameter', () => {
    const err = new WERR_INVALID_PARAMETER('', 'non-empty')
    expect(err.parameter).toBe('')
    expect(err.message).toContain('non-empty')
  })
})
