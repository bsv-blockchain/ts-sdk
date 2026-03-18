/** eslint-env jest */
import { withDoubleSpendRetry } from '../withDoubleSpendRetry'
import { WERR_REVIEW_ACTIONS } from '../../wallet/WERR_REVIEW_ACTIONS'
import Transaction from '../../transaction/Transaction'
import { ReviewActionResult } from '../../wallet/Wallet.interfaces'
import TopicBroadcaster from '../SHIPBroadcaster'

// --- Module mocks -----------------------------------------------------------

jest.mock('../../transaction/Transaction.js', () => ({
  fromBEEF: jest.fn()
}))

jest.mock('../SHIPBroadcaster.js', () => {
  return jest.fn().mockImplementation(() => ({
    broadcast: jest.fn()
  }))
})

// --- Typed mock refs --------------------------------------------------------

const MockedTransaction = Transaction as jest.Mocked<typeof Transaction>

// --- Helpers ----------------------------------------------------------------

const MAX_DOUBLE_SPEND_RETRIES = 5

function makeMockBroadcaster (): jest.Mocked<TopicBroadcaster> {
  return {
    broadcast: jest.fn()
  } as unknown as jest.Mocked<TopicBroadcaster>
}

function makeDoubleSpendError (
  competingBeef: number[] | null = [0x01, 0x02],
  competingTxs: string[] | null = ['competingtxid111111111111111111111111111111111111111111111111111111']
): WERR_REVIEW_ACTIONS {
  const result: ReviewActionResult = {
    txid: 'originaltxid1111111111111111111111111111111111111111111111111111111',
    status: 'doubleSpend',
    ...(competingBeef != null && { competingBeef }),
    ...(competingTxs != null && { competingTxs })
  }
  return new WERR_REVIEW_ACTIONS([result], [])
}

function makeNonDoubleSpendError (name: string = 'WERR_REVIEW_ACTIONS'): WERR_REVIEW_ACTIONS {
  const result: ReviewActionResult = {
    txid: 'originaltxid1111111111111111111111111111111111111111111111111111111',
    status: 'serviceError'
  }
  const err = new WERR_REVIEW_ACTIONS([result], [])
  err.name = name
  return err
}

// --- Tests ------------------------------------------------------------------

describe('withDoubleSpendRetry', () => {
  let broadcaster: jest.Mocked<TopicBroadcaster>
  let mockCompetingTx: Partial<Transaction>

  beforeEach(() => {
    jest.clearAllMocks()
    broadcaster = makeMockBroadcaster()
    mockCompetingTx = {}
    ;(MockedTransaction.fromBEEF as jest.Mock).mockReturnValue(mockCompetingTx as Transaction)
  })

  // --- Happy path -----------------------------------------------------------

  describe('succeeds without retry', () => {
    it('returns operation result immediately on first successful attempt', async () => {
      const expectedResult = { success: true }
      const operation = jest.fn().mockResolvedValue(expectedResult)

      const result = await withDoubleSpendRetry(operation, broadcaster)

      expect(result).toBe(expectedResult)
      expect(operation).toHaveBeenCalledTimes(1)
      expect(broadcaster.broadcast).not.toHaveBeenCalled()
    })

    it('returns operation result for non-object results (string)', async () => {
      const operation = jest.fn().mockResolvedValue('done')

      const result = await withDoubleSpendRetry(operation, broadcaster)

      expect(result).toBe('done')
      expect(operation).toHaveBeenCalledTimes(1)
    })

    it('returns operation result for undefined', async () => {
      const operation = jest.fn().mockResolvedValue(undefined)

      const result = await withDoubleSpendRetry(operation, broadcaster)

      expect(result).toBeUndefined()
      expect(operation).toHaveBeenCalledTimes(1)
    })
  })

  // --- Non-double-spend errors rethrown immediately -------------------------

  describe('rethrows non-WERR_REVIEW_ACTIONS errors immediately', () => {
    it('rethrows a plain Error without retrying', async () => {
      const plainError = new Error('Network error')
      const operation = jest.fn().mockRejectedValue(plainError)

      await expect(withDoubleSpendRetry(operation, broadcaster)).rejects.toThrow('Network error')
      expect(operation).toHaveBeenCalledTimes(1)
      expect(broadcaster.broadcast).not.toHaveBeenCalled()
    })

    it('rethrows errors with other error names without retrying', async () => {
      const otherError = new Error('other error')
      otherError.name = 'SOME_OTHER_ERROR'
      const operation = jest.fn().mockRejectedValue(otherError)

      await expect(withDoubleSpendRetry(operation, broadcaster)).rejects.toThrow('other error')
      expect(operation).toHaveBeenCalledTimes(1)
      expect(broadcaster.broadcast).not.toHaveBeenCalled()
    })
  })

  // --- WERR_REVIEW_ACTIONS without doubleSpend rethrown immediately ---------

  describe('rethrows WERR_REVIEW_ACTIONS that do not represent a valid doubleSpend', () => {
    it('rethrows WERR_REVIEW_ACTIONS with no doubleSpend result in reviewActionResults', async () => {
      const error = makeNonDoubleSpendError()
      const operation = jest.fn().mockRejectedValue(error)

      await expect(withDoubleSpendRetry(operation, broadcaster)).rejects.toThrow(error)
      expect(operation).toHaveBeenCalledTimes(1)
      expect(broadcaster.broadcast).not.toHaveBeenCalled()
    })

    it('rethrows WERR_REVIEW_ACTIONS where doubleSpend result has no competingBeef', async () => {
      const error = makeDoubleSpendError(null, ['competingtxid'])
      const operation = jest.fn().mockRejectedValue(error)

      await expect(withDoubleSpendRetry(operation, broadcaster)).rejects.toThrow(error)
      expect(operation).toHaveBeenCalledTimes(1)
      expect(broadcaster.broadcast).not.toHaveBeenCalled()
    })

    it('rethrows WERR_REVIEW_ACTIONS where doubleSpend result has no competingTxs', async () => {
      const error = makeDoubleSpendError([0x01, 0x02], null)
      const operation = jest.fn().mockRejectedValue(error)

      await expect(withDoubleSpendRetry(operation, broadcaster)).rejects.toThrow(error)
      expect(operation).toHaveBeenCalledTimes(1)
      expect(broadcaster.broadcast).not.toHaveBeenCalled()
    })

    it('rethrows WERR_REVIEW_ACTIONS where competingTxs is an empty array', async () => {
      const error = makeDoubleSpendError([0x01, 0x02], [])
      const operation = jest.fn().mockRejectedValue(error)

      await expect(withDoubleSpendRetry(operation, broadcaster)).rejects.toThrow(error)
      expect(operation).toHaveBeenCalledTimes(1)
      expect(broadcaster.broadcast).not.toHaveBeenCalled()
    })
  })

  // --- Retry on doubleSpend -------------------------------------------------

  describe('retries after broadcasting the competing transaction', () => {
    it('broadcasts the competing tx and retries the operation when doubleSpend is detected', async () => {
      const competingBeef = [0xbe, 0xef]
      const competingTxId = 'competingtxid111111111111111111111111111111111111111111111111111111'
      const doubleSpendError = makeDoubleSpendError(competingBeef, [competingTxId])

      broadcaster.broadcast.mockResolvedValue({ status: 'success', txid: competingTxId } as any)

      const expectedResult = { done: true }
      const operation = jest.fn()
        .mockRejectedValueOnce(doubleSpendError) // first attempt: double-spend
        .mockResolvedValueOnce(expectedResult) // second attempt: success

      const result = await withDoubleSpendRetry(operation, broadcaster)

      expect(result).toBe(expectedResult)
      expect(operation).toHaveBeenCalledTimes(2)
      expect(MockedTransaction.fromBEEF).toHaveBeenCalledWith(competingBeef, competingTxId)
      expect(broadcaster.broadcast).toHaveBeenCalledTimes(1)
      expect(broadcaster.broadcast).toHaveBeenCalledWith(mockCompetingTx)
    })

    it('calls Transaction.fromBEEF with competingBeef and the first competingTx', async () => {
      const competingBeef = [0x01, 0x02, 0x03]
      const firstTxId = 'firstcompetingtxid1111111111111111111111111111111111111111111111111'
      const secondTxId = 'secondcompetingtxid111111111111111111111111111111111111111111111111'
      const doubleSpendError = makeDoubleSpendError(competingBeef, [firstTxId, secondTxId])

      broadcaster.broadcast.mockResolvedValue({ status: 'success', txid: firstTxId } as any)
      const operation = jest.fn()
        .mockRejectedValueOnce(doubleSpendError)
        .mockResolvedValueOnce('ok')

      await withDoubleSpendRetry(operation, broadcaster)

      // Only the first competingTx should be used
      expect(MockedTransaction.fromBEEF).toHaveBeenCalledWith(competingBeef, firstTxId)
    })

    it('retries multiple times until success', async () => {
      const doubleSpendError = makeDoubleSpendError()
      broadcaster.broadcast.mockResolvedValue({ status: 'success' } as any)

      const operation = jest.fn()
        .mockRejectedValueOnce(doubleSpendError) // attempt 1
        .mockRejectedValueOnce(doubleSpendError) // attempt 2
        .mockRejectedValueOnce(doubleSpendError) // attempt 3
        .mockResolvedValueOnce('finally succeeded') // attempt 4

      const result = await withDoubleSpendRetry(operation, broadcaster)

      expect(result).toBe('finally succeeded')
      expect(operation).toHaveBeenCalledTimes(4)
      expect(broadcaster.broadcast).toHaveBeenCalledTimes(3)
    })
  })

  // --- MAX_DOUBLE_SPEND_RETRIES enforcement ----------------------------------

  describe('throws after MAX_DOUBLE_SPEND_RETRIES is exceeded', () => {
    it('throws the error after MAX_DOUBLE_SPEND_RETRIES (5) failed attempts', async () => {
      const doubleSpendError = makeDoubleSpendError()
      broadcaster.broadcast.mockResolvedValue({ status: 'success' } as any)

      // Operation always double-spends — should fail after maxRetries
      const operation = jest.fn().mockRejectedValue(doubleSpendError)

      await expect(
        withDoubleSpendRetry(operation, broadcaster, MAX_DOUBLE_SPEND_RETRIES)
      ).rejects.toThrow(doubleSpendError)

      // Called maxRetries times; the last attempt's error is rethrown without broadcasting
      expect(operation).toHaveBeenCalledTimes(MAX_DOUBLE_SPEND_RETRIES)
      // Broadcast is called for all but the final attempt (last error is rethrown directly)
      expect(broadcaster.broadcast).toHaveBeenCalledTimes(MAX_DOUBLE_SPEND_RETRIES - 1)
    })

    it('throws after custom maxRetries value is exceeded', async () => {
      const doubleSpendError = makeDoubleSpendError()
      broadcaster.broadcast.mockResolvedValue({ status: 'success' } as any)
      const operation = jest.fn().mockRejectedValue(doubleSpendError)

      await expect(
        withDoubleSpendRetry(operation, broadcaster, 2)
      ).rejects.toThrow(doubleSpendError)

      expect(operation).toHaveBeenCalledTimes(2)
      expect(broadcaster.broadcast).toHaveBeenCalledTimes(1)
    })
  })

  // --- Broadcaster interaction -----------------------------------------------

  describe('broadcaster.broadcast is called with the correct transaction', () => {
    it('passes the Transaction.fromBEEF result to broadcaster.broadcast', async () => {
      const competingTxMock = { id: jest.fn().mockReturnValue('abc') }
      ;(MockedTransaction.fromBEEF as jest.Mock).mockReturnValue(competingTxMock)

      const doubleSpendError = makeDoubleSpendError([0xaa, 0xbb], ['txid'])
      broadcaster.broadcast.mockResolvedValue({ status: 'success' } as any)

      const operation = jest.fn()
        .mockRejectedValueOnce(doubleSpendError)
        .mockResolvedValueOnce('done')

      await withDoubleSpendRetry(operation, broadcaster)

      expect(broadcaster.broadcast).toHaveBeenCalledWith(competingTxMock)
    })
  })
})
