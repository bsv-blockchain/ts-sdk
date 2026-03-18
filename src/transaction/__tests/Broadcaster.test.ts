import {
  BroadcastResponse,
  BroadcastFailure,
  isBroadcastResponse,
  isBroadcastFailure
} from '../../transaction/Broadcaster'

// Broadcaster.ts contains two interfaces (BroadcastResponse, BroadcastFailure, Broadcaster)
// and two exported type-guard functions.  The interfaces have no runtime representation,
// so coverage comes entirely from exercising isBroadcastResponse and isBroadcastFailure.

describe('isBroadcastResponse', () => {
  it('returns true for an object with status "success"', () => {
    const r: BroadcastResponse = {
      status: 'success',
      txid: 'abc123',
      message: 'broadcast successful'
    }
    expect(isBroadcastResponse(r)).toBe(true)
  })

  it('returns false for an object with status "error"', () => {
    const r: BroadcastFailure = {
      status: 'error',
      code: '500',
      description: 'Internal Server Error'
    }
    expect(isBroadcastResponse(r)).toBe(false)
  })

  it('narrows the type to BroadcastResponse inside a conditional', () => {
    const r: BroadcastResponse | BroadcastFailure = {
      status: 'success',
      txid: 'deadbeef',
      message: 'ok',
      competingTxs: ['aabbcc']
    }
    if (isBroadcastResponse(r)) {
      expect(r.txid).toBe('deadbeef')
      expect(r.message).toBe('ok')
      expect(r.competingTxs).toEqual(['aabbcc'])
    } else {
      fail('Expected isBroadcastResponse to return true')
    }
  })

  it('returns false even when the failure object has extra fields', () => {
    const r: BroadcastFailure = {
      status: 'error',
      code: '404',
      txid: 'txidfail',
      description: 'Not found',
      more: { detail: 'extra' }
    }
    expect(isBroadcastResponse(r)).toBe(false)
  })
})

describe('isBroadcastFailure', () => {
  it('returns true for an object with status "error"', () => {
    const r: BroadcastFailure = {
      status: 'error',
      code: 'ERR_UNKNOWN',
      description: 'Something went wrong'
    }
    expect(isBroadcastFailure(r)).toBe(true)
  })

  it('returns false for an object with status "success"', () => {
    const r: BroadcastResponse = {
      status: 'success',
      txid: 'txid1',
      message: 'done'
    }
    expect(isBroadcastFailure(r)).toBe(false)
  })

  it('narrows the type to BroadcastFailure inside a conditional', () => {
    const r: BroadcastResponse | BroadcastFailure = {
      status: 'error',
      code: '503',
      txid: 'tx503',
      description: 'Service unavailable',
      more: { raw: 'body' }
    }
    if (isBroadcastFailure(r)) {
      expect(r.code).toBe('503')
      expect(r.description).toBe('Service unavailable')
      expect(r.txid).toBe('tx503')
      expect(r.more).toEqual({ raw: 'body' })
    } else {
      fail('Expected isBroadcastFailure to return true')
    }
  })

  it('returns false even when the success object has an optional competingTxs field', () => {
    const r: BroadcastResponse = {
      status: 'success',
      txid: 't1',
      message: 'm1',
      competingTxs: ['other']
    }
    expect(isBroadcastFailure(r)).toBe(false)
  })

  it('handles BroadcastFailure with only the required fields', () => {
    const r: BroadcastFailure = {
      status: 'error',
      code: '400',
      description: 'Bad request'
    }
    expect(isBroadcastFailure(r)).toBe(true)
    if (isBroadcastFailure(r)) {
      expect(r.txid).toBeUndefined()
      expect(r.more).toBeUndefined()
    }
  })
})

describe('BroadcastResponse interface shape', () => {
  it('accepts competingTxs as an optional field', () => {
    const withCompeting: BroadcastResponse = {
      status: 'success',
      txid: 'tx',
      message: 'msg',
      competingTxs: ['tx1', 'tx2']
    }
    expect(withCompeting.competingTxs).toHaveLength(2)

    const withoutCompeting: BroadcastResponse = {
      status: 'success',
      txid: 'tx',
      message: 'msg'
    }
    expect(withoutCompeting.competingTxs).toBeUndefined()
  })
})

describe('BroadcastFailure interface shape', () => {
  it('accepts txid and more as optional fields', () => {
    const full: BroadcastFailure = {
      status: 'error',
      code: '422',
      txid: 'txfull',
      description: 'Unprocessable',
      more: { hints: ['check input'] }
    }
    expect(full.txid).toBe('txfull')
    expect(full.more).toEqual({ hints: ['check input'] })

    const minimal: BroadcastFailure = {
      status: 'error',
      code: '422',
      description: 'Unprocessable'
    }
    expect(minimal.txid).toBeUndefined()
    expect(minimal.more).toBeUndefined()
  })
})
