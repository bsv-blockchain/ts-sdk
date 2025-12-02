import { jest } from '@jest/globals'
import { AuthFetch } from '../AuthFetch.js'
import { Utils, PrivateKey } from '../../../primitives/index.js'

import { createNonce } from '../../utils/createNonce.js'

jest.mock('../../utils/createNonce.js', () => ({
  createNonce: jest.fn()
}))

type Mutable<T> = {
  -readonly [P in keyof T]: T[P]
}

interface TestPaymentContext {
  satoshisRequired: number
  transactionBase64: string
  derivationPrefix: string
  derivationSuffix: string
  serverIdentityKey: string
  clientIdentityKey: string
  attempts: number
  maxAttempts: number
  errors: Array<{
    attempt: number
    timestamp: string
    message: string
    stack?: string
  }>
  requestSummary: {
    url: string
    method: string
    headers: Record<string, string>
    bodyType: string
    bodyByteLength: number
  }
}

const createNonceMock = createNonce as jest.MockedFunction<typeof createNonce>

function createWalletStub (): any {
  const identityKey = new PrivateKey(10).toPublicKey().toString()
  const derivedKey = new PrivateKey(11).toPublicKey().toString()

  return {
    getPublicKey: jest.fn(async (options: Record<string, any>) => {
      if (options?.identityKey === true) {
        return { publicKey: identityKey }
      }
      return { publicKey: derivedKey }
    }),
    createAction: jest.fn(async () => ({
      tx: Utils.toArray('mock-transaction', 'utf8')
    })),
    createHmac: jest.fn(async () => ({
      hmac: new Array(32).fill(7)
    }))
  }
}

function createPaymentRequiredResponse (overrides: Record<string, string> = {}): Response {
  const headers: Record<string, string> = {
    'x-bsv-payment-version': '1.0',
    'x-bsv-payment-satoshis-required': '5',
    'x-bsv-auth-identity-key': 'server-key',
    'x-bsv-payment-derivation-prefix': 'prefix',
    ...overrides
  }
  return new Response('', { status: 402, headers })
}

afterEach(() => {
  jest.restoreAllMocks()
  createNonceMock.mockReset()
})

describe('AuthFetch payment handling', () => {
  test('createPaymentContext builds a complete retry context', async () => {
    const wallet = createWalletStub()
    const authFetch = new AuthFetch(wallet)

    createNonceMock.mockResolvedValueOnce('suffix-from-test')

    const config = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: { hello: 'world' }
    }

    const context = await (authFetch as any).createPaymentContext(
      'https://api.example.com/resource',
      config,
      42,
      'remote-identity-key',
      'test-prefix'
    ) as TestPaymentContext

    expect(context.satoshisRequired).toBe(42)
    expect(context.serverIdentityKey).toBe('remote-identity-key')
    expect(context.derivationPrefix).toBe('test-prefix')
    expect(context.derivationSuffix).toBe('suffix-from-test')
    expect(context.transactionBase64).toBe(Utils.toBase64(Utils.toArray('mock-transaction', 'utf8')))
    expect(context.clientIdentityKey).toEqual(expect.any(String))
    expect(context.attempts).toBe(0)
    expect(context.maxAttempts).toBe(3)
    expect(context.errors).toEqual([])
    expect(context.requestSummary).toMatchObject({
      url: 'https://api.example.com/resource',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      bodyType: 'object'
    })
    expect(context.requestSummary.bodyByteLength).toBe(
      Utils.toArray(JSON.stringify(config.body), 'utf8').length
    )

    expect(wallet.createAction).toHaveBeenCalledWith(
      expect.objectContaining({
        description: expect.stringContaining('https://api.example.com'),
        outputs: [
          expect.objectContaining({
            satoshis: 42,
            customInstructions: expect.stringContaining('remote-identity-key')
          })
        ]
      }),
      undefined
    )
  })

  test('handlePaymentAndRetry reuses compatible contexts and adds payment header', async () => {
    const wallet = createWalletStub()
    const authFetch = new AuthFetch(wallet)

    const paymentContext: TestPaymentContext = {
      satoshisRequired: 5,
      transactionBase64: Utils.toBase64([1, 2, 3]),
      derivationPrefix: 'prefix',
      derivationSuffix: 'suffix',
      serverIdentityKey: 'server-key',
      clientIdentityKey: 'client-key',
      attempts: 0,
      maxAttempts: 3,
      errors: [],
      requestSummary: {
        url: 'https://api.example.com/resource',
        method: 'POST',
        headers: { 'X-Test': '1' },
        bodyType: 'none',
        bodyByteLength: 0
      }
    }

    const fetchSpy = jest.spyOn(authFetch, 'fetch').mockResolvedValue({ status: 200 } as Response)
    jest.spyOn(authFetch as any, 'logPaymentAttempt').mockImplementation(() => {})
    const createPaymentContextSpy = jest.spyOn(authFetch as any, 'createPaymentContext')

    const config: Mutable<any> = {
      headers: { 'x-custom': 'value' },
      paymentContext
    }

    const response = createPaymentRequiredResponse()

    const result = await (authFetch as any).handlePaymentAndRetry(
      'https://api.example.com/resource',
      config,
      response
    )

    expect(result).toEqual({ status: 200 })
    expect(paymentContext.attempts).toBe(1)
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    const callArgs = fetchSpy.mock.calls[0] as [string, any]
    const nextConfig = callArgs?.[1]
    expect(nextConfig).toBeDefined()
    expect(nextConfig.paymentContext).toBe(paymentContext)
    expect(nextConfig.retryCounter).toBe(3)

    const paymentHeader = JSON.parse(nextConfig.headers['x-bsv-payment'])
    expect(paymentHeader).toEqual({
      derivationPrefix: 'prefix',
      derivationSuffix: 'suffix',
      transaction: Utils.toBase64([1, 2, 3])
    })

    expect(createPaymentContextSpy).not.toHaveBeenCalled()
  })

  test('handlePaymentAndRetry exhausts attempts and throws detailed error', async () => {
    const wallet = createWalletStub()
    const authFetch = new AuthFetch(wallet)
    jest.spyOn(authFetch as any, 'logPaymentAttempt').mockImplementation(() => {})
    jest.spyOn(authFetch as any, 'wait').mockResolvedValue(undefined)

    const firstError = new Error('payment attempt 1 failed')
    const secondError = new Error('payment attempt 2 failed')
    jest.spyOn(authFetch, 'fetch')
      .mockRejectedValueOnce(firstError)
      .mockRejectedValueOnce(secondError)

    const paymentContext: TestPaymentContext = {
      satoshisRequired: 5,
      transactionBase64: Utils.toBase64([9, 9, 9]),
      derivationPrefix: 'prefix',
      derivationSuffix: 'suffix',
      serverIdentityKey: 'server-key',
      clientIdentityKey: 'client-key',
      attempts: 0,
      maxAttempts: 2,
      errors: [],
      requestSummary: {
        url: 'https://api.example.com/resource',
        method: 'GET',
        headers: {},
        bodyType: 'none',
        bodyByteLength: 0
      }
    }

    const config: Mutable<any> = { paymentContext }
    const response = createPaymentRequiredResponse()

    await expect((async () => {
      try {
        await (authFetch as any).handlePaymentAndRetry(
          'https://api.example.com/resource',
          config,
          response
        )
      } catch (error) {
        const err = error as any
        expect(err.message).toBe(
          'Paid request to https://api.example.com/resource failed after 2/2 attempts. Sent 5 satoshis to server-key.'
        )
        expect(err.details).toMatchObject({
          attempts: { used: 2, max: 2 },
          payment: expect.objectContaining({
            satoshis: 5,
            serverIdentityKey: 'server-key',
            clientIdentityKey: 'client-key'
          })
        })
        expect(err.details.errors).toHaveLength(2)
        expect(err.details.errors[0]).toEqual(expect.objectContaining({
          attempt: 1,
          message: 'payment attempt 1 failed'
        }))
        expect(err.details.errors[1]).toEqual(expect.objectContaining({
          attempt: 2,
          message: 'payment attempt 2 failed'
        }))
        expect(typeof err.details.errors[0].timestamp).toBe('string')
        expect(err.cause).toBe(secondError)
        throw error
      }
    })()).rejects.toThrow('Paid request to https://api.example.com/resource failed after 2/2 attempts. Sent 5 satoshis to server-key.')

    expect(paymentContext.attempts).toBe(2)
    expect(paymentContext.errors).toHaveLength(2)
  })
})
