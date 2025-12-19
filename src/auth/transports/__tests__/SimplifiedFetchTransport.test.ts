import { jest } from '@jest/globals'
import { SimplifiedFetchTransport } from '../SimplifiedFetchTransport.js'
import * as Utils from '../../../primitives/utils.js'
import { AuthMessage } from '../../types.js'

function createGeneralPayload (path = '/resource', method = 'GET'): number[] {
  const writer = new Utils.Writer()
  const requestId = new Array(32).fill(1)
  writer.write(requestId)

  const methodBytes = Utils.toArray(method, 'utf8')
  writer.writeVarIntNum(methodBytes.length)
  writer.write(methodBytes)

  const pathBytes = Utils.toArray(path, 'utf8')
  writer.writeVarIntNum(pathBytes.length)
  writer.write(pathBytes)

  writer.writeVarIntNum(-1) // no query string
  writer.writeVarIntNum(0) // no headers
  writer.writeVarIntNum(-1) // no body

  return writer.toArray()
}

function createGeneralMessage (overrides: Partial<AuthMessage> = {}): AuthMessage {
  return {
    version: '1.0',
    messageType: 'general',
    identityKey: 'client-key',
    nonce: 'client-nonce',
    yourNonce: 'server-nonce',
    payload: createGeneralPayload(),
    signature: new Array(64).fill(0),
    ...overrides
  }
}

afterEach(() => {
  jest.restoreAllMocks()
})

describe('SimplifiedFetchTransport send', () => {
  test('wraps network failures with context', async () => {
    const fetchMock: jest.MockedFunction<typeof fetch> = jest.fn()
    fetchMock.mockRejectedValue(new Error('network down'))
    const transport = new SimplifiedFetchTransport('https://api.example.com', fetchMock as any)
    await transport.onData(async () => {})
    const message = createGeneralMessage()

    let caught: any
    await expect((async () => {
      try {
        await transport.send(message)
      } catch (error) {
        caught = error
        throw error
      }
    })()).rejects.toThrow('Network error while sending authenticated request to https://api.example.com/resource: network down')

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0][0]).toBe('https://api.example.com/resource')
    expect(caught).toBeInstanceOf(Error)
    expect(caught.cause).toBeInstanceOf(Error)
    expect(caught.cause?.message).toBe('network down')
  })

  test('throws when server omits authentication headers', async () => {
    const response = new Response('missing auth', {
      status: 200,
      headers: {
        'Content-Type': 'text/plain'
      }
    })
    const fetchMock: jest.MockedFunction<typeof fetch> = jest.fn()
    fetchMock.mockResolvedValue(response)
    const transport = new SimplifiedFetchTransport('https://api.example.com', fetchMock as any)
    await transport.onData(async () => {})

    const message = createGeneralMessage()

    let thrown: any
    await expect((async () => {
      try {
        await transport.send(message)
      } catch (error) {
        thrown = error
        throw error
      }
    })()).rejects.toThrow('Received HTTP 200 from https://api.example.com/resource without valid BSV authentication (missing headers: x-bsv-auth-version, x-bsv-auth-identity-key, x-bsv-auth-signature)')

    expect(thrown.details).toMatchObject({
      url: 'https://api.example.com/resource',
      status: 200,
      missingHeaders: [
        'x-bsv-auth-version',
        'x-bsv-auth-identity-key',
        'x-bsv-auth-signature'
      ]
    })
    expect(thrown.details.bodyPreview).toContain('missing auth')
  })

  test('rejects malformed requested certificates header', async () => {
    const fetchMock: jest.MockedFunction<typeof fetch> = jest.fn()
    fetchMock.mockResolvedValue(new Response('', {
      status: 200,
      headers: {
        'x-bsv-auth-version': '0.1',
        'x-bsv-auth-identity-key': 'server-key',
        'x-bsv-auth-signature': 'deadbeef',
        'x-bsv-auth-message-type': 'general',
        'x-bsv-auth-request-id': Utils.toBase64(new Array(32).fill(2)),
        'x-bsv-auth-requested-certificates': 'not-json'
      }
    }))

    const transport = new SimplifiedFetchTransport('https://api.example.com', fetchMock as any)
    await transport.onData(async () => {})
    const message = createGeneralMessage()

    await expect(transport.send(message)).rejects.toThrow(
      'Failed to parse x-bsv-auth-requested-certificates returned by https://api.example.com/resource: not-json'
    )
  })

  test('calls onDataCallback only for auth endpoint responses', async () => {
    // Test auth endpoint - should call callback
    const authFetchMock: jest.MockedFunction<typeof fetch> = jest.fn()
    authFetchMock.mockResolvedValue(new Response('{"status": "ok"}', {
      status: 200,
      headers: {
        'x-bsv-auth-version': '1.0',
        'x-bsv-auth-identity-key': 'server-key',
        'x-bsv-auth-signature': Utils.toHex(new Array(64).fill(0)),
        'x-bsv-auth-message-type': 'general',
        'x-bsv-auth-request-id': Utils.toBase64(new Array(32).fill(2))
      }
    }))

    const authTransport = new SimplifiedFetchTransport('https://api.example.com', authFetchMock as any)
    let callbackCalled = false
    let callbackMessage: AuthMessage | undefined
    await authTransport.onData(async (message) => {
      callbackCalled = true
      callbackMessage = message
    })

    const authMessage = createGeneralMessage()
    authMessage.payload = createGeneralPayload('/.well-known/auth', 'POST')
    await authTransport.send(authMessage)

    expect(callbackCalled).toBe(true)
    expect(callbackMessage).toMatchObject({
      version: '1.0',
      messageType: 'general',
      identityKey: 'server-key'
    })

    // Test non-auth endpoint - should NOT call callback
    const apiFetchMock: jest.MockedFunction<typeof fetch> = jest.fn()
    apiFetchMock.mockResolvedValue(new Response('{"status": "ok"}', {
      status: 200,
      headers: {
        'x-bsv-auth-version': '1.0',
        'x-bsv-auth-identity-key': 'server-key',
        'x-bsv-auth-signature': Utils.toHex(new Array(64).fill(0)),
        'x-bsv-auth-message-type': 'general',
        'x-bsv-auth-request-id': Utils.toBase64(new Array(32).fill(2))
      }
    }))

    const apiTransport = new SimplifiedFetchTransport('https://api.example.com', apiFetchMock as any)
    callbackCalled = false
    callbackMessage = undefined
    await apiTransport.onData(async (message) => {
      callbackCalled = true
      callbackMessage = message
    })

    const apiMessage = createGeneralMessage()
    apiMessage.payload = createGeneralPayload('/api/walletInfo', 'GET')
    await apiTransport.send(apiMessage)

    expect(callbackCalled).toBe(false)
    expect(callbackMessage).toBeUndefined()
  })

  test('calls onDataCallback for auth endpoint with trailing slash', async () => {
    const fetchMock: jest.MockedFunction<typeof fetch> = jest.fn()
    fetchMock.mockResolvedValue(new Response('{"status": "ok"}', {
      status: 200,
      headers: {
        'x-bsv-auth-version': '1.0',
        'x-bsv-auth-identity-key': 'server-key',
        'x-bsv-auth-signature': Utils.toHex(new Array(64).fill(0)),
        'x-bsv-auth-message-type': 'general',
        'x-bsv-auth-request-id': Utils.toBase64(new Array(32).fill(2))
      }
    }))

    const transport = new SimplifiedFetchTransport('https://api.example.com', fetchMock as any)
    let callbackCalled = false
    await transport.onData(async (message) => {
      callbackCalled = true
    })

    // Test auth endpoint with trailing slash - should call callback
    const authMessage = createGeneralMessage()
    authMessage.payload = createGeneralPayload('/.well-known/auth/', 'POST')
    await transport.send(authMessage)

    expect(callbackCalled).toBe(true)
  })
})
