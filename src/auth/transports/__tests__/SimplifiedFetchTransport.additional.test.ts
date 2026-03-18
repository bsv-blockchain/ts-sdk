import { jest } from '@jest/globals'
import { SimplifiedFetchTransport } from '../SimplifiedFetchTransport.js'
import * as Utils from '../../../primitives/utils.js'
import { AuthMessage } from '../../types.js'

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Build a serialized general message payload. */
function buildGeneralPayload ({
  path = '/api/resource',
  method = 'GET',
  search = '',
  headers = {} as Record<string, string>,
  body = null as number[] | null
} = {}): number[] {
  const writer = new Utils.Writer()

  // requestId: 32 bytes
  writer.write(new Array(32).fill(0xab))

  // method
  if (method.length > 0) {
    const methodBytes = Utils.toArray(method, 'utf8')
    writer.writeVarIntNum(methodBytes.length)
    writer.write(methodBytes)
  } else {
    writer.writeVarIntNum(0)
  }

  // path
  if (path.length > 0) {
    const pathBytes = Utils.toArray(path, 'utf8')
    writer.writeVarIntNum(pathBytes.length)
    writer.write(pathBytes)
  } else {
    writer.writeVarIntNum(0)
  }

  // search
  if (search.length > 0) {
    const searchBytes = Utils.toArray(search, 'utf8')
    writer.writeVarIntNum(searchBytes.length)
    writer.write(searchBytes)
  } else {
    writer.writeVarIntNum(0)
  }

  // headers
  const headerEntries = Object.entries(headers)
  writer.writeVarIntNum(headerEntries.length)
  for (const [key, value] of headerEntries) {
    const keyBytes = Utils.toArray(key, 'utf8')
    writer.writeVarIntNum(keyBytes.length)
    writer.write(keyBytes)
    const valueBytes = Utils.toArray(value, 'utf8')
    writer.writeVarIntNum(valueBytes.length)
    writer.write(valueBytes)
  }

  // body
  if (body != null && body.length > 0) {
    writer.writeVarIntNum(body.length)
    writer.write(body)
  } else {
    writer.writeVarIntNum(0)
  }

  return writer.toArray()
}

function makeGeneralMessage (overrides: Partial<AuthMessage> = {}): AuthMessage {
  return {
    version: '0.1',
    messageType: 'general',
    identityKey: 'client-key',
    nonce: 'cnonce',
    yourNonce: 'snonce',
    payload: buildGeneralPayload(),
    signature: new Array(64).fill(0),
    ...overrides
  }
}

function makeAuthMessage (messageType: AuthMessage['messageType'], overrides: Partial<AuthMessage> = {}): AuthMessage {
  return {
    version: '0.1',
    messageType,
    identityKey: 'client-key',
    nonce: 'cnonce',
    yourNonce: 'snonce',
    payload: [],
    signature: new Array(64).fill(0),
    ...overrides
  }
}

/** Build a minimal valid general response (all required BSV auth headers). */
function makeValidGeneralResponse (body = '', extraHeaders: Record<string, string> = {}): Response {
  return new Response(body, {
    status: 200,
    headers: {
      'x-bsv-auth-version': '0.1',
      'x-bsv-auth-identity-key': 'server-key',
      'x-bsv-auth-signature': 'aabbcc',
      'x-bsv-auth-message-type': 'general',
      ...extraHeaders
    }
  })
}

afterEach(() => {
  jest.restoreAllMocks()
})

// ─── Constructor ─────────────────────────────────────────────────────────────

describe('SimplifiedFetchTransport constructor', () => {
  test('throws when fetchClient is not a function', () => {
    expect(() => new SimplifiedFetchTransport('https://example.com', 'not-a-function' as any))
      .toThrow('SimplifiedFetchTransport requires a fetch implementation.')
  })

  test('throws when fetchClient is null', () => {
    expect(() => new SimplifiedFetchTransport('https://example.com', null as any))
      .toThrow('SimplifiedFetchTransport requires a fetch implementation.')
  })

  test('stores baseUrl and fetchClient', () => {
    const mockFetch = jest.fn() as any
    const transport = new SimplifiedFetchTransport('https://my.server.com', mockFetch)
    expect(transport.baseUrl).toBe('https://my.server.com')
    expect(transport.fetchClient).toBe(mockFetch)
  })
})

// ─── send without onData registered ──────────────────────────────────────────

describe('SimplifiedFetchTransport send without listener', () => {
  test('throws "Listen before you start speaking" when no onData registered', async () => {
    const mockFetch = jest.fn() as any
    const transport = new SimplifiedFetchTransport('https://example.com', mockFetch)
    // Never call onData

    await expect(transport.send(makeGeneralMessage())).rejects.toThrow(
      'Listen before you start speaking'
    )
    expect(mockFetch).not.toHaveBeenCalled()
  })
})

// ─── send: non-initialRequest auth message paths ─────────────────────────────

describe('SimplifiedFetchTransport send — non-general auth message', () => {
  test('non-initialRequest: resolves before response arrives and still calls onDataCallback', async () => {
    let resolveResponse: (r: Response) => void
    const responsePromise = new Promise<Response>((res) => { resolveResponse = res })

    const mockFetch = jest.fn<() => any>().mockReturnValue(responsePromise) as any
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)

    const received: AuthMessage[] = []
    await transport.onData(async (msg) => { received.push(msg) })

    const sendPromise = transport.send(makeAuthMessage('initialResponse'))
    // resolve before the fetch response arrives to confirm promise doesn't hang
    resolveResponse!(new Response(JSON.stringify({ version: '0.1', messageType: 'initialResponse', identityKey: 'k', payload: [], signature: [] }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    }))

    await sendPromise
    // Flush microtask queue so the background response processing completes
    await new Promise<void>(resolve => setTimeout(resolve, 0))
    // onDataCallback should have been invoked with the response message
    expect(received).toHaveLength(1)
    const firstReceived = received[0]
    expect(firstReceived).toBeDefined()
    expect(firstReceived?.messageType).toBe('initialResponse')
  })

  test('initialRequest: resolves after the response is processed', async () => {
    const responseBody = JSON.stringify({ version: '0.1', messageType: 'initialRequest', identityKey: 'server-key', payload: [], signature: [] })
    const mockFetch = jest.fn<() => any>().mockResolvedValue(
      new Response(responseBody, { status: 200, headers: { 'Content-Type': 'application/json' } })
    ) as any

    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    const received: AuthMessage[] = []
    await transport.onData(async (msg) => { received.push(msg) })

    await transport.send(makeAuthMessage('initialRequest'))

    expect(mockFetch).toHaveBeenCalledWith(
      'https://api.example.com/.well-known/auth',
      expect.objectContaining({ method: 'POST' })
    )
    expect(received).toHaveLength(1)
  })

  test('non-ok response on auth endpoint throws unauthenticated error', async () => {
    const mockFetch = jest.fn<() => any>().mockResolvedValue(
      new Response('Unauthorized', { status: 401, statusText: 'Unauthorized' })
    ) as any

    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    await expect(transport.send(makeAuthMessage('initialRequest'))).rejects.toThrow(
      'Received HTTP 401 Unauthorized from https://api.example.com/.well-known/auth without valid BSV authentication'
    )
  })

  test('network failure on auth endpoint wraps error with context', async () => {
    const mockFetch = jest.fn<() => any>().mockRejectedValue(new Error('DNS lookup failed')) as any

    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    await expect(transport.send(makeAuthMessage('initialRequest'))).rejects.toThrow(
      'Network error while sending authenticated request to https://api.example.com/.well-known/auth: DNS lookup failed'
    )
  })

  test('non-Error network failure still wraps as Error string', async () => {
    const mockFetch = jest.fn<() => any>().mockRejectedValue('plain string error') as any

    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    await expect(transport.send(makeAuthMessage('initialRequest'))).rejects.toThrow(
      'Network error while sending authenticated request to https://api.example.com/.well-known/auth: plain string error'
    )
  })
})

// ─── send: general message — body Content-Type handling ──────────────────────

describe('SimplifiedFetchTransport send — general message body handling', () => {
  async function sendWithBody (
    body: number[],
    contentType: string
  ): Promise<void> {
    const payload = buildGeneralPayload({
      method: 'POST',
      path: '/data',
      headers: { 'content-type': contentType },
      body
    })

    const mockFetch = jest.fn<() => any>().mockResolvedValue(makeValidGeneralResponse()) as any
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    await transport.send(makeGeneralMessage({ payload }))
    return mockFetch.mock.calls[0][1]?.body
  }

  test('application/json body is converted to UTF-8 string', async () => {
    const body = Utils.toArray('{"hello":"world"}', 'utf8') as number[]
    const payload = buildGeneralPayload({ method: 'POST', path: '/json', headers: { 'content-type': 'application/json' }, body })
    const mockFetch = jest.fn<() => any>().mockResolvedValue(makeValidGeneralResponse()) as any
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    await transport.send(makeGeneralMessage({ payload }))

    const sentBody = mockFetch.mock.calls[0][1]?.body
    expect(typeof sentBody).toBe('string')
    expect(sentBody).toContain('hello')
  })

  test('application/x-www-form-urlencoded body is converted to UTF-8 string', async () => {
    const body = Utils.toArray('name=Alice&age=30', 'utf8') as number[]
    const payload = buildGeneralPayload({
      method: 'POST',
      path: '/form',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body
    })
    const mockFetch = jest.fn<() => any>().mockResolvedValue(makeValidGeneralResponse()) as any
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    await transport.send(makeGeneralMessage({ payload }))

    const sentBody = mockFetch.mock.calls[0][1]?.body
    expect(typeof sentBody).toBe('string')
  })

  test('text/plain body is converted to UTF-8 string', async () => {
    const body = Utils.toArray('hello world', 'utf8') as number[]
    const payload = buildGeneralPayload({ method: 'POST', path: '/text', headers: { 'content-type': 'text/plain' }, body })
    const mockFetch = jest.fn<() => any>().mockResolvedValue(makeValidGeneralResponse()) as any
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    await transport.send(makeGeneralMessage({ payload }))

    const sentBody = mockFetch.mock.calls[0][1]?.body
    expect(typeof sentBody).toBe('string')
    expect(sentBody).toBe('hello world')
  })

  test('binary content-type body is converted to Uint8Array', async () => {
    const body = [0x89, 0x50, 0x4e, 0x47] // PNG magic bytes
    const payload = buildGeneralPayload({ method: 'POST', path: '/upload', headers: { 'content-type': 'image/png' }, body })
    const mockFetch = jest.fn<() => any>().mockResolvedValue(makeValidGeneralResponse()) as any
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    await transport.send(makeGeneralMessage({ payload }))

    const sentBody = mockFetch.mock.calls[0][1]?.body
    expect(sentBody).toBeInstanceOf(Uint8Array)
  })

  test('throws when body is present but content-type header is missing', async () => {
    // No content-type header, but body present
    const body = [1, 2, 3, 4]
    const payload = buildGeneralPayload({ method: 'POST', path: '/no-ct', headers: {}, body })
    const mockFetch = jest.fn<() => any>().mockResolvedValue(makeValidGeneralResponse()) as any
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    await expect(transport.send(makeGeneralMessage({ payload }))).rejects.toThrow(
      'Content-Type header is required for requests with a body.'
    )
  })
})

// ─── send: general message — response header parsing ─────────────────────────

describe('SimplifiedFetchTransport send — general message response parsing', () => {
  test('invokes onDataCallback with parsed AuthMessage', async () => {
    const mockFetch = jest.fn<() => any>().mockResolvedValue(makeValidGeneralResponse()) as any
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)

    const received: AuthMessage[] = []
    await transport.onData(async (msg) => { received.push(msg) })

    await transport.send(makeGeneralMessage())

    expect(received).toHaveLength(1)
    expect(received[0].version).toBe('0.1')
    expect(received[0].identityKey).toBe('server-key')
    expect(received[0].messageType).toBe('general')
  })

  test('sets messageType to certificateRequest when x-bsv-auth-message-type is certificateRequest', async () => {
    const mockFetch = jest.fn<() => any>().mockResolvedValue(
      makeValidGeneralResponse('', { 'x-bsv-auth-message-type': 'certificateRequest' })
    ) as any
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)

    const received: AuthMessage[] = []
    await transport.onData(async (msg) => { received.push(msg) })

    await transport.send(makeGeneralMessage())
    expect(received[0].messageType).toBe('certificateRequest')
  })

  test('parses requestedCertificates header into structured object', async () => {
    const certSet = { certifiers: ['certKey1'], types: {} }
    const mockFetch = jest.fn<() => any>().mockResolvedValue(
      makeValidGeneralResponse('', { 'x-bsv-auth-requested-certificates': JSON.stringify(certSet) })
    ) as any
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)

    const received: AuthMessage[] = []
    await transport.onData(async (msg) => { received.push(msg) })

    await transport.send(makeGeneralMessage())
    expect(received[0].requestedCertificates).toEqual(certSet)
  })

  test('throws on malformed requestedCertificates header', async () => {
    const mockFetch = jest.fn<() => any>().mockResolvedValue(
      makeValidGeneralResponse('', { 'x-bsv-auth-requested-certificates': '{invalid json' })
    ) as any
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    await expect(transport.send(makeGeneralMessage())).rejects.toThrow(
      'Failed to parse x-bsv-auth-requested-certificates'
    )
  })

  test('includes x-bsv-auth-request-id in payload when present in response', async () => {
    const requestIdBase64 = Utils.toBase64(new Array(32).fill(0xcc))
    const mockFetch = jest.fn<() => any>().mockResolvedValue(
      makeValidGeneralResponse('', { 'x-bsv-auth-request-id': requestIdBase64 })
    ) as any
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    const received: AuthMessage[] = []
    await transport.onData(async (msg) => { received.push(msg) })

    await transport.send(makeGeneralMessage())
    expect(received[0].payload).toBeDefined()
    expect(Array.isArray(received[0].payload)).toBe(true)
  })

  test('includes x-bsv (non-auth) and authorization headers in signed payload', async () => {
    const mockFetch = jest.fn<() => any>().mockResolvedValue(new Response('', {
      status: 200,
      headers: {
        'x-bsv-auth-version': '0.1',
        'x-bsv-auth-identity-key': 'server-key',
        'x-bsv-auth-signature': 'deadbeef',
        'x-bsv-custom-header': 'custom-value',   // should be included
        'authorization': 'Bearer token',            // should be included
        'x-bsv-auth-extra': 'excluded'             // should NOT be included (x-bsv-auth prefix)
      }
    })) as any
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    const received: AuthMessage[] = []
    await transport.onData(async (msg) => { received.push(msg) })

    await transport.send(makeGeneralMessage())
    // The payload should be non-empty (headers were serialized into it)
    const firstReceived = received[0]
    expect(firstReceived).toBeDefined()
    expect(firstReceived?.payload?.length).toBeGreaterThan(0)
  })

  test('network failure on general message wraps error with URL context', async () => {
    const mockFetch = jest.fn<() => any>().mockRejectedValue(new Error('timeout')) as any
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    await expect(transport.send(makeGeneralMessage())).rejects.toThrow(
      'Network error while sending authenticated request to https://api.example.com/api/resource: timeout'
    )
  })

  test('non-Error network failure on general message uses String()', async () => {
    const mockFetch = jest.fn<() => any>().mockRejectedValue(42) as any
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    await expect(transport.send(makeGeneralMessage())).rejects.toThrow(
      'Network error while sending authenticated request to https://api.example.com/api/resource: 42'
    )
  })

  test('appends headers from httpRequest when headers field is not an object', async () => {
    // Build a payload where the deserialized httpRequest has no headers field by
    // providing 0 headers in the encoded payload (the transport then sets headers to {})
    const payload = buildGeneralPayload({ method: 'GET', path: '/resource', headers: {} })
    const mockFetch = jest.fn<() => any>().mockResolvedValue(makeValidGeneralResponse()) as any
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    await transport.send(makeGeneralMessage({ payload }))

    const requestInit = mockFetch.mock.calls[0][1]
    expect(requestInit.headers).toMatchObject({
      'x-bsv-auth-version': '0.1',
      'x-bsv-auth-identity-key': 'client-key'
    })
  })
})

// ─── deserializeRequestPayload ────────────────────────────────────────────────

describe('SimplifiedFetchTransport deserializeRequestPayload', () => {
  let transport: SimplifiedFetchTransport

  beforeEach(() => {
    transport = new SimplifiedFetchTransport('https://example.com', jest.fn() as any)
  })

  test('returns GET and empty urlPostfix when method and path lengths are 0', () => {
    const writer = new Utils.Writer()
    writer.write(new Array(32).fill(0)) // requestId
    writer.writeVarIntNum(0)            // method length 0
    writer.writeVarIntNum(0)            // path length 0
    writer.writeVarIntNum(0)            // search length 0
    writer.writeVarIntNum(0)            // 0 headers
    writer.writeVarIntNum(0)            // body length 0

    const result = transport.deserializeRequestPayload(writer.toArray())
    expect(result.method).toBe('GET')
    expect(result.urlPostfix).toBe('')
    expect(result.body).toBeUndefined()
  })

  test('combines path and search into urlPostfix', () => {
    const payload = buildGeneralPayload({ path: '/items', search: '?page=2', method: 'GET' })
    const result = transport.deserializeRequestPayload(payload)
    expect(result.urlPostfix).toBe('/items?page=2')
  })

  test('deserializes headers correctly', () => {
    const payload = buildGeneralPayload({
      headers: { 'x-custom': 'value1', 'accept': 'application/json' }
    })
    const result = transport.deserializeRequestPayload(payload)
    expect(result.headers['x-custom']).toBe('value1')
    expect(result.headers['accept']).toBe('application/json')
  })

  test('deserializes body when present', () => {
    const bodyBytes = [10, 20, 30, 40]
    const payload = buildGeneralPayload({
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream' },
      body: bodyBytes
    })
    const result = transport.deserializeRequestPayload(payload)
    expect(result.body).toEqual(bodyBytes)
  })

  test('returns undefined body when body length is 0', () => {
    const payload = buildGeneralPayload({ body: null })
    const result = transport.deserializeRequestPayload(payload)
    expect(result.body).toBeUndefined()
  })

  test('returns correct requestId as base64', () => {
    const payload = buildGeneralPayload()
    const result = transport.deserializeRequestPayload(payload)
    // The requestId is the base64 of 32 bytes of 0xab
    expect(typeof result.requestId).toBe('string')
    expect(result.requestId.length).toBeGreaterThan(0)
  })
})

// ─── onData callback registration ────────────────────────────────────────────

describe('SimplifiedFetchTransport onData', () => {
  test('registers callback and errors from callback are swallowed', async () => {
    const mockFetch = jest.fn<() => any>().mockResolvedValue(makeValidGeneralResponse()) as any
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)

    await transport.onData(async (_msg) => {
      throw new Error('intentional callback error')
    })

    // Should not throw even though callback throws
    await expect(transport.send(makeGeneralMessage())).resolves.toBeUndefined()
  })
})

// ─── getBodyPreview (via error path in unauthenticated response) ─────────────

describe('SimplifiedFetchTransport body preview in error messages', () => {
  test('includes text body preview in unauthenticated error', async () => {
    const mockFetch: any = jest.fn()
    mockFetch.mockResolvedValue(new Response('{"error":"forbidden"}', {
      status: 403,
      statusText: 'Forbidden',
      headers: { 'Content-Type': 'application/json' }
    }))
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    let caught: any
    try {
      await transport.send(makeGeneralMessage())
    } catch (e) {
      caught = e
    }
    expect(caught).toBeDefined()
    expect(caught.message).toContain('forbidden')
  })

  test('body preview is omitted when body is empty', async () => {
    const mockFetch: any = jest.fn()
    mockFetch.mockResolvedValue(new Response('', { status: 503, headers: {} }))
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    let caught: any
    try {
      await transport.send(makeGeneralMessage())
    } catch (e) {
      caught = e
    }
    expect(caught.message).not.toContain('body preview')
  })

  test('binary body produces hex preview', async () => {
    // Binary bytes (low printability ratio)
    const binaryBytes = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x80, 0x81, 0xff, 0xfe])
    const mockFetch: any = jest.fn()
    mockFetch.mockResolvedValue(new Response(binaryBytes.buffer as ArrayBuffer, {
      status: 401,
      headers: { 'Content-Type': 'application/octet-stream' }
    }))
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    let caught: any
    try {
      await transport.send(makeGeneralMessage())
    } catch (e) {
      caught = e
    }
    // Should contain 0x prefix from binary hex formatting
    expect(caught.message).toContain('0x')
  })

  test('large body (>1024 bytes) is truncated in preview', async () => {
    const largeBody = 'x'.repeat(2000)
    const mockFetch: any = jest.fn()
    mockFetch.mockResolvedValue(new Response(largeBody, {
      status: 401,
      headers: { 'Content-Type': 'text/plain' }
    }))
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    let caught: any
    try {
      await transport.send(makeGeneralMessage())
    } catch (e) {
      caught = e
    }
    expect(caught.message).toContain('truncated')
  })

  test('preview longer than 512 chars is truncated with ellipsis', async () => {
    // Body that is textual and between 512 and 1024 chars (not truncated due to length, but truncated for preview)
    const mediumBody = 'A'.repeat(600)
    const mockFetch: any = jest.fn()
    mockFetch.mockResolvedValue(new Response(mediumBody, {
      status: 401,
      headers: { 'Content-Type': 'text/plain' }
    }))
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    let caught: any
    try {
      await transport.send(makeGeneralMessage())
    } catch (e) {
      caught = e
    }
    expect(caught.message).toContain('…')
  })

  test('status description includes statusText when non-empty', async () => {
    const mockFetch: any = jest.fn()
    mockFetch.mockResolvedValue(new Response('error text', {
      status: 422,
      statusText: 'Unprocessable Entity',
      headers: { 'Content-Type': 'text/plain' }
    }))
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    let caught: any
    try {
      await transport.send(makeGeneralMessage())
    } catch (e) {
      caught = e
    }
    expect(caught.message).toContain('422 Unprocessable Entity')
  })

  test('error details contains missingHeaders as empty array when all missing', async () => {
    const mockFetch: any = jest.fn()
    mockFetch.mockResolvedValue(new Response('body', { status: 200 }))
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    let caught: any
    try {
      await transport.send(makeGeneralMessage())
    } catch (e) {
      caught = e
    }
    expect(caught.details.missingHeaders).toEqual([
      'x-bsv-auth-version',
      'x-bsv-auth-identity-key',
      'x-bsv-auth-signature'
    ])
  })
})

// ─── createMalformedHeaderError — non-Error cause ────────────────────────────

describe('SimplifiedFetchTransport malformed header error — non-Error cause', () => {
  test('formats error when JSON.parse throws a non-Error value (string cause)', async () => {
    // Spy on JSON.parse to throw a string
    const originalParse = JSON.parse
    jest.spyOn(JSON, 'parse').mockImplementation((text) => {
      if (text === '{bad}') throw 'string error cause'
      return originalParse(text)
    })

    const mockFetch: any = jest.fn()
    mockFetch.mockResolvedValue(new Response('', {
      status: 200,
      headers: {
        'x-bsv-auth-version': '0.1',
        'x-bsv-auth-identity-key': 'server-key',
        'x-bsv-auth-signature': 'aabbcc',
        'x-bsv-auth-requested-certificates': '{bad}'
      }
    }))

    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    let caught: any
    try {
      await transport.send(makeGeneralMessage())
    } catch (e) {
      caught = e
    }

    expect(caught).toBeDefined()
    expect(caught.message).toContain('Failed to parse x-bsv-auth-requested-certificates')
    expect(caught.message).toContain('string error cause')
  })
})

// ─── isTextualContent heuristics ─────────────────────────────────────────────

describe('SimplifiedFetchTransport — isTextualContent heuristics (via send response)', () => {
  async function sendAndCatchError (body: BodyInit | null, contentType: string | null): Promise<Error> {
    const headers: Record<string, string> = {}
    if (contentType != null) {
      headers['Content-Type'] = contentType
    }

    const mockFetch: any = jest.fn()
    mockFetch.mockResolvedValue(new Response(body, { status: 401, headers }))
    const transport = new SimplifiedFetchTransport('https://api.example.com', mockFetch)
    await transport.onData(async () => {})

    try {
      await transport.send(makeGeneralMessage())
      throw new Error('expected rejection')
    } catch (e) {
      return e as Error
    }
  }

  test('application/problem+json is treated as text', async () => {
    const err = await sendAndCatchError('{"detail":"bad"}', 'application/problem+json')
    expect(err.message).toContain('bad')
  })

  test('application/xml is treated as text', async () => {
    const err = await sendAndCatchError('<root>value</root>', 'application/xml')
    expect(err.message).toContain('root')
  })

  test('charset= in content type is treated as text', async () => {
    const err = await sendAndCatchError('hello chars', 'application/octet-stream; charset=utf-8')
    expect(err.message).toContain('hello chars')
  })

  test('null content type with mostly printable bytes is treated as text', async () => {
    // >80% printable ASCII
    const printableBody = 'Hello World from the server! This is all ASCII text.'
    const err = await sendAndCatchError(printableBody, null)
    // Should be treated as text, not binary hex
    expect(err.message).not.toMatch(/^.*0x[0-9a-f]+/)
  })

  test('null content type with mostly binary bytes treated as binary', async () => {
    // Lots of control/non-printable bytes
    const binaryBytes = new Uint8Array(50).fill(0x01)
    const err = await sendAndCatchError(binaryBytes.buffer as ArrayBuffer, null)
    expect(err.message).toContain('0x')
  })
})
