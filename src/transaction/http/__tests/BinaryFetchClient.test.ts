import {
  BinaryFetchClient,
  BinaryNodejsHttpClient,
  binaryHttpClient
} from '../../../transaction/http/BinaryFetchClient'
import { executeNodejsRequest } from '../../../transaction/http/NodejsHttpRequestUtils'

jest.mock('../../../transaction/http/NodejsHttpRequestUtils', () => ({
  executeNodejsRequest: jest.fn()
}))

const mockedExecuteNodejsRequest = executeNodejsRequest as jest.MockedFunction<typeof executeNodejsRequest>

describe('BinaryFetchClient', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })

  function makeMockFetch (opts: {
    ok: boolean
    status: number
    statusText: string
    body: string
  }): jest.Mock {
    return jest.fn().mockResolvedValue({
      ok: opts.ok,
      status: opts.status,
      statusText: opts.statusText,
      text: async () => opts.body
    })
  }

  it('returns correct HttpClientResponse structure on successful response', async () => {
    const mockFetch = makeMockFetch({
      ok: true,
      status: 200,
      statusText: 'OK',
      body: 'response text'
    })

    const client = new BinaryFetchClient(mockFetch)
    const result = await client.request('https://example.com', { method: 'GET' })

    expect(result.ok).toBe(true)
    expect(result.status).toBe(200)
    expect(result.statusText).toBe('OK')
    expect(result.data).toBe('response text')
  })

  it('sends correct method to fetch', async () => {
    const mockFetch = makeMockFetch({ ok: true, status: 200, statusText: 'OK', body: '' })

    const client = new BinaryFetchClient(mockFetch)
    await client.request('https://example.com/endpoint', { method: 'POST' })

    const [, fetchOptions] = mockFetch.mock.calls[0]
    expect(fetchOptions.method).toBe('POST')
  })

  it('sends correct headers to fetch', async () => {
    const mockFetch = makeMockFetch({ ok: true, status: 200, statusText: 'OK', body: '' })
    const headers = { 'Content-Type': 'application/octet-stream', Authorization: 'Bearer token' }

    const client = new BinaryFetchClient(mockFetch)
    await client.request('https://example.com/endpoint', { method: 'PUT', headers })

    const [, fetchOptions] = mockFetch.mock.calls[0]
    expect(fetchOptions.headers).toEqual(headers)
  })

  it('sends data as body to fetch', async () => {
    const mockFetch = makeMockFetch({ ok: true, status: 200, statusText: 'OK', body: '' })
    const data = Buffer.from('binary data')

    const client = new BinaryFetchClient(mockFetch)
    await client.request('https://example.com/endpoint', { method: 'POST', data })

    const [, fetchOptions] = mockFetch.mock.calls[0]
    expect(fetchOptions.body).toBe(data)
  })

  it('sends correct URL to fetch', async () => {
    const mockFetch = makeMockFetch({ ok: true, status: 200, statusText: 'OK', body: '' })
    const url = 'https://example.com/api/v1/resource'

    const client = new BinaryFetchClient(mockFetch)
    await client.request(url, { method: 'GET' })

    const [calledUrl] = mockFetch.mock.calls[0]
    expect(calledUrl).toBe(url)
  })

  it('handles response.text() correctly and stores result as data', async () => {
    const responseBody = 'raw binary string content'
    const mockFetch = makeMockFetch({ ok: true, status: 200, statusText: 'OK', body: responseBody })

    const client = new BinaryFetchClient(mockFetch)
    const result = await client.request<string>('https://example.com', { method: 'GET' })

    expect(result.data).toBe(responseBody)
  })

  it('reflects non-ok response correctly', async () => {
    const mockFetch = makeMockFetch({
      ok: false,
      status: 404,
      statusText: 'Not Found',
      body: 'not found'
    })

    const client = new BinaryFetchClient(mockFetch)
    const result = await client.request('https://example.com/missing', { method: 'GET' })

    expect(result.ok).toBe(false)
    expect(result.status).toBe(404)
    expect(result.statusText).toBe('Not Found')
    expect(result.data).toBe('not found')
  })
})

describe('BinaryNodejsHttpClient', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })

  it('calls executeNodejsRequest with https module, url, options, and Buffer.from serializer', async () => {
    const mockHttps = {
      request: jest.fn()
    }

    const expectedResponse = { ok: true, status: 200, statusText: 'OK', data: Buffer.from('ok') }
    mockedExecuteNodejsRequest.mockResolvedValue(expectedResponse)

    const client = new BinaryNodejsHttpClient(mockHttps as any)
    const url = 'https://example.com/binary'
    const options = { method: 'POST', data: Buffer.from('payload') }

    const result = await client.request(url, options)

    expect(mockedExecuteNodejsRequest).toHaveBeenCalledTimes(1)
    const [httpsArg, urlArg, optionsArg, serializerArg] = mockedExecuteNodejsRequest.mock.calls[0]
    expect(httpsArg).toBe(mockHttps)
    expect(urlArg).toBe(url)
    expect(optionsArg).toBe(options)
    expect(typeof serializerArg).toBe('function')
    expect(result).toBe(expectedResponse)
  })

  it('serializer passed to executeNodejsRequest wraps data with Buffer.from', async () => {
    const mockHttps = { request: jest.fn() }
    mockedExecuteNodejsRequest.mockResolvedValue({
      ok: true, status: 200, statusText: 'OK', data: ''
    })

    const client = new BinaryNodejsHttpClient(mockHttps as any)
    await client.request('https://example.com', { method: 'GET' })

    const serializer = mockedExecuteNodejsRequest.mock.calls[0][3]
    const input = 'test input'
    const result = serializer(input)
    expect(result).toEqual(Buffer.from(input))
  })
})

describe('binaryHttpClient', () => {
  afterEach(() => {
    if ('window' in globalThis) {
      delete (globalThis as any).window
    }
  })

  it('returns a BinaryFetchClient when window.fetch is available', async () => {
    const mockFetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
      text: async () => 'binary content'
    })

    global.window = { fetch: mockFetch } as unknown as Window & typeof globalThis

    const client = binaryHttpClient()
    expect(client).toBeDefined()
    expect(client).toBeInstanceOf(BinaryFetchClient)
  })

  it('BinaryFetchClient returned by binaryHttpClient uses window.fetch', async () => {
    const mockFetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
      text: async () => 'content'
    })

    global.window = { fetch: mockFetch } as unknown as Window & typeof globalThis

    const client = binaryHttpClient()
    await client.request('https://example.com', { method: 'GET' })

    expect(mockFetch).toHaveBeenCalledTimes(1)
  })

  it('returns a BinaryNodejsHttpClient when window is absent but require is available (Node.js path)', async () => {
    if ('window' in globalThis) {
      delete (globalThis as any).window
    }

    const client = binaryHttpClient()
    expect(client).toBeDefined()
    expect(typeof client.request).toBe('function')
  })
})
