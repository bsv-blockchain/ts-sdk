import { defaultHttpClient } from '../../../transaction/http/DefaultHttpClient'

describe('defaultHttpClient', () => {
  afterEach(() => {
    // Restore window if it was set
    if ('window' in globalThis) {
      delete (globalThis as any).window
    }
  })

  it('returns a FetchHttpClient (with a request method) when window.fetch is available', async () => {
    const mockFetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: {
        get: (_key: string) => 'application/json'
      },
      json: async () => ({ result: 'ok' })
    })

    global.window = { fetch: mockFetch } as unknown as Window & typeof globalThis

    const client = defaultHttpClient()
    expect(client).toBeDefined()
    expect(typeof client.request).toBe('function')

    // Verify it actually uses the window.fetch by making a request
    await client.request('https://example.com', { method: 'GET' })
    expect(mockFetch).toHaveBeenCalledTimes(1)
  })

  it('returns an httpClient whose request() uses the bound window.fetch', async () => {
    const mockFetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: {
        get: (_key: string) => null
      },
      text: async () => 'plain text body'
    })

    global.window = { fetch: mockFetch } as unknown as Window & typeof globalThis

    const client = defaultHttpClient()
    const response = await client.request('https://example.com/api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      data: { foo: 'bar' }
    })

    expect(mockFetch).toHaveBeenCalledTimes(1)
    const [calledUrl, calledOptions] = mockFetch.mock.calls[0]
    expect(calledUrl).toBe('https://example.com/api')
    expect(calledOptions.method).toBe('POST')
    expect(response.ok).toBe(true)
    expect(response.status).toBe(200)
  })

  it('returns a NodejsHttpClient when window is absent but require is available (Node.js path)', async () => {
    // Remove window to force the Node.js path
    if ('window' in globalThis) {
      delete (globalThis as any).window
    }

    const client = defaultHttpClient()
    expect(client).toBeDefined()
    expect(typeof client.request).toBe('function')
  })
})
