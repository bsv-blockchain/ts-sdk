import { toOriginHeader } from '../utils/toOriginHeader'

afterEach(() => jest.resetAllMocks())

type FetchMockCall = Parameters<typeof fetch> // alias for readability

async function okJson (body: unknown = {}) {
  return await Promise.resolve({
    ok: true,
    status: 200,
    json: async () => await Promise.resolve(body)
  } as Response)
}

describe('toOriginHeader()', () => {
  const vectors: Array<[originator: string, baseUrl: string, expected: string | undefined]> = [
    /* originator,                     baseUrl,                      expected */
    ['localhost', 'http://localhost:3321', 'http://localhost'],
    ['localhost:3000', 'http://localhost:3321', 'http://localhost:3000'],
    ['example.com', 'https://api.example.com', 'https://example.com'],
    ['https://example.com:8443', 'http://localhost:3321', 'https://example.com:8443']
    // ["metanet://somehost", "http://localhost:3321", "metanet://somehost"], // TODO: Consider adding support in the future
  ]

  it.each(vectors)('originator=%p, baseUrl=%p → %p', (originator, baseUrl, expected) => {
    const schemeFromBase = new URL(baseUrl).protocol.replace(':', '')
    const result = toOriginHeader(originator, schemeFromBase)
    expect(result).toBe(expected)
  })

  it('throws on clearly malformed input', () => {
    expect(() => toOriginHeader('bad url^%', 'http')).toThrow()
  })
})
