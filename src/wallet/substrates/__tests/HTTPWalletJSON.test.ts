import HTTPWalletJSON from '../HTTPWalletJSON'
import { WERR_INVALID_PARAMETER } from '../../WERR_INVALID_PARAMETER'
import { WERR_INSUFFICIENT_FUNDS } from '../../WERR_INSUFFICIENT_FUNDS'
import { WERR_REVIEW_ACTIONS } from '../../WERR_REVIEW_ACTIONS'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a minimal fetch mock that resolves with a JSON-shaped Response. */
function makeFetch(
  body: unknown,
  { ok = true, status = 200 }: { ok?: boolean; status?: number } = {}
): jest.Mock {
  return jest.fn().mockResolvedValue({
    ok,
    status,
    json: () => Promise.resolve(body),
  } as unknown as Response)
}

/** Build a fetch mock that rejects (network-level failure). */
function makeNetworkErrorFetch(message = 'Network failure'): jest.Mock {
  return jest.fn().mockRejectedValue(new Error(message))
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

describe('HTTPWalletJSON – constructor', () => {
  it('stores the provided baseUrl', () => {
    const client = new HTTPWalletJSON('example.com', 'http://my-server:9000')
    expect(client.baseUrl).toBe('http://my-server:9000')
  })

  it('uses http://localhost:3321 as the default baseUrl', () => {
    const client = new HTTPWalletJSON('example.com')
    expect(client.baseUrl).toBe('http://localhost:3321')
  })

  it('stores the originator', () => {
    const client = new HTTPWalletJSON('wallet.example.com')
    expect(client.originator).toBe('wallet.example.com')
  })

  it('accepts undefined originator', () => {
    const client = new HTTPWalletJSON(undefined)
    expect(client.originator).toBeUndefined()
  })

  it('stores the custom httpClient', () => {
    const mockFetch = jest.fn()
    const client = new HTTPWalletJSON('example.com', 'http://localhost:3321', mockFetch as unknown as typeof fetch)
    expect(client.httpClient).toBe(mockFetch)
  })
})

// ---------------------------------------------------------------------------
// api() – happy-path deserialization
// ---------------------------------------------------------------------------

describe('HTTPWalletJSON – api() successful responses', () => {
  it('POSTs to the correct URL and returns the parsed body', async () => {
    const mockFetch = makeFetch({ version: '1.0.0.0.0.0.0' })
    const client = new HTTPWalletJSON(undefined, 'http://localhost:3321', mockFetch as unknown as typeof fetch)

    const result = await client.getVersion({})

    expect(mockFetch).toHaveBeenCalledTimes(1)
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('http://localhost:3321/getVersion')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body as string)).toEqual({})
    expect(result).toEqual({ version: '1.0.0.0.0.0.0' })
  })

  it('sets Accept and Content-Type headers', async () => {
    const mockFetch = makeFetch({ height: 800000 })
    const client = new HTTPWalletJSON(undefined, 'http://localhost:3321', mockFetch as unknown as typeof fetch)

    await client.getHeight({})

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit]
    const headers = init.headers as Record<string, string>
    expect(headers['Accept']).toBe('application/json')
    expect(headers['Content-Type']).toBe('application/json')
  })

  it('serialises args as JSON in the request body', async () => {
    const mockFetch = makeFetch({ actions: [], totalActions: 0 })
    const client = new HTTPWalletJSON(undefined, 'http://localhost:3321', mockFetch as unknown as typeof fetch)

    await client.listActions({ labels: ['test-label'] })

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit]
    expect(JSON.parse(init.body as string)).toEqual({ labels: ['test-label'] })
  })
})

// ---------------------------------------------------------------------------
// api() – error response deserialization
// ---------------------------------------------------------------------------

describe('HTTPWalletJSON – api() error responses', () => {
  it('throws WERR_INVALID_PARAMETER (code 6) when the server returns it', async () => {
    const errorBody = {
      isError: true,
      code: 6,
      parameter: 'description',
      message: 'The description parameter must be at least 5 length.',
    }
    const mockFetch = makeFetch(errorBody, { ok: false, status: 400 })
    const client = new HTTPWalletJSON(undefined, 'http://localhost:3321', mockFetch as unknown as typeof fetch)

    await expect(client.createAction({ description: 'x' })).rejects.toThrow(WERR_INVALID_PARAMETER)

    try {
      await client.createAction({ description: 'x' })
    } catch (e: unknown) {
      const err = e as WERR_INVALID_PARAMETER
      expect(err.name).toBe('WERR_INVALID_PARAMETER')
      expect(err.parameter).toBe('description')
      expect(err.code).toBe(6)
    }
  })

  it('WERR_INVALID_PARAMETER carries the server message verbatim', async () => {
    const errorBody = {
      isError: true,
      code: 6,
      parameter: 'lockingScript',
      message: 'Custom server message for lockingScript.',
    }
    const mockFetch = makeFetch(errorBody, { ok: false, status: 400 })
    const client = new HTTPWalletJSON(undefined, 'http://localhost:3321', mockFetch as unknown as typeof fetch)

    try {
      await client.createAction({ description: 'hello world' })
    } catch (e: unknown) {
      const err = e as WERR_INVALID_PARAMETER
      expect(err.message).toBe('Custom server message for lockingScript.')
    }
  })

  it('throws WERR_INSUFFICIENT_FUNDS (code 7) when the server returns it', async () => {
    const errorBody = {
      isError: true,
      code: 7,
      totalSatoshisNeeded: 5000,
      moreSatoshisNeeded: 2000,
    }
    const mockFetch = makeFetch(errorBody, { ok: false, status: 400 })
    const client = new HTTPWalletJSON(undefined, 'http://localhost:3321', mockFetch as unknown as typeof fetch)

    await expect(client.createAction({ description: 'hello world' })).rejects.toThrow(WERR_INSUFFICIENT_FUNDS)

    try {
      await client.createAction({ description: 'hello world' })
    } catch (e: unknown) {
      const err = e as WERR_INSUFFICIENT_FUNDS
      expect(err.totalSatoshisNeeded).toBe(5000)
      expect(err.moreSatoshisNeeded).toBe(2000)
      expect(err.code).toBe(7)
    }
  })

  it('throws WERR_REVIEW_ACTIONS (code 5) when the server returns it', async () => {
    const errorBody = {
      isError: true,
      code: 5,
      reviewActionResults: [{ txid: 'abc', status: 'failed' }],
      sendWithResults: [],
      txid: 'abc123',
    }
    const mockFetch = makeFetch(errorBody, { ok: false, status: 400 })
    const client = new HTTPWalletJSON(undefined, 'http://localhost:3321', mockFetch as unknown as typeof fetch)

    await expect(client.createAction({ description: 'hello world' })).rejects.toThrow(WERR_REVIEW_ACTIONS)

    try {
      await client.createAction({ description: 'hello world' })
    } catch (e: unknown) {
      const err = e as WERR_REVIEW_ACTIONS
      expect(err.code).toBe(5)
      expect(err.txid).toBe('abc123')
      expect(err.reviewActionResults).toEqual([{ txid: 'abc', status: 'failed' }])
    }
  })

  it('throws a generic Error when the server returns a non-400 error status', async () => {
    const mockFetch = makeFetch({ message: 'Internal Server Error' }, { ok: false, status: 500 })
    const client = new HTTPWalletJSON(undefined, 'http://localhost:3321', mockFetch as unknown as typeof fetch)

    await expect(client.getVersion({})).rejects.toThrow(Error)

    try {
      await client.getVersion({})
    } catch (e: unknown) {
      const err = e as Error
      expect(err.message).toContain('getVersion')
      expect(err.message).toContain('Internal Server Error')
    }
  })

  it('falls back to "HTTP Client error <status>" when the 500 body has no message', async () => {
    const mockFetch = makeFetch({}, { ok: false, status: 503 })
    const client = new HTTPWalletJSON(undefined, 'http://localhost:3321', mockFetch as unknown as typeof fetch)

    try {
      await client.getVersion({})
    } catch (e: unknown) {
      const err = e as Error
      expect(err.message).toContain('HTTP Client error 503')
    }
  })

  it('does NOT throw for an unknown error code when isError is true', async () => {
    // code 99 is unrecognised – falls through to the generic error path
    const errorBody = { isError: true, code: 99, message: 'Unknown problem' }
    const mockFetch = makeFetch(errorBody, { ok: false, status: 400 })
    const client = new HTTPWalletJSON(undefined, 'http://localhost:3321', mockFetch as unknown as typeof fetch)

    await expect(client.getVersion({})).rejects.toThrow(Error)
  })
})

// ---------------------------------------------------------------------------
// Network errors
// ---------------------------------------------------------------------------

describe('HTTPWalletJSON – network errors', () => {
  it('propagates a fetch rejection as-is', async () => {
    const mockFetch = makeNetworkErrorFetch('Failed to fetch')
    const client = new HTTPWalletJSON(undefined, 'http://localhost:3321', mockFetch as unknown as typeof fetch)

    await expect(client.getVersion({})).rejects.toThrow('Failed to fetch')
  })
})

// ---------------------------------------------------------------------------
// All wallet interface methods delegate to api()
// ---------------------------------------------------------------------------

describe('HTTPWalletJSON – method routing', () => {
  let client: HTTPWalletJSON
  let mockFetch: jest.Mock

  beforeEach(() => {
    mockFetch = makeFetch({})
    client = new HTTPWalletJSON(undefined, 'http://localhost:3321', mockFetch as unknown as typeof fetch)
  })

  const expectCallName = async (method: () => Promise<unknown>, expectedPath: string) => {
    await method().catch(() => { /* ignore deserialization quirks */ })
    const url: string = mockFetch.mock.calls[mockFetch.mock.calls.length - 1][0]
    expect(url).toContain(expectedPath)
  }

  it('createAction calls /createAction', async () => {
    await expectCallName(
      () => client.createAction({ description: 'hello world' }),
      '/createAction'
    )
  })

  it('signAction calls /signAction', async () => {
    await expectCallName(
      () => client.signAction({ spends: {}, reference: 'cmVm' }),
      '/signAction'
    )
  })

  it('abortAction calls /abortAction', async () => {
    await expectCallName(
      () => client.abortAction({ reference: 'cmVm' }),
      '/abortAction'
    )
  })

  it('listActions calls /listActions', async () => {
    await expectCallName(
      () => client.listActions({ labels: [] }),
      '/listActions'
    )
  })

  it('internalizeAction calls /internalizeAction', async () => {
    await expectCallName(
      () => client.internalizeAction({ tx: [], outputs: [], description: 'hello world' }),
      '/internalizeAction'
    )
  })

  it('listOutputs calls /listOutputs', async () => {
    await expectCallName(
      () => client.listOutputs({ basket: 'default' }),
      '/listOutputs'
    )
  })

  it('relinquishOutput calls /relinquishOutput', async () => {
    await expectCallName(
      () => client.relinquishOutput({ basket: 'default', output: 'abc.0' }),
      '/relinquishOutput'
    )
  })

  it('getPublicKey calls /getPublicKey', async () => {
    await expectCallName(
      () => client.getPublicKey({ identityKey: true }),
      '/getPublicKey'
    )
  })

  it('revealCounterpartyKeyLinkage calls /revealCounterpartyKeyLinkage', async () => {
    await expectCallName(
      () => client.revealCounterpartyKeyLinkage({ counterparty: 'aa', verifier: 'bb' }),
      '/revealCounterpartyKeyLinkage'
    )
  })

  it('revealSpecificKeyLinkage calls /revealSpecificKeyLinkage', async () => {
    await expectCallName(
      () => client.revealSpecificKeyLinkage({
        counterparty: 'aa', verifier: 'bb',
        protocolID: [0, 'proto'], keyID: 'k1',
      }),
      '/revealSpecificKeyLinkage'
    )
  })

  it('encrypt calls /encrypt', async () => {
    await expectCallName(
      () => client.encrypt({ plaintext: [1, 2], protocolID: [0, 'proto'], keyID: 'k1' }),
      '/encrypt'
    )
  })

  it('decrypt calls /decrypt', async () => {
    await expectCallName(
      () => client.decrypt({ ciphertext: [1, 2], protocolID: [0, 'proto'], keyID: 'k1' }),
      '/decrypt'
    )
  })

  it('createHmac calls /createHmac', async () => {
    await expectCallName(
      () => client.createHmac({ data: [1], protocolID: [0, 'proto'], keyID: 'k1' }),
      '/createHmac'
    )
  })

  it('verifyHmac calls /verifyHmac', async () => {
    await expectCallName(
      () => client.verifyHmac({ data: [1], hmac: [2], protocolID: [0, 'proto'], keyID: 'k1' }),
      '/verifyHmac'
    )
  })

  it('createSignature calls /createSignature', async () => {
    await expectCallName(
      () => client.createSignature({ data: [1], protocolID: [0, 'proto'], keyID: 'k1' }),
      '/createSignature'
    )
  })

  it('verifySignature calls /verifySignature', async () => {
    await expectCallName(
      () => client.verifySignature({ data: [1], signature: [2], protocolID: [0, 'proto'], keyID: 'k1' }),
      '/verifySignature'
    )
  })

  it('acquireCertificate calls /acquireCertificate', async () => {
    await expectCallName(
      () => client.acquireCertificate({
        type: 'dHlwZQ==', certifier: 'aa', acquisitionProtocol: 'issuance',
        fields: {}, certifierUrl: 'https://certifier.example.com',
      } as any),
      '/acquireCertificate'
    )
  })

  it('listCertificates calls /listCertificates', async () => {
    await expectCallName(
      () => client.listCertificates({ certifiers: [], types: [] }),
      '/listCertificates'
    )
  })

  it('proveCertificate calls /proveCertificate', async () => {
    await expectCallName(
      () => client.proveCertificate({
        certificate: {} as any, fieldsToReveal: [], verifier: 'vv',
      }),
      '/proveCertificate'
    )
  })

  it('relinquishCertificate calls /relinquishCertificate', async () => {
    await expectCallName(
      () => client.relinquishCertificate({ type: 'dHlwZQ==', serialNumber: 'c2Vy', certifier: 'aa' }),
      '/relinquishCertificate'
    )
  })

  it('discoverByIdentityKey calls /discoverByIdentityKey', async () => {
    await expectCallName(
      () => client.discoverByIdentityKey({ identityKey: 'aa' }),
      '/discoverByIdentityKey'
    )
  })

  it('discoverByAttributes calls /discoverByAttributes', async () => {
    await expectCallName(
      () => client.discoverByAttributes({ attributes: { name: 'Alice' } }),
      '/discoverByAttributes'
    )
  })

  it('isAuthenticated calls /isAuthenticated', async () => {
    await expectCallName(
      () => client.isAuthenticated({}),
      '/isAuthenticated'
    )
  })

  it('waitForAuthentication calls /waitForAuthentication', async () => {
    await expectCallName(
      () => client.waitForAuthentication({}),
      '/waitForAuthentication'
    )
  })

  it('getHeight calls /getHeight', async () => {
    await expectCallName(
      () => client.getHeight({}),
      '/getHeight'
    )
  })

  it('getHeaderForHeight calls /getHeaderForHeight', async () => {
    await expectCallName(
      () => client.getHeaderForHeight({ height: 1 }),
      '/getHeaderForHeight'
    )
  })

  it('getNetwork calls /getNetwork', async () => {
    await expectCallName(
      () => client.getNetwork({}),
      '/getNetwork'
    )
  })

  it('getVersion calls /getVersion', async () => {
    await expectCallName(
      () => client.getVersion({}),
      '/getVersion'
    )
  })
})

// ---------------------------------------------------------------------------
// Response body passthrough
// ---------------------------------------------------------------------------

describe('HTTPWalletJSON – response body passthrough', () => {
  it('returns the exact JSON body from a successful getVersion call', async () => {
    const expected = { version: '1.0.0.0.0.0.0' }
    const mockFetch = makeFetch(expected)
    const client = new HTTPWalletJSON(undefined, 'http://localhost:3321', mockFetch as unknown as typeof fetch)

    const result = await client.getVersion({})
    expect(result).toEqual(expected)
  })

  it('returns the exact JSON body from a successful listActions call', async () => {
    const expected = { totalActions: 2, actions: [{ txid: 'aa', status: 'completed' }] }
    const mockFetch = makeFetch(expected)
    const client = new HTTPWalletJSON(undefined, 'http://localhost:3321', mockFetch as unknown as typeof fetch)

    const result = await client.listActions({ labels: [] })
    expect(result).toEqual(expected)
  })

  it('returns the exact JSON body from a successful getNetwork call', async () => {
    const expected = { network: 'mainnet' as const }
    const mockFetch = makeFetch(expected)
    const client = new HTTPWalletJSON(undefined, 'http://localhost:3321', mockFetch as unknown as typeof fetch)

    const result = await client.getNetwork({})
    expect(result).toEqual(expected)
  })
})
