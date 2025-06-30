import LookupResolver, {
  HTTPSOverlayLookupFacilitator
} from '../LookupResolver'
import OverlayAdminTokenTemplate from '../../overlay-tools/OverlayAdminTokenTemplate'
import { CompletedProtoWallet } from '../../auth/certificates/__tests/CompletedProtoWallet'
import { PrivateKey } from '../../primitives/index'
import { Transaction } from '../../transaction/index'
import { LockingScript } from '../../script/index'

const mockFacilitator = {
  lookup: jest.fn()
}

const sampleBeef1 = new Transaction(
  1,
  [],
  [{ lockingScript: LockingScript.fromHex('88'), satoshis: 1 }],
  0
).toBEEF()
const sampleBeef2 = new Transaction(
  1,
  [],
  [{ lockingScript: LockingScript.fromHex('88'), satoshis: 2 }],
  0
).toBEEF()
const sampleBeef3 = new Transaction(
  1,
  [],
  [{ lockingScript: LockingScript.fromHex('88'), satoshis: 3 }],
  0
).toBEEF()
const sampleBeef4 = new Transaction(
  1,
  [],
  [{ lockingScript: LockingScript.fromHex('88'), satoshis: 4 }],
  0
).toBEEF()

describe('LookupResolver', () => {
  beforeEach(() => {
    mockFacilitator.lookup.mockReset()
  })

  it('should query the host and return the response when a single host is found via SLAP', async () => {
    const slapHostKey = new PrivateKey(42)
    const slapWallet = new CompletedProtoWallet(slapHostKey)
    const slapLib = new OverlayAdminTokenTemplate(slapWallet)
    const slapScript = await slapLib.lock(
      'SLAP',
      'https://slaphost.com',
      'ls_foo'
    )
    const slapTx = new Transaction(
      1,
      [],
      [
        {
          lockingScript: slapScript,
          satoshis: 1
        }
      ],
      0
    )

    mockFacilitator.lookup
      .mockReturnValueOnce({
        type: 'output-list',
        outputs: [
          {
            outputIndex: 0,
            beef: slapTx.toBEEF()
          }
        ]
      })
      .mockReturnValueOnce({
        type: 'output-list',
        outputs: [
          {
            beef: sampleBeef1,
            outputIndex: 0
          }
        ]
      })

    const r = new LookupResolver({
      facilitator: mockFacilitator,
      slapTrackers: ['https://mock.slap']
    })
    const res = await r.query({
      service: 'ls_foo',
      query: { test: 1 }
    })
    expect(res).toEqual({
      type: 'output-list',
      outputs: [
        {
          beef: sampleBeef1,
          outputIndex: 0
        }
      ]
    })
    expect(mockFacilitator.lookup.mock.calls).toEqual([
      [
        'https://mock.slap',
        {
          service: 'ls_slap',
          query: {
            service: 'ls_foo'
          }
        },
        5000
      ],
      [
        'https://slaphost.com',
        {
          service: 'ls_foo',
          query: {
            test: 1
          }
        },
        undefined
      ]
    ])
  })

  it('should query from provided additional hosts while still making use of SLAP', async () => {
    const slapHostKey = new PrivateKey(42)
    const slapWallet = new CompletedProtoWallet(slapHostKey)
    const slapLib = new OverlayAdminTokenTemplate(slapWallet)
    const slapScript = await slapLib.lock(
      'SLAP',
      'https://slaphost.com',
      'ls_foo'
    )
    const slapTx = new Transaction(
      1,
      [],
      [
        {
          lockingScript: slapScript,
          satoshis: 1
        }
      ],
      0
    )

    mockFacilitator.lookup
      .mockReturnValueOnce({
        type: 'output-list',
        outputs: [
          {
            outputIndex: 0,
            beef: slapTx.toBEEF()
          }
        ]
      })
      .mockReturnValueOnce({
        type: 'output-list',
        outputs: [
          {
            beef: sampleBeef1,
            outputIndex: 0
          }
        ]
      })
      .mockReturnValueOnce({
        type: 'output-list',
        outputs: [
          {
            // duplicate the output the other host knows about
            beef: sampleBeef1,
            outputIndex: 0
          },
          {
            // the additional host also knows about a second output
            beef: sampleBeef2,
            outputIndex: 1033
          }
        ]
      })

    const r = new LookupResolver({
      facilitator: mockFacilitator,
      slapTrackers: ['https://mock.slap'],
      additionalHosts: {
        ls_foo: ['https://additional.host']
      }
    })
    const res = await r.query({
      service: 'ls_foo',
      query: { test: 1 }
    })
    expect(res).toEqual({
      type: 'output-list',
      outputs: [
        {
          // expect the first output to appear only once, and be de-duplicated
          beef: sampleBeef1,
          outputIndex: 0
        },
        {
          // also expect the second output from the additional host
          beef: sampleBeef2,
          outputIndex: 1033
        }
      ]
    })
    expect(mockFacilitator.lookup.mock.calls).toEqual([
      [
        'https://mock.slap',
        {
          service: 'ls_slap',
          query: {
            service: 'ls_foo'
          }
        },
        5000
      ],
      [
        'https://slaphost.com',
        {
          service: 'ls_foo',
          query: {
            test: 1
          }
        },
        undefined
      ],
      [
        // additional host should also have been queried
        'https://additional.host',
        {
          service: 'ls_foo',
          query: {
            test: 1
          }
        },
        undefined
      ]
    ])
  })

  it('should utilize host overrides instead of SLAP', async () => {
    mockFacilitator.lookup.mockReturnValueOnce({
      type: 'output-list',
      outputs: [
        {
          beef: sampleBeef1,
          outputIndex: 0
        }
      ]
    })

    const r = new LookupResolver({
      facilitator: mockFacilitator,
      slapTrackers: ['https://mock.slap'],
      hostOverrides: {
        ls_foo: ['https://override.host']
      }
    })
    const res = await r.query({
      service: 'ls_foo',
      query: { test: 1 }
    })
    expect(res).toEqual({
      type: 'output-list',
      outputs: [
        {
          beef: sampleBeef1,
          outputIndex: 0
        }
      ]
    })
    expect(mockFacilitator.lookup.mock.calls).toEqual([
      [
        'https://override.host',
        {
          service: 'ls_foo',
          query: {
            test: 1
          }
        },
        undefined
      ]
    ])
  })

  it('should allow using host overrides with additional hosts at the same time', async () => {
    mockFacilitator.lookup
      .mockReturnValueOnce({
        type: 'output-list', // from the override host
        outputs: [
          {
            beef: sampleBeef1,
            outputIndex: 0
          }
        ]
      })
      .mockReturnValueOnce({
        type: 'output-list', // from the additional host
        outputs: [
          {
            beef: sampleBeef1,
            outputIndex: 0
          },
          {
            beef: sampleBeef2,
            outputIndex: 1033
          }
        ]
      })

    const r = new LookupResolver({
      facilitator: mockFacilitator,
      slapTrackers: ['https://mock.slap'],
      additionalHosts: {
        ls_foo: ['https://additional.host']
      },
      hostOverrides: {
        ls_foo: ['https://override.host']
      }
    })
    const res = await r.query({
      service: 'ls_foo',
      query: { test: 1 }
    })
    expect(res).toEqual({
      type: 'output-list',
      outputs: [
        {
          // expect the first output to appear only once, and be de-duplicated
          beef: sampleBeef1,
          outputIndex: 0
        },
        {
          // also expect the second output from the additional host
          beef: sampleBeef2,
          outputIndex: 1033
        }
      ]
    })
    expect(mockFacilitator.lookup.mock.calls).toEqual([
      [
        'https://override.host',
        {
          service: 'ls_foo',
          query: {
            test: 1
          }
        },
        undefined
      ],
      [
        // additional host should also have been queried
        'https://additional.host',
        {
          service: 'ls_foo',
          query: {
            test: 1
          }
        },
        undefined
      ]
    ])
  })

  it('should handle multiple SLAP trackers and aggregate results from multiple hosts', async () => {
    const slapHostKey1 = new PrivateKey(42)
    const slapWallet1 = new CompletedProtoWallet(slapHostKey1)
    const slapLib1 = new OverlayAdminTokenTemplate(slapWallet1)
    const slapScript1 = await slapLib1.lock(
      'SLAP',
      'https://slaphost1.com',
      'ls_foo'
    )
    const slapTx1 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: slapScript1,
          satoshis: 1
        }
      ],
      0
    )

    const slapHostKey2 = new PrivateKey(43)
    const slapWallet2 = new CompletedProtoWallet(slapHostKey2)
    const slapLib2 = new OverlayAdminTokenTemplate(slapWallet2)
    const slapScript2 = await slapLib2.lock(
      'SLAP',
      'https://slaphost2.com',
      'ls_foo'
    )
    const slapTx2 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: slapScript2,
          satoshis: 1
        }
      ],
      0
    )

    // SLAP trackers return hosts
    mockFacilitator.lookup
      .mockReturnValueOnce({
        type: 'output-list',
        outputs: [
          {
            outputIndex: 0,
            beef: slapTx1.toBEEF()
          }
        ]
      })
      .mockReturnValueOnce({
        type: 'output-list',
        outputs: [
          {
            outputIndex: 0,
            beef: slapTx2.toBEEF()
          }
        ]
      })

    // Hosts respond to the query
    mockFacilitator.lookup
      .mockReturnValueOnce({
        type: 'output-list',
        outputs: [
          {
            beef: sampleBeef3,
            outputIndex: 0
          }
        ]
      })
      .mockReturnValueOnce({
        type: 'output-list',
        outputs: [
          {
            beef: sampleBeef4,
            outputIndex: 1
          }
        ]
      })

    const r = new LookupResolver({
      facilitator: mockFacilitator,
      slapTrackers: ['https://mock.slap1', 'https://mock.slap2']
    })

    const res = await r.query({
      service: 'ls_foo',
      query: { test: 1 }
    })

    expect(res).toEqual({
      type: 'output-list',
      outputs: [
        { beef: sampleBeef3, outputIndex: 0 },
        { beef: sampleBeef4, outputIndex: 1 }
      ]
    })

    expect(mockFacilitator.lookup.mock.calls).toEqual([
      [
        'https://mock.slap1',
        {
          service: 'ls_slap',
          query: {
            service: 'ls_foo'
          }
        },
        5000
      ],
      [
        'https://mock.slap2',
        {
          service: 'ls_slap',
          query: {
            service: 'ls_foo'
          }
        },
        5000
      ],
      [
        'https://slaphost1.com',
        {
          service: 'ls_foo',
          query: {
            test: 1
          }
        },
        undefined
      ],
      [
        'https://slaphost2.com',
        {
          service: 'ls_foo',
          query: {
            test: 1
          }
        },
        undefined
      ]
    ])
  })

  it('should de-duplicate outputs from multiple hosts', async () => {
    const slapHostKey1 = new PrivateKey(42)
    const slapWallet1 = new CompletedProtoWallet(slapHostKey1)
    const slapLib1 = new OverlayAdminTokenTemplate(slapWallet1)
    const slapScript1 = await slapLib1.lock(
      'SLAP',
      'https://slaphost1.com',
      'ls_foo'
    )
    const slapTx1 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: slapScript1,
          satoshis: 1
        }
      ],
      0
    )

    const slapHostKey2 = new PrivateKey(43)
    const slapWallet2 = new CompletedProtoWallet(slapHostKey2)
    const slapLib2 = new OverlayAdminTokenTemplate(slapWallet2)
    const slapScript2 = await slapLib2.lock(
      'SLAP',
      'https://slaphost2.com',
      'ls_foo'
    )
    const slapTx2 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: slapScript2,
          satoshis: 1
        }
      ],
      0
    )

    // SLAP tracker returns two hosts
    mockFacilitator.lookup.mockReturnValueOnce({
      type: 'output-list',
      outputs: [
        { outputIndex: 0, beef: slapTx1.toBEEF() },
        { outputIndex: 0, beef: slapTx2.toBEEF() }
      ]
    })

    // Both hosts return the same output
    const duplicateOutput = { beef: sampleBeef3, outputIndex: 0 }
    mockFacilitator.lookup
      .mockReturnValueOnce({
        type: 'output-list',
        outputs: [duplicateOutput]
      })
      .mockReturnValueOnce({
        type: 'output-list',
        outputs: [duplicateOutput]
      })

    const r = new LookupResolver({
      facilitator: mockFacilitator,
      slapTrackers: ['https://mock.slap']
    })

    const res = await r.query({
      service: 'ls_foo',
      query: { test: 1 }
    })

    expect(res).toEqual({
      type: 'output-list',
      outputs: [duplicateOutput]
    })

    expect(mockFacilitator.lookup.mock.calls).toEqual([
      [
        'https://mock.slap',
        {
          service: 'ls_slap',
          query: {
            service: 'ls_foo'
          }
        },
        5000
      ],
      [
        'https://slaphost1.com',
        {
          service: 'ls_foo',
          query: {
            test: 1
          }
        },
        undefined
      ],
      [
        'https://slaphost2.com',
        {
          service: 'ls_foo',
          query: {
            test: 1
          }
        },
        undefined
      ]
    ])
  })

  it('should ignore freeform responses when first response is output-list', async () => {
    const slapHostKey1 = new PrivateKey(42)
    const slapWallet1 = new CompletedProtoWallet(slapHostKey1)
    const slapLib1 = new OverlayAdminTokenTemplate(slapWallet1)
    const slapScript1 = await slapLib1.lock(
      'SLAP',
      'https://slaphost1.com',
      'ls_foo'
    )
    const slapTx1 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: slapScript1,
          satoshis: 1
        }
      ],
      0
    )

    const slapHostKey2 = new PrivateKey(43)
    const slapWallet2 = new CompletedProtoWallet(slapHostKey2)
    const slapLib2 = new OverlayAdminTokenTemplate(slapWallet2)
    const slapScript2 = await slapLib2.lock(
      'SLAP',
      'https://slaphost2.com',
      'ls_foo'
    )
    const slapTx2 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: slapScript2,
          satoshis: 1
        }
      ],
      0
    )

    // SLAP tracker returns two hosts
    mockFacilitator.lookup.mockReturnValueOnce({
      type: 'output-list',
      outputs: [
        { outputIndex: 0, beef: slapTx1.toBEEF() },
        { outputIndex: 0, beef: slapTx2.toBEEF() }
      ]
    })

    // First host returns 'output-list' response
    mockFacilitator.lookup.mockReturnValueOnce({
      type: 'output-list',
      outputs: [{ beef: sampleBeef3, outputIndex: 0 }]
    })

    // Second host returns 'freeform' response
    mockFacilitator.lookup.mockReturnValueOnce({
      type: 'freeform',
      result: { message: 'Freeform response from host2' }
    })

    const r = new LookupResolver({
      facilitator: mockFacilitator,
      slapTrackers: ['https://mock.slap']
    })

    const res = await r.query({
      service: 'ls_foo',
      query: { test: 1 }
    })

    expect(res).toEqual({
      type: 'output-list',
      outputs: [{ beef: sampleBeef3, outputIndex: 0 }]
    })

    expect(mockFacilitator.lookup.mock.calls).toEqual([
      [
        'https://mock.slap',
        {
          service: 'ls_slap',
          query: {
            service: 'ls_foo'
          }
        },
        5000
      ],
      [
        'https://slaphost1.com',
        {
          service: 'ls_foo',
          query: {
            test: 1
          }
        },
        undefined
      ],
      [
        'https://slaphost2.com',
        {
          service: 'ls_foo',
          query: {
            test: 1
          }
        },
        undefined
      ]
    ])
  })

  it('should throw an error when no competent hosts are found', async () => {
    // SLAP tracker returns empty output-list
    mockFacilitator.lookup.mockReturnValueOnce({
      type: 'output-list',
      outputs: []
    })

    const r = new LookupResolver({
      facilitator: mockFacilitator,
      slapTrackers: ['https://mock.slap']
    })

    await expect(
      r.query({
        service: 'ls_foo',
        query: { test: 1 }
      })
    ).rejects.toThrow(
      'No competent mainnet hosts found by the SLAP trackers for lookup service: ls_foo'
    )

    expect(mockFacilitator.lookup.mock.calls).toEqual([
      [
        'https://mock.slap',
        {
          service: 'ls_slap',
          query: {
            service: 'ls_foo'
          }
        },
        5000
      ]
    ])
  })

  it('should not throw an error when one host fails to respond', async () => {
    const slapHostKey1 = new PrivateKey(42)
    const slapWallet1 = new CompletedProtoWallet(slapHostKey1)
    const slapLib1 = new OverlayAdminTokenTemplate(slapWallet1)
    const slapScript1 = await slapLib1.lock(
      'SLAP',
      'https://slaphost1.com',
      'ls_foo'
    )
    const slapTx1 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: slapScript1,
          satoshis: 1
        }
      ],
      0
    )

    const slapHostKey2 = new PrivateKey(43)
    const slapWallet2 = new CompletedProtoWallet(slapHostKey2)
    const slapLib2 = new OverlayAdminTokenTemplate(slapWallet2)
    const slapScript2 = await slapLib2.lock(
      'SLAP',
      'https://slaphost2.com',
      'ls_foo'
    )
    const slapTx2 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: slapScript2,
          satoshis: 1
        }
      ],
      0
    )

    // SLAP tracker returns two hosts
    mockFacilitator.lookup.mockReturnValueOnce({
      type: 'output-list',
      outputs: [
        { outputIndex: 0, beef: slapTx1.toBEEF() },
        { outputIndex: 0, beef: slapTx2.toBEEF() }
      ]
    })

    // First host responds successfully
    mockFacilitator.lookup.mockReturnValueOnce({
      type: 'output-list',
      outputs: [{ beef: sampleBeef3, outputIndex: 0 }]
    })

    // Second host fails to respond
    mockFacilitator.lookup.mockImplementationOnce(async () => {
      throw new Error('Host2 failed to respond')
    })

    const r = new LookupResolver({
      facilitator: mockFacilitator,
      slapTrackers: ['https://mock.slap']
    })

    const res = await r.query({
      service: 'ls_foo',
      query: { test: 1 }
    })

    expect(res).toEqual({
      type: 'output-list',
      outputs: [
        {
          beef: sampleBeef3,
          outputIndex: 0
        }
      ]
    })

    expect(mockFacilitator.lookup.mock.calls).toEqual([
      [
        'https://mock.slap',
        {
          service: 'ls_slap',
          query: {
            service: 'ls_foo'
          }
        },
        5000
      ],
      [
        'https://slaphost1.com',
        {
          service: 'ls_foo',
          query: {
            test: 1
          }
        },
        undefined
      ],
      [
        'https://slaphost2.com',
        {
          service: 'ls_foo',
          query: {
            test: 1
          }
        },
        undefined
      ]
    ])
  })

  it('Directly uses SLAP resolvers to facilitate SLAP queries', async () => {
    mockFacilitator.lookup.mockReturnValueOnce({
      type: 'output-list',
      outputs: [
        {
          beef: sampleBeef1,
          outputIndex: 0
        }
      ]
    })

    const r = new LookupResolver({
      facilitator: mockFacilitator,
      slapTrackers: ['https://mock.slap']
    })
    const res = await r.query({
      service: 'ls_slap',
      query: { test: 1 }
    })
    expect(res).toEqual({
      type: 'output-list',
      outputs: [
        {
          beef: sampleBeef1,
          outputIndex: 0
        }
      ]
    })
    expect(mockFacilitator.lookup.mock.calls).toEqual([
      [
        'https://mock.slap',
        {
          service: 'ls_slap',
          query: {
            test: 1
          }
        },
        undefined
      ]
    ])
  })

  it('should throw an error when SLAP tracker returns invalid response', async () => {
    // SLAP tracker returns 'freeform' response
    mockFacilitator.lookup.mockReturnValueOnce({
      type: 'freeform',
      result: { message: 'Invalid response' }
    })

    const r = new LookupResolver({
      facilitator: mockFacilitator,
      slapTrackers: ['https://mock.slap']
    })

    // Because a freeform response is not valid, the SLAP trackers have not found any competent hosts.
    await expect(
      r.query({
        service: 'ls_foo',
        query: { test: 1 }
      })
    ).rejects.toThrow(
      'No competent mainnet hosts found by the SLAP trackers for lookup service: ls_foo'
    )

    expect(mockFacilitator.lookup.mock.calls).toEqual([
      [
        'https://mock.slap',
        {
          service: 'ls_slap',
          query: {
            service: 'ls_foo'
          }
        },
        5000
      ]
    ])
  })

  it('should throw an error when HTTPSOverlayLookupFacilitator is used with non-HTTPS URL', async () => {
    const facilitator = new HTTPSOverlayLookupFacilitator()
    await expect(
      facilitator.lookup('http://insecure.url', { service: 'test', query: {} })
    ).rejects.toThrow(
      'HTTPS facilitator can only use URLs that start with "https:"'
    )
  })
  describe('LookupResolver Resiliency', () => {
    beforeEach(() => {
      mockFacilitator.lookup.mockReset()
    })

    it('should continue to function when one SLAP tracker fails', async () => {
      const slapHostKey = new PrivateKey(42)
      const slapWallet = new CompletedProtoWallet(slapHostKey)
      const slapLib = new OverlayAdminTokenTemplate(slapWallet)
      const slapScript = await slapLib.lock(
        'SLAP',
        'https://slaphost.com',
        'ls_foo'
      )
      const slapTx = new Transaction(
        1,
        [],
        [
          {
            lockingScript: slapScript,
            satoshis: 1
          }
        ],
        0
      )

      // First SLAP tracker fails
      mockFacilitator.lookup.mockImplementationOnce(async () => {
        throw new Error('SLAP tracker failed')
      })

      // Second SLAP tracker succeeds
      mockFacilitator.lookup.mockReturnValueOnce({
        type: 'output-list',
        outputs: [
          {
            outputIndex: 0,
            beef: slapTx.toBEEF()
          }
        ]
      })

      // Host responds successfully
      mockFacilitator.lookup.mockReturnValueOnce({
        type: 'output-list',
        outputs: [
          {
            beef: sampleBeef3,
            outputIndex: 0
          }
        ]
      })

      const r = new LookupResolver({
        facilitator: mockFacilitator,
        slapTrackers: ['https://mock.slap1', 'https://mock.slap2']
      })

      const res = await r.query({
        service: 'ls_foo',
        query: { test: 1 }
      })

      expect(res).toEqual({
        type: 'output-list',
        outputs: [
          {
            beef: sampleBeef3,
            outputIndex: 0
          }
        ]
      })

      expect(mockFacilitator.lookup.mock.calls).toEqual([
        [
          'https://mock.slap1',
          {
            service: 'ls_slap',
            query: {
              service: 'ls_foo'
            }
          },
          5000
        ],
        [
          'https://mock.slap2',
          {
            service: 'ls_slap',
            query: {
              service: 'ls_foo'
            }
          },
          5000
        ],
        [
          'https://slaphost.com',
          {
            service: 'ls_foo',
            query: {
              test: 1
            }
          },
          undefined
        ]
      ])
    })

    it('should aggregate outputs from hosts that respond, even if some SLAP trackers lie to our face', async () => {
      const slapHostKey1 = new PrivateKey(42)
      const slapWallet1 = new CompletedProtoWallet(slapHostKey1)
      const slapLib1 = new OverlayAdminTokenTemplate(slapWallet1)
      const slapScript1 = await slapLib1.lock(
        'SLAP',
        'https://slaphost1.com',
        'ls_foo'
      )
      const slapTx1 = new Transaction(
        1,
        [],
        [
          {
            lockingScript: slapScript1,
            satoshis: 1
          }
        ],
        0
      )

      const slapHostKey2 = new PrivateKey(43)
      const slapWallet2 = new CompletedProtoWallet(slapHostKey2)
      const slapLib2 = new OverlayAdminTokenTemplate(slapWallet2)
      const slapScript2 = await slapLib2.lock(
        'SLAP',
        'https://slaphost2.com',
        'ls_foo'
      )
      const slapTx2 = new Transaction(
        1,
        [],
        [
          {
            lockingScript: slapScript2,
            satoshis: 1
          }
        ],
        0
      )

      const slapHostKey3 = new PrivateKey(44)
      const slapWallet3 = new CompletedProtoWallet(slapHostKey3)
      const slapLib3 = new OverlayAdminTokenTemplate(slapWallet3)
      const slapScript3 = await slapLib3.lock(
        'SLAP',
        'https://slaphost3.pantsonfire.com',
        'ls_not_what_i_asked_you_for'
      )
      const slapTx3 = new Transaction(
        1,
        [],
        [
          {
            lockingScript: slapScript3,
            satoshis: 1
          }
        ],
        0
      )

      // SLAP trackers return hosts
      mockFacilitator.lookup.mockReturnValueOnce({
        type: 'output-list',
        outputs: [
          { outputIndex: 0, beef: slapTx1.toBEEF() },
          { outputIndex: 0, beef: slapTx2.toBEEF() },
          { outputIndex: 0, beef: slapTx3.toBEEF() }
        ]
      })

      // First host responds successfully
      mockFacilitator.lookup.mockReturnValueOnce({
        type: 'output-list',
        outputs: [{ beef: sampleBeef3, outputIndex: 0 }]
      })

      // Second host fails
      mockFacilitator.lookup.mockImplementationOnce(async () => {
        throw new Error('Host2 failed')
      })

      const r = new LookupResolver({
        facilitator: mockFacilitator,
        slapTrackers: ['https://mock.slap']
      })

      const res = await r.query({
        service: 'ls_foo',
        query: { test: 1 }
      })

      expect(res).toEqual({
        type: 'output-list',
        outputs: [{ beef: sampleBeef3, outputIndex: 0 }]
      })

      expect(mockFacilitator.lookup.mock.calls).toEqual([
        [
          'https://mock.slap',
          {
            service: 'ls_slap',
            query: {
              service: 'ls_foo'
            }
          },
          5000
        ],
        [
          'https://slaphost1.com',
          {
            service: 'ls_foo',
            query: {
              test: 1
            }
          },
          undefined
        ],
        [
          'https://slaphost2.com',
          {
            service: 'ls_foo',
            query: {
              test: 1
            }
          },
          undefined
        ]
      ])
    })

    it('should aggregate outputs from hosts that respond, even if some SLAP trackers give us rotten BEEF', async () => {
      const slapHostKey1 = new PrivateKey(42)
      const slapWallet1 = new CompletedProtoWallet(slapHostKey1)
      const slapLib1 = new OverlayAdminTokenTemplate(slapWallet1)
      const slapScript1 = await slapLib1.lock(
        'SLAP',
        'https://slaphost1.com',
        'ls_foo'
      )
      const slapTx1 = new Transaction(
        1,
        [],
        [
          {
            lockingScript: slapScript1,
            satoshis: 1
          }
        ],
        0
      )

      const slapHostKey2 = new PrivateKey(43)
      const slapWallet2 = new CompletedProtoWallet(slapHostKey2)
      const slapLib2 = new OverlayAdminTokenTemplate(slapWallet2)
      const slapScript2 = await slapLib2.lock(
        'SLAP',
        'https://slaphost2.com',
        'ls_foo'
      )
      const slapTx2 = new Transaction(
        1,
        [],
        [
          {
            lockingScript: slapScript2,
            satoshis: 1
          }
        ],
        0
      )

      // SLAP trackers return hosts
      mockFacilitator.lookup.mockReturnValueOnce({
        type: 'output-list',
        outputs: [
          { outputIndex: 0, beef: slapTx1.toBEEF() },
          { outputIndex: 0, beef: slapTx2.toBEEF() },
          { outputIndex: 0, beef: [0] } // "rotten" (corrupted) BEEF
        ]
      })

      // First host responds successfully
      mockFacilitator.lookup.mockReturnValueOnce({
        type: 'output-list',
        outputs: [{ beef: sampleBeef3, outputIndex: 0 }]
      })

      // Second host fails
      mockFacilitator.lookup.mockImplementationOnce(async () => {
        throw new Error('Host2 failed')
      })

      const r = new LookupResolver({
        facilitator: mockFacilitator,
        slapTrackers: ['https://mock.slap']
      })

      const res = await r.query({
        service: 'ls_foo',
        query: { test: 1 }
      })

      expect(res).toEqual({
        type: 'output-list',
        outputs: [{ beef: sampleBeef3, outputIndex: 0 }]
      })

      expect(mockFacilitator.lookup.mock.calls).toEqual([
        [
          'https://mock.slap',
          {
            service: 'ls_slap',
            query: {
              service: 'ls_foo'
            }
          },
          5000
        ],
        [
          'https://slaphost1.com',
          {
            service: 'ls_foo',
            query: {
              test: 1
            }
          },
          undefined
        ],
        [
          'https://slaphost2.com',
          {
            service: 'ls_foo',
            query: {
              test: 1
            }
          },
          undefined
        ]
      ])
    })

    it('should aggregate outputs from hosts that respond, even if some fail', async () => {
      const slapHostKey1 = new PrivateKey(42)
      const slapWallet1 = new CompletedProtoWallet(slapHostKey1)
      const slapLib1 = new OverlayAdminTokenTemplate(slapWallet1)
      const slapScript1 = await slapLib1.lock(
        'SLAP',
        'https://slaphost1.com',
        'ls_foo'
      )
      const slapTx1 = new Transaction(
        1,
        [],
        [
          {
            lockingScript: slapScript1,
            satoshis: 1
          }
        ],
        0
      )

      const slapHostKey2 = new PrivateKey(43)
      const slapWallet2 = new CompletedProtoWallet(slapHostKey2)
      const slapLib2 = new OverlayAdminTokenTemplate(slapWallet2)
      const slapScript2 = await slapLib2.lock(
        'SLAP',
        'https://slaphost2.com',
        'ls_foo'
      )
      const slapTx2 = new Transaction(
        1,
        [],
        [
          {
            lockingScript: slapScript2,
            satoshis: 1
          }
        ],
        0
      )

      // SLAP trackers return hosts
      mockFacilitator.lookup.mockReturnValueOnce({
        type: 'output-list',
        outputs: [
          { outputIndex: 0, beef: slapTx1.toBEEF() },
          { outputIndex: 0, beef: slapTx2.toBEEF() }
        ]
      })

      // First host responds successfully
      mockFacilitator.lookup.mockReturnValueOnce({
        type: 'output-list',
        outputs: [{ beef: sampleBeef3, outputIndex: 0 }]
      })

      // Second host fails
      mockFacilitator.lookup.mockImplementationOnce(async () => {
        throw new Error('Host2 failed')
      })

      const r = new LookupResolver({
        facilitator: mockFacilitator,
        slapTrackers: ['https://mock.slap']
      })

      const res = await r.query({
        service: 'ls_foo',
        query: { test: 1 }
      })

      expect(res).toEqual({
        type: 'output-list',
        outputs: [{ beef: sampleBeef3, outputIndex: 0 }]
      })

      expect(mockFacilitator.lookup.mock.calls).toEqual([
        [
          'https://mock.slap',
          {
            service: 'ls_slap',
            query: {
              service: 'ls_foo'
            }
          },
          5000
        ],
        [
          'https://slaphost1.com',
          {
            service: 'ls_foo',
            query: {
              test: 1
            }
          },
          undefined
        ],
        [
          'https://slaphost2.com',
          {
            service: 'ls_foo',
            query: {
              test: 1
            }
          },
          undefined
        ]
      ])
    })

    it('should handle invalid responses from some hosts and continue with valid ones', async () => {
      const slapHostKey = new PrivateKey(42)
      const slapWallet = new CompletedProtoWallet(slapHostKey)
      const slapLib = new OverlayAdminTokenTemplate(slapWallet)
      const slapScript = await slapLib.lock(
        'SLAP',
        'https://slaphost.com',
        'ls_foo'
      )
      const slapTx = new Transaction(
        1,
        [],
        [
          {
            lockingScript: slapScript,
            satoshis: 1
          }
        ],
        0
      )

      // SLAP tracker returns host
      mockFacilitator.lookup.mockReturnValueOnce({
        type: 'output-list',
        outputs: [{ outputIndex: 0, beef: slapTx.toBEEF() }]
      })

      // Host returns invalid response
      mockFacilitator.lookup.mockReturnValueOnce({
        type: 'invalid-type',
        data: {}
      })

      const r = new LookupResolver({
        facilitator: mockFacilitator,
        slapTrackers: ['https://mock.slap']
      })

      const res = await r.query({
        service: 'ls_foo',
        query: { test: 1 }
      })

      // Since there are no valid outputs, expect an error
      expect(res).toEqual({
        type: 'output-list',
        outputs: []
      })

      expect(mockFacilitator.lookup.mock.calls).toEqual([
        [
          'https://mock.slap',
          {
            service: 'ls_slap',
            query: {
              service: 'ls_foo'
            }
          },
          5000
        ],
        [
          'https://slaphost.com',
          {
            service: 'ls_foo',
            query: {
              test: 1
            }
          },
          undefined
        ]
      ])
    })

    it('should handle all SLAP trackers failing and throw an error', async () => {
      // Both SLAP trackers fail
      mockFacilitator.lookup.mockImplementation(async () => {
        throw new Error('SLAP tracker failed')
      })

      const r = new LookupResolver({
        facilitator: mockFacilitator,
        slapTrackers: ['https://mock.slap1', 'https://mock.slap2']
      })

      await expect(
        r.query({
          service: 'ls_foo',
          query: { test: 1 }
        })
      ).rejects.toThrow(
        'No competent mainnet hosts found by the SLAP trackers for lookup service: ls_foo'
      )

      expect(mockFacilitator.lookup.mock.calls.length).toBe(2)
    })

    it('should handle all hosts failing and throw an error', async () => {
      const slapHostKey = new PrivateKey(42)
      const slapWallet = new CompletedProtoWallet(slapHostKey)
      const slapLib = new OverlayAdminTokenTemplate(slapWallet)
      const slapScript = await slapLib.lock(
        'SLAP',
        'https://slaphost.com',
        'ls_foo'
      )
      const slapTx = new Transaction(
        1,
        [],
        [
          {
            lockingScript: slapScript,
            satoshis: 1
          }
        ],
        0
      )

      // SLAP tracker returns host
      mockFacilitator.lookup.mockReturnValueOnce({
        type: 'output-list',
        outputs: [{ outputIndex: 0, beef: slapTx.toBEEF() }]
      })

      // Host fails
      mockFacilitator.lookup.mockImplementationOnce(async () => {
        throw new Error('Host failed')
      })

      const r = new LookupResolver({
        facilitator: mockFacilitator,
        slapTrackers: ['https://mock.slap']
      })

      await expect(
        r.query({
          service: 'ls_foo',
          query: { test: 1 }
        })
      ).rejects.toThrow('No successful responses from any hosts')

      expect(mockFacilitator.lookup.mock.calls.length).toBe(2)
    })

    it('should continue to aggregate outputs when some hosts return invalid outputs', async () => {
      const slapHostKey1 = new PrivateKey(42)
      const slapWallet1 = new CompletedProtoWallet(slapHostKey1)
      const slapLib1 = new OverlayAdminTokenTemplate(slapWallet1)
      const slapScript1 = await slapLib1.lock(
        'SLAP',
        'https://slaphost1.com',
        'ls_foo'
      )
      const slapTx1 = new Transaction(
        1,
        [],
        [
          {
            lockingScript: slapScript1,
            satoshis: 1
          }
        ],
        0
      )

      const slapHostKey2 = new PrivateKey(43)
      const slapWallet2 = new CompletedProtoWallet(slapHostKey2)
      const slapLib2 = new OverlayAdminTokenTemplate(slapWallet2)
      const slapScript2 = await slapLib2.lock(
        'SLAP',
        'https://slaphost2.com',
        'ls_foo'
      )
      const slapTx2 = new Transaction(
        1,
        [],
        [
          {
            lockingScript: slapScript2,
            satoshis: 1
          }
        ],
        0
      )

      // SLAP tracker returns two hosts
      mockFacilitator.lookup.mockReturnValueOnce({
        type: 'output-list',
        outputs: [
          { outputIndex: 0, beef: slapTx1.toBEEF() },
          { outputIndex: 0, beef: slapTx2.toBEEF() }
        ]
      })

      // First host returns valid output
      mockFacilitator.lookup.mockReturnValueOnce({
        type: 'output-list',
        outputs: [{ beef: sampleBeef3, outputIndex: 0 }]
      })

      // Second host returns invalid output
      mockFacilitator.lookup.mockReturnValueOnce({
        type: 'output-list',
        outputs: [{ invalid: true }]
      })

      const r = new LookupResolver({
        facilitator: mockFacilitator,
        slapTrackers: ['https://mock.slap']
      })

      const res = await r.query({
        service: 'ls_foo',
        query: { test: 1 }
      })

      expect(res).toEqual({
        type: 'output-list',
        outputs: [{ beef: sampleBeef3, outputIndex: 0 }]
      })

      expect(mockFacilitator.lookup.mock.calls.length).toBe(3)
    })

    it('should continue to aggregate outputs when some hosts return malformed malarkie', async () => {
      const slapHostKey1 = new PrivateKey(42)
      const slapWallet1 = new CompletedProtoWallet(slapHostKey1)
      const slapLib1 = new OverlayAdminTokenTemplate(slapWallet1)
      const slapScript1 = await slapLib1.lock(
        'SLAP',
        'https://slaphost1.com',
        'ls_foo'
      )
      const slapTx1 = new Transaction(
        1,
        [],
        [
          {
            lockingScript: slapScript1,
            satoshis: 1
          }
        ],
        0
      )

      const slapHostKey2 = new PrivateKey(43)
      const slapWallet2 = new CompletedProtoWallet(slapHostKey2)
      const slapLib2 = new OverlayAdminTokenTemplate(slapWallet2)
      const slapScript2 = await slapLib2.lock(
        'SLAP',
        'https://slaphost2.com',
        'ls_foo'
      )
      const slapTx2 = new Transaction(
        1,
        [],
        [
          {
            lockingScript: slapScript2,
            satoshis: 1
          }
        ],
        0
      )

      // SLAP tracker returns two hosts
      mockFacilitator.lookup.mockReturnValueOnce({
        type: 'output-list',
        outputs: [
          { outputIndex: 0, beef: slapTx1.toBEEF() },
          { outputIndex: 0, beef: slapTx2.toBEEF() }
        ]
      })

      // First host returns valid output
      mockFacilitator.lookup.mockReturnValueOnce({
        type: 'output-list',
        outputs: [{ beef: sampleBeef3, outputIndex: 0 }]
      })

      // Second host returns invalid output
      mockFacilitator.lookup.mockReturnValueOnce({
        type: 'output-list',
        output: 'document.createElement('
      })

      const r = new LookupResolver({
        facilitator: mockFacilitator,
        slapTrackers: ['https://mock.slap']
      })

      const res = await r.query({
        service: 'ls_foo',
        query: { test: 1 }
      })

      expect(res).toEqual({
        type: 'output-list',
        outputs: [{ beef: sampleBeef3, outputIndex: 0 }]
      })

      expect(mockFacilitator.lookup.mock.calls.length).toBe(3)
    })
  })
})
