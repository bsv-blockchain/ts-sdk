import SHIPCast from '../../overlay-tools/SHIPBroadcaster'
import LookupResolver from '../../overlay-tools/LookupResolver'
import { PrivateKey } from '../../primitives/index'
import { Transaction } from '../../transaction/index'
import OverlayAdminTokenTemplate from '../../overlay-tools/OverlayAdminTokenTemplate'
import { CompletedProtoWallet } from '../../auth/certificates/__tests/CompletedProtoWallet'

const mockFacilitator = {
  send: jest.fn()
}

const mockResolver = {
  query: jest.fn()
}

describe('SHIPCast', () => {
  beforeEach(() => {
    mockFacilitator.send.mockReset()
    mockResolver.query.mockReset()
  })

  it('Handles constructor errors', () => {
    expect(() => new SHIPCast([])).toThrow(
      new Error('At least one topic is required for broadcast.')
    )
    expect(() => new SHIPCast(['badprefix_foo'])).toThrow(
      new Error('Every topic must start with "tm_".')
    )
  })

  it('should broadcast to a single SHIP host found via resolver', async () => {
    const shipHostKey = new PrivateKey(42)
    const shipWallet = new CompletedProtoWallet(shipHostKey)
    const shipLib = new OverlayAdminTokenTemplate(shipWallet)
    const shipScript = await shipLib.lock(
      'SHIP',
      'https://shiphost.com',
      'tm_foo'
    )
    const shipTx = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript,
          satoshis: 1
        }
      ],
      0
    )

    // Resolver returns one host interested in 'tm_foo' topic
    mockResolver.query.mockReturnValueOnce({
      type: 'output-list',
      outputs: [
        {
          beef: shipTx.toBEEF(),
          outputIndex: 0
        }
      ]
    })

    // Host responds successfully
    mockFacilitator.send.mockReturnValueOnce({
      tm_foo: {
        outputsToAdmit: [0],
        coinsToRetain: []
      }
    })

    const b = new SHIPCast(['tm_foo'], {
      facilitator: mockFacilitator,
      resolver: mockResolver as unknown as LookupResolver
    })
    const testTx = new Transaction(1, [], [], 0)
    const response = await b.broadcast(testTx)

    expect(response).toEqual({
      status: 'success',
      txid: testTx.id('hex'),
      message: 'Sent to 1 Overlay Services host.'
    })

    expect(mockResolver.query).toHaveBeenCalledWith(
      {
        service: 'ls_ship',
        query: {
          topics: ['tm_foo']
        }
      },
      5000
    )

    expect(mockFacilitator.send).toHaveBeenCalledWith('https://shiphost.com', {
      beef: testTx.toBEEF(),
      topics: ['tm_foo']
    })
  })

  it('should be resilient to malformed or corrupted SHIP data, to the extent possible', async () => {
    const shipHostKey = new PrivateKey(42)
    const shipWallet = new CompletedProtoWallet(shipHostKey)
    const shipLib = new OverlayAdminTokenTemplate(shipWallet)
    // First SHIP is for wrong topic
    const shipScript = await shipLib.lock(
      'SHIP',
      'https://shiphost.com',
      'tm_wrong'
    )
    const shipTx = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript,
          satoshis: 1
        }
      ],
      0
    )
    const shipHostKey2 = new PrivateKey(43)
    const shipWallet2 = new CompletedProtoWallet(shipHostKey2)
    const shipLib2 = new OverlayAdminTokenTemplate(shipWallet2)
    // Second SHIP is for correct topic
    const shipScript2 = await shipLib2.lock(
      'SHIP',
      'https://shiphost2.com',
      'tm_foo'
    )
    const shipTx2 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript2,
          satoshis: 1
        }
      ],
      0
    )

    // Resolver returns two hosts, both the correct and the corrupted ones.
    mockResolver.query.mockReturnValueOnce({
      type: 'output-list',
      outputs: [
        {
          beef: shipTx.toBEEF(),
          outputIndex: 0
        },
        {
          beef: shipTx2.toBEEF(),
          outputIndex: 0
        }
      ]
    })

    // Host responds successfully
    mockFacilitator.send.mockReturnValue({
      tm_foo: {
        outputsToAdmit: [0],
        coinsToRetain: []
      }
    })

    const b = new SHIPCast(['tm_foo'], {
      facilitator: mockFacilitator,
      resolver: mockResolver as unknown as LookupResolver
    })
    const testTx = new Transaction(1, [], [], 0)
    let response = await b.broadcast(testTx)

    expect(response).toEqual({
      status: 'success',
      txid: testTx.id('hex'),
      // One SHIP advertisement should be used, but the second one was invalid
      message: 'Sent to 1 Overlay Services host.'
    })

    // Transaction should have been sent to the second host, but the first one was invalid
    expect(mockFacilitator.send).toHaveBeenCalledWith('https://shiphost2.com', {
      beef: testTx.toBEEF(),
      topics: ['tm_foo']
    })
    mockFacilitator.send.mockClear()

    // Resolver returns the wrong type of data
    mockResolver.query.mockReturnValueOnce({
      type: 'invalid',
      bogus: true,
      outputs: {
        different: 'structure'
      }
    })
    await expect(async () => await b.broadcast(testTx)).rejects.toThrow(
      'SHIP answer is not an output list.'
    )
    expect(mockFacilitator.send).not.toHaveBeenCalled()

    // Resolver returns the wrong output structure
    mockResolver.query.mockReturnValueOnce({
      type: 'output-list',
      outputs: {
        different: 'structure'
      }
    })
    await expect(async () => await b.broadcast(testTx)).rejects.toThrow(
      'answer.outputs is not iterable'
    )
    expect(mockFacilitator.send).not.toHaveBeenCalled()

    // Resolver returns corrupted BEEF alongside good data
    mockResolver.query.mockReturnValueOnce({
      type: 'output-list',
      outputs: [
        {
          beef: shipTx.toBEEF(), // Wrong topic
          outputIndex: 0
        },
        {
          beef: [0], // corrupted "rotten" BEEF
          outputIndex: 4
        },
        {
          beef: shipTx2.toBEEF(),
          outputIndex: 1 // Wrong output index
        },
        {
          beef: shipTx2.toBEEF(),
          outputIndex: 0 // correct
        }
      ]
    })
    response = await b.broadcast(testTx)
    expect(response).toEqual({
      status: 'success',
      txid: testTx.id('hex'),
      // One SHIP advertisement should be used, but the second one was invalid
      message: 'Sent to 1 Overlay Services host.'
    })

    // Transaction should have been sent to the second host, but the first one was invalid
    expect(mockFacilitator.send).toHaveBeenCalledWith('https://shiphost2.com', {
      beef: testTx.toBEEF(),
      topics: ['tm_foo']
    })
  })

  it('should fail when transaction cannot be serialized to BEEF', async () => {
    const b = new SHIPCast(['tm_foo'], {
      facilitator: mockFacilitator,
      resolver: mockResolver as unknown as LookupResolver
    })
    const testTx = {
      toBEEF: () => {
        throw new Error('Cannot serialize to BEEF')
      },
      metadata: new Map()
    } as unknown as Transaction

    await expect(b.broadcast(testTx)).rejects.toThrow(
      'Transactions sent via SHIP to Overlay Services must be serializable to BEEF format.'
    )
  })

  it('should fail when no hosts are interested in the topics', async () => {
    // Resolver returns empty output list
    mockResolver.query.mockReturnValueOnce({
      type: 'output-list',
      outputs: []
    })

    const b = new SHIPCast(['tm_foo'], {
      facilitator: mockFacilitator,
      resolver: mockResolver as unknown as LookupResolver
    })
    const testTx = new Transaction(1, [], [], 0)

    const result = await b.broadcast(testTx)

    expect(result).toEqual({
      status: 'error',
      code: 'ERR_NO_HOSTS_INTERESTED',
      description: 'No mainnet hosts are interested in receiving this transaction.'
    })

    expect(mockResolver.query).toHaveBeenCalledWith(
      {
        service: 'ls_ship',
        query: {
          topics: ['tm_foo']
        }
      },
      5000
    )

    expect(mockFacilitator.send).not.toHaveBeenCalled()
  })

  it('should fail when all hosts reject the transaction', async () => {
    const shipHostKey = new PrivateKey(42)
    const shipWallet = new CompletedProtoWallet(shipHostKey)
    const shipLib = new OverlayAdminTokenTemplate(shipWallet)
    const shipScript = await shipLib.lock(
      'SHIP',
      'https://shiphost.com',
      'tm_foo'
    )
    const shipTx = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript,
          satoshis: 1
        }
      ],
      0
    )

    // Resolver returns one host
    mockResolver.query.mockReturnValueOnce({
      type: 'output-list',
      outputs: [
        {
          beef: shipTx.toBEEF(),
          outputIndex: 0
        }
      ]
    })

    // Host fails
    mockFacilitator.send.mockImplementationOnce(() => {
      throw new Error('Host failed')
    })

    const b = new SHIPCast(['tm_foo'], {
      facilitator: mockFacilitator,
      resolver: mockResolver as unknown as LookupResolver
    })
    const testTx = new Transaction(1, [], [], 0)

    const result = await b.broadcast(testTx)

    expect(result).toEqual({
      status: 'error',
      code: 'ERR_ALL_HOSTS_REJECTED',
      description: 'All mainnet topical hosts have rejected the transaction.'
    })

    expect(mockFacilitator.send).toHaveBeenCalled()
  })

  it('should fail when required specific hosts are not among interested hosts', async () => {
    const shipHostKey = new PrivateKey(42)
    const shipWallet = new CompletedProtoWallet(shipHostKey)
    const shipLib = new OverlayAdminTokenTemplate(shipWallet)
    const shipScript = await shipLib.lock(
      'SHIP',
      'https://shiphost.com',
      'tm_foo'
    )
    const shipTx = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript,
          satoshis: 1
        }
      ],
      0
    )

    // Resolver returns one host
    mockResolver.query.mockReturnValueOnce({
      type: 'output-list',
      outputs: [
        {
          beef: shipTx.toBEEF(),
          outputIndex: 0
        }
      ]
    })

    // First host acknowledges 'tm_foo', but it's not the right host.
    mockFacilitator.send.mockImplementationOnce(
      async (host, { beef, topics }) => {
        const steak = {}
        for (const topic of topics) {
          steak[topic] = {
            outputsToAdmit: topic === 'tm_foo' ? [0] : [],
            coinsToRetain: []
          }
        }
        return steak
      }
    )

    const b = new SHIPCast(['tm_foo'], {
      facilitator: mockFacilitator,
      resolver: mockResolver as unknown as LookupResolver,
      requireAcknowledgmentFromSpecificHostsForTopics: {
        'https://anotherhost.com': ['tm_foo']
      },
      requireAcknowledgmentFromAllHostsForTopics: [],
      requireAcknowledgmentFromAnyHostForTopics: []
    })
    const testTx = new Transaction(1, [], [], 0)
    const response = await b.broadcast(testTx)

    expect(response).toEqual({
      status: 'error',
      code: 'ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED',
      description: 'Specific hosts did not acknowledge the required topics.'
    })
  })

  it('should succeed when all hosts acknowledge all topics (default behavior)', async () => {
    const shipHostKey1 = new PrivateKey(42)
    const shipWallet1 = new CompletedProtoWallet(shipHostKey1)
    const shipLib1 = new OverlayAdminTokenTemplate(shipWallet1)
    const shipScript1 = await shipLib1.lock(
      'SHIP',
      'https://shiphost1.com',
      'tm_foo'
    )
    const shipScript1b = await shipLib1.lock(
      'SHIP',
      'https://shiphost1.com',
      'tm_bar'
    )
    const shipTx1 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript1,
          satoshis: 1
        },
        {
          lockingScript: shipScript1b,
          satoshis: 1
        }
      ],
      0
    )

    const shipHostKey2 = new PrivateKey(43)
    const shipWallet2 = new CompletedProtoWallet(shipHostKey2)
    const shipLib2 = new OverlayAdminTokenTemplate(shipWallet2)
    const shipScript2 = await shipLib2.lock(
      'SHIP',
      'https://shiphost2.com',
      'tm_bar'
    )
    const shipScript2b = await shipLib2.lock(
      'SHIP',
      'https://shiphost2.com',
      'tm_foo'
    )
    const shipTx2 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript2,
          satoshis: 1
        },
        {
          lockingScript: shipScript2b,
          satoshis: 1
        }
      ],
      0
    )

    // Resolver returns two hosts
    mockResolver.query.mockReturnValueOnce({
      type: 'output-list',
      outputs: [
        { beef: shipTx1.toBEEF(), outputIndex: 0 },
        { beef: shipTx1.toBEEF(), outputIndex: 1 },
        { beef: shipTx2.toBEEF(), outputIndex: 0 },
        { beef: shipTx2.toBEEF(), outputIndex: 1 }
      ]
    })

    // Both hosts acknowledge all topics
    mockFacilitator.send.mockImplementation(async (host, { topics }) => {
      const steak = {}
      for (const topic of topics) {
        steak[topic] = {
          outputsToAdmit: [0],
          coinsToRetain: []
        }
      }
      return steak
    })

    const b = new SHIPCast(['tm_foo', 'tm_bar'], {
      facilitator: mockFacilitator,
      resolver: mockResolver as unknown as LookupResolver
    })
    const testTx = new Transaction(1, [], [], 0)
    const response = await b.broadcast(testTx)

    expect(response).toEqual({
      status: 'success',
      txid: testTx.id('hex'),
      message: 'Sent to 2 Overlay Services hosts.'
    })

    expect(mockResolver.query).toHaveBeenCalledWith(
      {
        service: 'ls_ship',
        query: {
          topics: ['tm_foo', 'tm_bar']
        }
      },
      5000
    )

    expect(mockFacilitator.send).toHaveBeenCalledTimes(2)
  })

  it('should fail if at least one host does not acknowledge every topic (default behavior)', async () => {
    const shipHostKey1 = new PrivateKey(42)
    const shipWallet1 = new CompletedProtoWallet(shipHostKey1)
    const shipLib1 = new OverlayAdminTokenTemplate(shipWallet1)
    const shipScript1 = await shipLib1.lock(
      'SHIP',
      'https://shiphost1.com',
      'tm_foo'
    )
    const shipTx1 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript1,
          satoshis: 1
        }
      ],
      0
    )

    const shipHostKey2 = new PrivateKey(43)
    const shipWallet2 = new CompletedProtoWallet(shipHostKey2)
    const shipLib2 = new OverlayAdminTokenTemplate(shipWallet2)
    const shipScript2 = await shipLib2.lock(
      'SHIP',
      'https://shiphost2.com',
      'tm_bar'
    )
    const shipTx2 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript2,
          satoshis: 1
        }
      ],
      0
    )

    // Resolver returns two hosts
    mockResolver.query.mockReturnValueOnce({
      type: 'output-list',
      outputs: [
        { beef: shipTx1.toBEEF(), outputIndex: 0 },
        { beef: shipTx2.toBEEF(), outputIndex: 0 }
      ]
    })

    // First host acknowledges 'tm_foo'
    mockFacilitator.send.mockImplementationOnce(
      async (host, { beef, topics }) => {
        const steak = {}
        for (const topic of topics) {
          steak[topic] = {
            outputsToAdmit: [],
            coinsToRetain: []
          }
        }
        return steak
      }
    )

    // Second host does not acknowledge any topics
    mockFacilitator.send.mockImplementationOnce(
      async (host, { beef, topics }) => {
        const steak = {}
        for (const topic of topics) {
          steak[topic] = {
            outputsToAdmit: [],
            coinsToRetain: []
          }
        }
        return steak
      }
    )

    const b = new SHIPCast(['tm_foo', 'tm_bar'], {
      facilitator: mockFacilitator,
      resolver: mockResolver as unknown as LookupResolver
    })
    const testTx = new Transaction(1, [], [], 0)
    const response = await b.broadcast(testTx)

    expect(response).toEqual({
      status: 'error',
      code: 'ERR_REQUIRE_ACK_FROM_ANY_HOST_FAILED',
      description: 'No host acknowledged the required topics.'
    })
  })

  it('should succeed when at least one host acknowledges required topics with requireAcknowledgmentFromAnyHostForTopics set to "any"', async () => {
    const shipHostKey1 = new PrivateKey(42)
    const shipWallet1 = new CompletedProtoWallet(shipHostKey1)
    const shipLib1 = new OverlayAdminTokenTemplate(shipWallet1)
    const shipScript1 = await shipLib1.lock(
      'SHIP',
      'https://shiphost1.com',
      'tm_foo'
    )
    const shipTx1 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript1,
          satoshis: 1
        }
      ],
      0
    )

    const shipHostKey2 = new PrivateKey(43)
    const shipWallet2 = new CompletedProtoWallet(shipHostKey2)
    const shipLib2 = new OverlayAdminTokenTemplate(shipWallet2)
    const shipScript2 = await shipLib2.lock(
      'SHIP',
      'https://shiphost2.com',
      'tm_bar'
    )
    const shipTx2 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript2,
          satoshis: 1
        }
      ],
      0
    )

    // Resolver returns two hosts
    mockResolver.query.mockReturnValueOnce({
      type: 'output-list',
      outputs: [
        { beef: shipTx1.toBEEF(), outputIndex: 0 },
        { beef: shipTx2.toBEEF(), outputIndex: 0 }
      ]
    })

    // First host acknowledges no topics
    mockFacilitator.send.mockImplementationOnce(
      async (host, { beef, topics }) => {
        const steak = {}
        for (const topic of topics) {
          steak[topic] = {
            outputsToAdmit: [],
            coinsToRetain: []
          }
        }
        return steak
      }
    )

    // Second host acknowledges 'tm_bar'
    mockFacilitator.send.mockImplementationOnce(
      async (host, { beef, topics }) => {
        const steak = {}
        for (const topic of topics) {
          steak[topic] = {
            outputsToAdmit: topic === 'tm_bar' ? [0] : [],
            coinsToRetain: []
          }
        }
        return steak
      }
    )

    const b = new SHIPCast(['tm_foo', 'tm_bar'], {
      facilitator: mockFacilitator,
      resolver: mockResolver as unknown as LookupResolver,
      requireAcknowledgmentFromAnyHostForTopics: 'any',
      requireAcknowledgmentFromAllHostsForTopics: []
    })

    const testTx = new Transaction(1, [], [], 0)
    const response = await b.broadcast(testTx)

    expect(response).toEqual({
      status: 'success',
      txid: testTx.id('hex'),
      message: 'Sent to 2 Overlay Services hosts.'
    })
  })

  it('should fail when no hosts acknowledge required topics with requireAcknowledgmentFromAnyHostForTopics set to "any"', async () => {
    const shipHostKey1 = new PrivateKey(42)
    const shipWallet1 = new CompletedProtoWallet(shipHostKey1)
    const shipLib1 = new OverlayAdminTokenTemplate(shipWallet1)
    const shipScript1 = await shipLib1.lock(
      'SHIP',
      'https://shiphost1.com',
      'tm_foo'
    )
    const shipTx1 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript1,
          satoshis: 1
        }
      ],
      0
    )

    // Resolver returns one host
    mockResolver.query.mockReturnValueOnce({
      type: 'output-list',
      outputs: [{ beef: shipTx1.toBEEF(), outputIndex: 0 }]
    })

    // Host acknowledges no topics
    mockFacilitator.send.mockImplementationOnce(
      async (host, { beef, topics }) => {
        const steak = {}
        for (const topic of topics) {
          steak[topic] = {
            outputsToAdmit: [],
            coinsToRetain: []
          }
        }
        return steak
      }
    )

    const b = new SHIPCast(['tm_foo'], {
      facilitator: mockFacilitator,
      resolver: mockResolver as unknown as LookupResolver,
      requireAcknowledgmentFromAnyHostForTopics: 'any',
      requireAcknowledgmentFromAllHostsForTopics: []
    })

    const testTx = new Transaction(1, [], [], 0)
    const response = await b.broadcast(testTx)

    expect(response).toEqual({
      status: 'error',
      code: 'ERR_REQUIRE_ACK_FROM_ANY_HOST_FAILED',
      description: 'No host acknowledged the required topics.'
    })
  })

  it('should succeed when specific hosts acknowledge required topics', async () => {
    const shipHostKey1 = new PrivateKey(42)
    const shipWallet1 = new CompletedProtoWallet(shipHostKey1)
    const shipLib1 = new OverlayAdminTokenTemplate(shipWallet1)
    const shipScript1 = await shipLib1.lock(
      'SHIP',
      'https://shiphost1.com',
      'tm_foo'
    )
    const shipTx1 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript1,
          satoshis: 1
        }
      ],
      0
    )

    const shipHostKey2 = new PrivateKey(43)
    const shipWallet2 = new CompletedProtoWallet(shipHostKey2)
    const shipLib2 = new OverlayAdminTokenTemplate(shipWallet2)
    const shipScript2 = await shipLib2.lock(
      'SHIP',
      'https://shiphost2.com',
      'tm_bar'
    )
    const shipTx2 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript2,
          satoshis: 1
        }
      ],
      0
    )

    // Resolver returns two hosts
    mockResolver.query.mockReturnValueOnce({
      type: 'output-list',
      outputs: [
        { beef: shipTx1.toBEEF(), outputIndex: 0 },
        { beef: shipTx2.toBEEF(), outputIndex: 0 }
      ]
    })

    // First host acknowledges 'tm_foo'
    mockFacilitator.send.mockImplementationOnce(
      async (host, { beef, topics }) => {
        const steak = {}
        for (const topic of topics) {
          steak[topic] = {
            outputsToAdmit: topic === 'tm_foo' ? [0] : [],
            coinsToRetain: []
          }
        }
        return steak
      }
    )

    // Second host does not acknowledge 'tm_bar'
    mockFacilitator.send.mockImplementationOnce(
      async (host, { beef, topics }) => {
        const steak = {}
        for (const topic of topics) {
          steak[topic] = {
            outputsToAdmit: [],
            coinsToRetain: []
          }
        }
        return steak
      }
    )

    const b = new SHIPCast(['tm_foo', 'tm_bar'], {
      facilitator: mockFacilitator,
      resolver: mockResolver as unknown as LookupResolver,
      requireAcknowledgmentFromSpecificHostsForTopics: {
        'https://shiphost1.com': ['tm_foo']
      },
      requireAcknowledgmentFromAllHostsForTopics: [],
      requireAcknowledgmentFromAnyHostForTopics: []
    })
    const testTx = new Transaction(1, [], [], 0)
    const response = await b.broadcast(testTx)

    expect(response).toEqual({
      status: 'success',
      txid: testTx.id('hex'),
      message: 'Sent to 2 Overlay Services hosts.'
    })
  })

  it('should succeed when interested hosts only remove coins in a transaction broadcast', async () => {
    const shipHostKey1 = new PrivateKey(42)
    const shipWallet1 = new CompletedProtoWallet(shipHostKey1)
    const shipLib1 = new OverlayAdminTokenTemplate(shipWallet1)
    const shipScript1 = await shipLib1.lock(
      'SHIP',
      'https://shiphost1.com',
      'tm_foo'
    )
    const shipTx1 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript1,
          satoshis: 1
        }
      ],
      0
    )

    const shipHostKey2 = new PrivateKey(43)
    const shipWallet2 = new CompletedProtoWallet(shipHostKey2)
    const shipLib2 = new OverlayAdminTokenTemplate(shipWallet2)
    const shipScript2 = await shipLib2.lock(
      'SHIP',
      'https://shiphost2.com',
      'tm_bar'
    )
    const shipTx2 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript2,
          satoshis: 1
        }
      ],
      0
    )

    // Resolver returns two hosts
    mockResolver.query.mockReturnValueOnce({
      type: 'output-list',
      outputs: [
        { beef: shipTx1.toBEEF(), outputIndex: 0 },
        { beef: shipTx2.toBEEF(), outputIndex: 0 }
      ]
    })

    // First host acknowledges 'tm_foo' with coinsRemoved
    mockFacilitator.send.mockImplementationOnce(
      async (host, { beef, topics }) => {
        const steak = {}
        for (const topic of topics) {
          steak[topic] = {
            outputsToAdmit: [],
            coinsToRetain: [],
            coinsRemoved: topic === 'tm_foo' ? [0] : []
          }
        }
        return steak
      }
    )

    // Second host does not acknowledge 'tm_bar'
    mockFacilitator.send.mockImplementationOnce(
      async (host, { beef, topics }) => {
        const steak = {}
        for (const topic of topics) {
          steak[topic] = {
            outputsToAdmit: [],
            coinsToRetain: [],
            coinsRemoved: []
          }
        }
        return steak
      }
    )

    const b = new SHIPCast(['tm_foo', 'tm_bar'], {
      facilitator: mockFacilitator,
      resolver: mockResolver as unknown as LookupResolver,
      requireAcknowledgmentFromSpecificHostsForTopics: {
        'https://shiphost1.com': ['tm_foo']
      },
      requireAcknowledgmentFromAllHostsForTopics: [],
      requireAcknowledgmentFromAnyHostForTopics: []
    })

    const testTx = new Transaction(1, [], [], 0)
    const response = await b.broadcast(testTx)

    expect(response).toEqual({
      status: 'success',
      txid: testTx.id('hex'),
      message: 'Sent to 2 Overlay Services hosts.'
    })

    // Verify the resolver was queried correctly
    expect(mockResolver.query).toHaveBeenCalledWith(
      {
        service: 'ls_ship',
        query: {
          topics: ['tm_foo', 'tm_bar']
        }
      },
      5000
    )
  })

  it('should fail when specific hosts do not acknowledge required topics', async () => {
    const shipHostKey1 = new PrivateKey(42)
    const shipWallet1 = new CompletedProtoWallet(shipHostKey1)
    const shipLib1 = new OverlayAdminTokenTemplate(shipWallet1)
    const shipScript1 = await shipLib1.lock(
      'SHIP',
      'https://shiphost1.com',
      'tm_foo'
    )
    const shipTx1 = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript1,
          satoshis: 1
        }
      ],
      0
    )

    // Resolver returns one host
    mockResolver.query.mockReturnValueOnce({
      type: 'output-list',
      outputs: [{ beef: shipTx1.toBEEF(), outputIndex: 0 }]
    })

    // Host does not acknowledge 'tm_foo'
    mockFacilitator.send.mockImplementationOnce(
      async (host, { beef, topics }) => {
        const steak = {}
        for (const topic of topics) {
          steak[topic] = {
            outputsToAdmit: [],
            coinsToRetain: []
          }
        }
        return steak
      }
    )

    const b = new SHIPCast(['tm_foo'], {
      facilitator: mockFacilitator,
      resolver: mockResolver as unknown as LookupResolver,
      requireAcknowledgmentFromSpecificHostsForTopics: {
        'https://shiphost1.com': ['tm_foo']
      },
      requireAcknowledgmentFromAllHostsForTopics: [],
      requireAcknowledgmentFromAnyHostForTopics: []
    })

    const testTx = new Transaction(1, [], [], 0)
    const response = await b.broadcast(testTx)

    expect(response).toEqual({
      status: 'error',
      code: 'ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED',
      description: 'Specific hosts did not acknowledge the required topics.'
    })
  })

  it('should handle invalid acknowledgments from hosts gracefully', async () => {
    const shipHostKey = new PrivateKey(42)
    const shipWallet = new CompletedProtoWallet(shipHostKey)
    const shipLib = new OverlayAdminTokenTemplate(shipWallet)
    const shipScript = await shipLib.lock(
      'SHIP',
      'https://shiphost.com',
      'tm_foo'
    )
    const shipTx = new Transaction(
      1,
      [],
      [
        {
          lockingScript: shipScript,
          satoshis: 1
        }
      ],
      0
    )

    // Resolver returns one host
    mockResolver.query.mockReturnValueOnce({
      type: 'output-list',
      outputs: [
        {
          beef: shipTx.toBEEF(),
          outputIndex: 0
        }
      ]
    })

    // Host returns invalid acknowledgment
    mockFacilitator.send.mockReturnValueOnce(null)
    const b = new SHIPCast(['tm_foo'], {
      facilitator: mockFacilitator,
      resolver: mockResolver as unknown as LookupResolver
    })
    const testTx = new Transaction(1, [], [], 0)
    const response = await b.broadcast(testTx)

    // Since the host responded (successfully in terms of HTTP), but with invalid data, we should consider it a failure
    expect(response).toEqual({
      status: 'error',
      code: 'ERR_ALL_HOSTS_REJECTED',
      description: 'All mainnet topical hosts have rejected the transaction.'
    })
  })
  describe('SHIPCast private methods', () => {
    let shipCast: SHIPCast

    beforeEach(() => {
      shipCast = new SHIPCast(['tm_foo', 'tm_bar'], {
        facilitator: mockFacilitator,
        resolver: mockResolver as unknown as LookupResolver
      })
    })

    describe('checkAcknowledgmentFromAllHosts', () => {
      it('should return true when all hosts acknowledge all required topics', () => {
        const hostAcknowledgments = {
          'https://host1.com': new Set(['tm_foo', 'tm_bar']),
          'https://host2.com': new Set(['tm_foo', 'tm_bar'])
        }
        const result = (shipCast as any).checkAcknowledgmentFromAllHosts(
          hostAcknowledgments,
          ['tm_foo', 'tm_bar'],
          'all'
        )
        expect(result).toBe(true)
      })

      it('should return false when any host does not acknowledge all required topics', () => {
        const hostAcknowledgments = {
          'https://host1.com': new Set(['tm_foo']),
          'https://host2.com': new Set(['tm_foo', 'tm_bar'])
        }
        const result = (shipCast as any).checkAcknowledgmentFromAllHosts(
          hostAcknowledgments,
          ['tm_foo', 'tm_bar'],
          'all'
        )
        expect(result).toBe(false)
      })

      it('should return true when all hosts acknowledge any of the required topics', () => {
        const hostAcknowledgments = {
          'https://host1.com': new Set(['tm_foo']),
          'https://host2.com': new Set(['tm_bar'])
        }
        const result = (shipCast as any).checkAcknowledgmentFromAllHosts(
          hostAcknowledgments,
          ['tm_foo', 'tm_bar'],
          'any'
        )
        expect(result).toBe(true)
      })

      it('should return false when any host does not acknowledge any of the required topics', () => {
        const hostAcknowledgments = {
          'https://host1.com': new Set(),
          'https://host2.com': new Set(['tm_bar'])
        }
        const result = (shipCast as any).checkAcknowledgmentFromAllHosts(
          hostAcknowledgments,
          ['tm_foo', 'tm_bar'],
          'any'
        )
        expect(result).toBe(false)
      })
    })

    describe('checkAcknowledgmentFromAnyHost', () => {
      it('should return true when at least one host acknowledges all required topics', () => {
        const hostAcknowledgments = {
          'https://host1.com': new Set(['tm_foo', 'tm_bar']),
          'https://host2.com': new Set(['tm_foo'])
        }
        const result = (shipCast as any).checkAcknowledgmentFromAnyHost(
          hostAcknowledgments,
          ['tm_foo', 'tm_bar'],
          'all'
        )
        expect(result).toBe(true)
      })

      it('should return false when no host acknowledges all required topics', () => {
        const hostAcknowledgments = {
          'https://host1.com': new Set(['tm_foo']),
          'https://host2.com': new Set(['tm_bar'])
        }
        const result = (shipCast as any).checkAcknowledgmentFromAnyHost(
          hostAcknowledgments,
          ['tm_foo', 'tm_bar'],
          'all'
        )
        expect(result).toBe(false)
      })

      it('should return true when at least one host acknowledges any of the required topics', () => {
        const hostAcknowledgments = {
          'https://host1.com': new Set(['tm_foo']),
          'https://host2.com': new Set()
        }
        const result = (shipCast as any).checkAcknowledgmentFromAnyHost(
          hostAcknowledgments,
          ['tm_foo', 'tm_bar'],
          'any'
        )
        expect(result).toBe(true)
      })

      it('should return false when no host acknowledges any of the required topics', () => {
        const hostAcknowledgments = {
          'https://host1.com': new Set(),
          'https://host2.com': new Set()
        }
        const result = (shipCast as any).checkAcknowledgmentFromAnyHost(
          hostAcknowledgments,
          ['tm_foo', 'tm_bar'],
          'any'
        )
        expect(result).toBe(false)
      })
    })

    describe('checkAcknowledgmentFromSpecificHosts', () => {
      it('should return true when specific hosts acknowledge all required topics', () => {
        const hostAcknowledgments = {
          'https://host1.com': new Set(['tm_foo', 'tm_bar']),
          'https://host2.com': new Set(['tm_foo'])
        }
        const requirements = {
          'https://host1.com': ['tm_foo', 'tm_bar']
        }
        const result = (shipCast as any).checkAcknowledgmentFromSpecificHosts(
          hostAcknowledgments,
          requirements
        )
        expect(result).toBe(true)
      })

      it('should return false when specific hosts do not acknowledge all required topics', () => {
        const hostAcknowledgments = {
          'https://host1.com': new Set(['tm_foo']),
          'https://host2.com': new Set(['tm_bar'])
        }
        const requirements = {
          'https://host1.com': ['tm_foo', 'tm_bar']
        }
        const result = (shipCast as any).checkAcknowledgmentFromSpecificHosts(
          hostAcknowledgments,
          requirements
        )
        expect(result).toBe(false)
      })

      it('should return true when specific hosts acknowledge any of the required topics', () => {
        const hostAcknowledgments = {
          'https://host1.com': new Set(['tm_foo']),
          'https://host2.com': new Set(['tm_bar'])
        }
        const requirements = {
          'https://host1.com': 'any'
        }
        const result = (shipCast as any).checkAcknowledgmentFromSpecificHosts(
          hostAcknowledgments,
          requirements
        )
        expect(result).toBe(true)
      })

      it('should return false when specific hosts do not acknowledge any of the required topics', () => {
        const hostAcknowledgments = {
          'https://host1.com': new Set(),
          'https://host2.com': new Set(['tm_bar'])
        }
        const requirements = {
          'https://host1.com': 'any'
        }
        const result = (shipCast as any).checkAcknowledgmentFromSpecificHosts(
          hostAcknowledgments,
          requirements
        )
        expect(result).toBe(false)
      })

      it('should handle multiple hosts with different requirements', () => {
        const hostAcknowledgments = {
          'https://host1.com': new Set(['tm_foo']),
          'https://host2.com': new Set(['tm_bar']),
          'https://host3.com': new Set(['tm_foo', 'tm_bar'])
        }
        const requirements = {
          'https://host1.com': ['tm_foo'],
          'https://host2.com': 'any',
          'https://host3.com': 'all'
        }
        const result = (shipCast as any).checkAcknowledgmentFromSpecificHosts(
          hostAcknowledgments,
          requirements
        )
        expect(result).toBe(true)
      })

      it('should return false if any specific host fails to meet its requirement', () => {
        const hostAcknowledgments = {
          'https://host1.com': new Set(['tm_foo']),
          'https://host2.com': new Set(),
          'https://host3.com': new Set(['tm_foo'])
        }
        const requirements = {
          'https://host1.com': ['tm_foo'],
          'https://host2.com': 'any',
          'https://host3.com': ['tm_foo', 'tm_bar']
        }
        const result = (shipCast as any).checkAcknowledgmentFromSpecificHosts(
          hostAcknowledgments,
          requirements
        )
        expect(result).toBe(false)
      })
    })
  })
})
