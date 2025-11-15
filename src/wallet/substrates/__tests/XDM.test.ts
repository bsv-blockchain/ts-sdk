import XDMSubstrate from '../../../wallet/substrates/XDM'
import { WalletError } from '../../../wallet/WalletError'
import { Utils } from '../../../primitives/index'

describe('XDMSubstrate', () => {
  let xdmSubstrate: XDMSubstrate
  let originalWindow: Window & typeof globalThis | undefined
  let addEventListenerMock: jest.Mock

  beforeEach(() => {
    originalWindow = global.window
    addEventListenerMock = jest.fn()

    global.window = {
      postMessage: jest.fn(),
      parent: {
        postMessage: jest.fn()
      } as unknown as Window,
      addEventListener: addEventListenerMock,
      removeEventListener: jest.fn()
    } as unknown as Window & typeof globalThis

    jest.spyOn(window.parent, 'postMessage')
  })

  afterEach(() => {
    global.window = originalWindow as any
    jest.restoreAllMocks()
  })

  const getMessageListener = () => {
    const calls = addEventListenerMock.mock.calls
    const lastCall = calls[calls.length - 1]
    if (!lastCall) {
      throw new Error('No message listener registered.')
    }
    return lastCall[1] as (event: MessageEvent) => void
  }

  const dispatchMessage = (event: Partial<MessageEvent> & { data: any }) => {
    getMessageListener()(event as MessageEvent)
  }

  describe('constructor', () => {
    it('should throw if window is not an object', () => {
      ;(global as any).window = undefined
      expect(() => {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const _ = new XDMSubstrate()
      }).toThrow('The XDM substrate requires a global window object.')
    })

    it('should throw if window.postMessage is not an object', () => {
      ;(global.window as any).postMessage = undefined
      expect(() => {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const _ = new XDMSubstrate()
      }).toThrow(
        'The window object does not seem to support postMessage calls.'
      )
    })

    it('should construct successfully if window and window.postMessage are defined', () => {
      expect(() => {
        xdmSubstrate = new XDMSubstrate()
      }).not.toThrow()
    })
  })

  describe('invoke', () => {
    beforeEach(() => {
      xdmSubstrate = new XDMSubstrate()
    })

    it('should send a message to window.parent.postMessage with correct parameters', async () => {
      const call = 'testCall'
      const args = { foo: 'bar' }
      const mockId = 'mockedId'

      jest.spyOn(Utils, 'toBase64').mockReturnValue(mockId)

      xdmSubstrate.invoke(call as any, args) as any
      expect(window.parent.postMessage).toHaveBeenCalledWith(
        {
          type: 'CWI',
          isInvocation: true,
          id: mockId,
          call,
          args
        },
        '*'
      )
    })

    it('should resolve when receiving a valid message', async () => {
      const call = 'testCall'
      const args = { foo: 'bar' }
      const result = { data: 'some data' }
      const mockId = 'mockedId'

      jest.spyOn(Utils, 'toBase64').mockReturnValue(mockId)

      const invokePromise = xdmSubstrate.invoke(call as any, args)

      // Simulate receiving the message
      const event = {
        data: {
          type: 'CWI',
          isInvocation: false,
          id: mockId,
          status: 'success',
          result
        },
        isTrusted: true
      }

      dispatchMessage(event)

      const res = await invokePromise

      expect(res).toEqual(result)
    })

    it('should reject when receiving an error message', async () => {
      const call = 'testCall'
      const args = { foo: 'bar' }
      const errorDescription = 'An error occurred'
      const errorCode = 123
      const mockId = 'mockedId'

      jest.spyOn(Utils, 'toBase64').mockReturnValue(mockId)

      const invokePromise = xdmSubstrate.invoke(call as any, args)

      // Simulate receiving the message
      const event = {
        data: {
          type: 'CWI',
          isInvocation: false,
          id: mockId,
          status: 'error',
          description: errorDescription,
          code: errorCode
        },
        isTrusted: true
      }

      dispatchMessage(event)

      await expect(invokePromise).rejects.toThrow(WalletError)
      await expect(invokePromise).rejects.toThrow(errorDescription)
      try {
        await invokePromise
      } catch (err) {
        expect(err.code).toBe(errorCode)
      }
    })

    it('should ignore messages with incorrect type', async () => {
      const call = 'testCall'
      const args = { foo: 'bar' }
      const result = { data: 'some data' }
      const mockId = 'mockedId'

      jest.spyOn(Utils, 'toBase64').mockReturnValue(mockId)

      const invokePromise = xdmSubstrate.invoke(call as any, args)

      // Simulate receiving an unrelated message
      const event = {
        data: {
          type: 'WrongType',
          isInvocation: false,
          id: mockId,
          status: 'success',
          result
        },
        isTrusted: true
      }

      dispatchMessage(event)

      // The promise should still be pending
      let isResolved = false
      invokePromise.then(() => {
        isResolved = true
      })

      // Wait a bit to ensure no unintended resolution
      await new Promise((resolve) => setTimeout(resolve, 1))
      expect(isResolved).toBe(false)
    })

    it('should ignore messages with incorrect id', async () => {
      const call = 'testCall'
      const args = { foo: 'bar' }
      const result = { data: 'some data' }
      const mockId = 'mockedId'

      jest.spyOn(Utils, 'toBase64').mockReturnValue(mockId)

      const invokePromise = xdmSubstrate.invoke(call as any, args)

      // Simulate receiving a message with wrong id
      const event = {
        data: {
          type: 'CWI',
          isInvocation: false,
          id: 'wrongId',
          status: 'success',
          result
        },
        isTrusted: true
      }

      dispatchMessage(event)

      // The promise should still be pending
      let isResolved = false
      invokePromise.then(() => {
        isResolved = true
      })

      // Wait a bit to ensure no unintended resolution
      await new Promise((resolve) => setTimeout(resolve, 1))
      expect(isResolved).toBe(false)
    })

    it('should ignore messages where e.isTrusted is false', async () => {
      const call = 'testCall'
      const args = { foo: 'bar' }
      const result = { data: 'some data' }
      const mockId = 'mockedId'

      jest.spyOn(Utils, 'toBase64').mockReturnValue(mockId)

      const invokePromise = xdmSubstrate.invoke(call as any, args)

      // Simulate receiving a message with isTrusted false
      const event = {
        data: {
          type: 'CWI',
          isInvocation: false,
          id: mockId,
          status: 'success',
          result
        },
        isTrusted: false
      }

      dispatchMessage(event)

      // The promise should still be pending
      let isResolved = false
      invokePromise.then(() => {
        isResolved = true
      })

      // Wait a bit to ensure no unintended resolution
      await new Promise((resolve) => setTimeout(resolve, 1))
      expect(isResolved).toBe(false)
    })

    it('should ignore messages where e.data.isInvocation is true', async () => {
      const call = 'testCall'
      const args = { foo: 'bar' }
      const result = { data: 'some data' }
      const mockId = 'mockedId'

      jest.spyOn(Utils, 'toBase64').mockReturnValue(mockId)

      const invokePromise = xdmSubstrate.invoke(call as any, args)

      // Simulate receiving a message with isInvocation true
      const event = {
        data: {
          type: 'CWI',
          isInvocation: true,
          id: mockId,
          status: 'success',
          result
        },
        isTrusted: true
      }

      dispatchMessage(event)

      // The promise should still be pending
      let isResolved = false
      invokePromise.then(() => {
        isResolved = true
      })

      // Wait a bit to ensure no unintended resolution
      await new Promise((resolve) => setTimeout(resolve, 1))
      expect(isResolved).toBe(false)
    })
  })

  // Helper function to test methods
  const testMethod = (methodName: string, args: any, result: any): void => {
    describe(methodName, () => {
      beforeEach(() => {
        xdmSubstrate = new XDMSubstrate()
      })

      it('should call invoke with correct arguments and return the result', async () => {
        const call = methodName
        const mockId = 'mockedId'

        jest.spyOn(Utils, 'toBase64').mockReturnValue(mockId)

        const invokePromise = xdmSubstrate[methodName](args)

        expect(window.parent.postMessage).toHaveBeenCalledWith(
          {
            type: 'CWI',
            isInvocation: true,
            id: mockId,
            call,
            args
          },
          '*'
        )

        const event = {
          data: {
            type: 'CWI',
            isInvocation: false,
            id: mockId,
            status: 'success',
            result
          },
          isTrusted: true
        }

        dispatchMessage(event)

        const res = await invokePromise
        expect(res).toEqual(result)
      })

      it('should throw error when invoke rejects', async () => {
        const call = methodName
        const errorDescription = 'An error occurred'
        const errorCode = 123
        const mockId = 'mockedId'

        jest.spyOn(Utils, 'toBase64').mockReturnValue(mockId)

        const invokePromise = xdmSubstrate[methodName](args)

        expect(window.parent.postMessage).toHaveBeenCalledWith(
          {
            type: 'CWI',
            isInvocation: true,
            id: mockId,
            call,
            args
          },
          '*'
        )

        // Simulate receiving an error message
        const event = {
          data: {
            type: 'CWI',
            isInvocation: false,
            id: mockId,
            status: 'error',
            description: errorDescription,
            code: errorCode
          },
          isTrusted: true
        }

        dispatchMessage(event)

        await expect(invokePromise).rejects.toThrow(WalletError)
        await expect(invokePromise).rejects.toThrow(errorDescription)
        await invokePromise.catch((err) => {
          expect(err.code).toBe(errorCode)
        })
      })
    })
  }

  // List of methods to test
  const methodsToTest = [
    {
      methodName: 'createAction',
      args: {
        description: 'Test description',
        inputs: [],
        outputs: []
      },
      result: { txid: 'abc123' }
    },
    {
      methodName: 'signAction',
      args: {
        spends: {},
        reference: 'someReference'
      },
      result: { txid: 'abc123' }
    },
    {
      methodName: 'abortAction',
      args: {
        reference: 'someReference'
      },
      result: { aborted: true }
    },
    {
      methodName: 'listActions',
      args: {
        labels: []
      },
      result: { totalActions: 0, actions: [] }
    },
    {
      methodName: 'internalizeAction',
      args: {
        tx: 'someTx',
        outputs: [],
        description: 'Test description'
      },
      result: { accepted: true }
    },
    {
      methodName: 'listOutputs',
      args: {
        basket: 'someBasket'
      },
      result: { totalOutputs: 0, outputs: [] }
    },
    {
      methodName: 'relinquishOutput',
      args: {
        basket: 'someBasket',
        output: 'someOutput'
      },
      result: { relinquished: true }
    },
    {
      methodName: 'getPublicKey',
      args: {
        identityKey: true
      },
      result: { publicKey: 'somePubKey' }
    },
    {
      methodName: 'revealCounterpartyKeyLinkage',
      args: {
        counterparty: 'someCounterparty',
        verifier: 'someVerifier'
      },
      result: {
        prover: 'someProver',
        verifier: 'someVerifier',
        counterparty: 'someCounterparty',
        revelationTime: 'someTime',
        encryptedLinkage: [],
        encryptedLinkageProof: []
      }
    },
    {
      methodName: 'revealSpecificKeyLinkage',
      args: {
        counterparty: 'someCounterparty',
        verifier: 'someVerifier',
        protocolID: [0, 'someProtocol'],
        keyID: 'someKeyID'
      },
      result: {
        prover: 'someProver',
        verifier: 'someVerifier',
        counterparty: 'someCounterparty',
        protocolID: [0, 'someProtocol'],
        keyID: 'someKeyID',
        encryptedLinkage: [],
        encryptedLinkageProof: [],
        proofType: []
      }
    },
    {
      methodName: 'encrypt',
      args: {
        plaintext: [],
        protocolID: [0, 'someProtocol'],
        keyID: 'someKeyID'
      },
      result: { ciphertext: [] }
    },
    {
      methodName: 'decrypt',
      args: {
        ciphertext: [],
        protocolID: [0, 'someProtocol'],
        keyID: 'someKeyID'
      },
      result: { plaintext: [] }
    },
    {
      methodName: 'createHmac',
      args: {
        data: [],
        protocolID: [0, 'someProtocol'],
        keyID: 'someKeyID'
      },
      result: { hmac: [] }
    },
    {
      methodName: 'verifyHmac',
      args: {
        data: [],
        hmac: [],
        protocolID: [0, 'someProtocol'],
        keyID: 'someKeyID'
      },
      result: { valid: true }
    },
    {
      methodName: 'createSignature',
      args: {
        data: [],
        protocolID: [0, 'someProtocol'],
        keyID: 'someKeyID'
      },
      result: { signature: [] }
    },
    {
      methodName: 'verifySignature',
      args: {
        data: [],
        signature: [],
        protocolID: [0, 'someProtocol'],
        keyID: 'someKeyID'
      },
      result: { valid: true }
    },
    {
      methodName: 'acquireCertificate',
      args: {
        type: 'someType',
        subject: 'someSubject',
        serialNumber: 'someSerialNumber',
        revocationOutpoint: 'someOutpoint',
        signature: 'someSignature',
        fields: {},
        certifier: 'someCertifier',
        keyringRevealer: 'certifier',
        keyringForSubject: {},
        acquisitionProtocol: 'direct'
      },
      result: {
        type: 'someType',
        subject: 'someSubject',
        serialNumber: 'someSerialNumber',
        certifier: 'someCertifier',
        revocationOutpoint: 'someOutpoint',
        signature: 'someSignature',
        fields: {}
      }
    },
    {
      methodName: 'listCertificates',
      args: {
        certifiers: [],
        types: []
      },
      result: {
        totalCertificates: 0,
        certificates: []
      }
    },
    {
      methodName: 'proveCertificate',
      args: {
        certificate: {
          type: 'someType',
          subject: 'someSubject',
          serialNumber: 'someSerialNumber',
          certifier: 'someCertifier',
          revocationOutpoint: 'someOutpoint',
          signature: 'someSignature',
          fields: {}
        },
        fieldsToReveal: [],
        verifier: 'someVerifier'
      },
      result: {
        keyringForVerifier: {}
      }
    },
    {
      methodName: 'relinquishCertificate',
      args: {
        type: 'someType',
        serialNumber: 'someSerialNumber',
        certifier: 'someCertifier'
      },
      result: { relinquished: true }
    },
    {
      methodName: 'discoverByIdentityKey',
      args: {
        identityKey: 'someIdentityKey'
      },
      result: {
        totalCertificates: 0,
        certificates: []
      }
    },
    {
      methodName: 'discoverByAttributes',
      args: {
        attributes: {}
      },
      result: {
        totalCertificates: 0,
        certificates: []
      }
    },
    {
      methodName: 'isAuthenticated',
      args: {},
      result: { authenticated: true }
    },
    {
      methodName: 'waitForAuthentication',
      args: {},
      result: { authenticated: true }
    },
    {
      methodName: 'getHeight',
      args: {},
      result: { height: 1000 }
    },
    {
      methodName: 'getHeaderForHeight',
      args: { height: 1000 },
      result: { header: 'someHeader' }
    },
    {
      methodName: 'getNetwork',
      args: {},
      result: { network: 'mainnet' }
    },
    {
      methodName: 'getVersion',
      args: {},
      result: { version: '1.0.0' }
    }
  ]

  methodsToTest.forEach(({ methodName, args, result }) => {
    testMethod(methodName, args, result)
  })
})
