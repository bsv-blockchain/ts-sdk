/** eslint-env jest */
import { defaultChainTracker } from '../DefaultChainTracker'
import WhatsOnChain from '../WhatsOnChain'
import ChainTracker from '../../ChainTracker'

// --- Tests ------------------------------------------------------------------

describe('defaultChainTracker', () => {
  describe('return type and instance', () => {
    it('returns an instance of WhatsOnChain', () => {
      const tracker = defaultChainTracker()
      expect(tracker).toBeInstanceOf(WhatsOnChain)
    })

    it('satisfies the ChainTracker interface by having isValidRootForHeight method', () => {
      const tracker = defaultChainTracker()
      expect(typeof tracker.isValidRootForHeight).toBe('function')
    })

    it('returns a new instance on each call', () => {
      const tracker1 = defaultChainTracker()
      const tracker2 = defaultChainTracker()
      expect(tracker1).not.toBe(tracker2)
    })
  })

  describe('WhatsOnChain defaults', () => {
    it('defaults to mainnet network', () => {
      const tracker = defaultChainTracker() as WhatsOnChain
      expect(tracker.network).toBe('main')
    })

    it('returns a tracker that responds to isValidRootForHeight as a function', () => {
      const tracker = defaultChainTracker()
      // The method exists and is callable (we do not make real HTTP calls in unit tests)
      expect(tracker.isValidRootForHeight).toBeDefined()
      const returnValue = tracker.isValidRootForHeight('someRoot', 0)
      // It must return a Promise (thenable)
      expect(typeof returnValue.then).toBe('function')
      // Prevent unhandled rejection from real network call
      returnValue.catch(() => {})
    })
  })
})
