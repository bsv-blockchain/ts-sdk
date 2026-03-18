/* eslint-env jest */
/**
 * Additional tests for src/primitives/Random.ts
 *
 * The existing Random.test.ts covers the happy-path via the real Node.js 18+
 * globalThis.crypto path.  These tests exercise the remaining branches by
 * isolating the module in different synthetic environments so that the Rand
 * constructor walks a different code path each time.
 *
 * Because the module caches its `ayn` singleton at the module level we must
 * re-require a fresh copy via jest.isolateModules() for every environment
 * variant.
 *
 * NOTE: In Node 18+, globalThis.crypto is a getter on the prototype, not an
 * own property. To shadow it, we use Object.defineProperty to install an own
 * property with configurable:true, then delete it in afterEach to restore.
 */

/** Shadow globalThis.crypto with the given value (or undefined). */
function shadowCrypto (value: any): void {
  Object.defineProperty(globalThis, 'crypto', {
    value,
    configurable: true,
    writable: true
  })
}

/** Remove the own-property shadow so the prototype getter is visible again. */
function restoreCrypto (): void {
  // Only delete if we installed an own property
  if (Object.prototype.hasOwnProperty.call(globalThis, 'crypto')) {
    delete (globalThis as any).crypto
  }
}

describe('Random – environment branches', () => {
  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  /** Load a fresh copy of the Random module inside the current environment. */
  function loadRandom (): (len: number) => number[] {
    let Random: (len: number) => number[]
    // isolateModules executes synchronously
    jest.isolateModules(() => {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      Random = require('../../primitives/Random').default
    })
    return Random!
  }

  // -------------------------------------------------------------------------
  // 1. globalThis.crypto path (already covered by the main test suite but
  //    explicitly validated here to confirm isolateModules works).
  // -------------------------------------------------------------------------
  describe('globalThis.crypto path', () => {
    it('produces bytes when globalThis.crypto is available', () => {
      // Node 18+ exposes globalThis.crypto – do not mock, just verify the
      // isolated module still works.
      const Random = loadRandom()
      const bytes = Random(16)
      expect(bytes).toHaveLength(16)
      bytes.forEach(b => {
        expect(b).toBeGreaterThanOrEqual(0)
        expect(b).toBeLessThanOrEqual(255)
      })
    })
  })

  // -------------------------------------------------------------------------
  // 2. self.crypto path (Web Worker / Service Worker environment)
  // -------------------------------------------------------------------------
  describe('self.crypto path', () => {
    const hadSelf = typeof self !== 'undefined'
    let originalSelf: any
    let originalProcess: any

    beforeEach(() => {
      // Shadow globalThis.crypto with undefined so the first branch is skipped
      shadowCrypto(undefined)
      originalSelf = (globalThis as any).self
      // Remove process so the Node.js < 18 branch (which precedes self.crypto) is also skipped
      originalProcess = (globalThis as any).process
      delete (globalThis as any).process
    })

    afterEach(() => {
      restoreCrypto()
      if (hadSelf) {
        (globalThis as any).self = originalSelf
      } else {
        delete (globalThis as any).self
      }
      ;(globalThis as any).process = originalProcess
    })

    it('uses self.crypto.getRandomValues when globalThis.crypto is absent', () => {
      const mockGetRandomValues = jest.fn((arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) arr[i] = 42
        return arr
      })

      // Install a synthetic `self` with a working crypto object.
      ;(globalThis as any).self = {
        crypto: { getRandomValues: mockGetRandomValues }
      }

      const Random = loadRandom()
      const bytes = Random(4)

      expect(bytes).toHaveLength(4)
      expect(bytes).toEqual([42, 42, 42, 42])
      expect(mockGetRandomValues).toHaveBeenCalledTimes(1)
    })
  })

  // -------------------------------------------------------------------------
  // 3. window.crypto path (browser main-thread environment)
  // -------------------------------------------------------------------------
  describe('window.crypto path', () => {
    const hadSelf = typeof self !== 'undefined'
    const hadWindow = typeof window !== 'undefined'
    let originalSelf: any
    let originalWindow: any
    let originalProcess: any

    beforeEach(() => {
      // Shadow globalThis.crypto with undefined
      shadowCrypto(undefined)
      originalSelf = (globalThis as any).self
      originalWindow = (globalThis as any).window
      // Remove process and self so the Node.js and self.crypto branches are skipped
      originalProcess = (globalThis as any).process
      delete (globalThis as any).process
      delete (globalThis as any).self
    })

    afterEach(() => {
      restoreCrypto()
      if (hadSelf) {
        (globalThis as any).self = originalSelf
      } else {
        delete (globalThis as any).self
      }
      if (hadWindow) {
        (globalThis as any).window = originalWindow
      } else {
        delete (globalThis as any).window
      }
      ;(globalThis as any).process = originalProcess
    })

    it('uses window.crypto.getRandomValues when globalThis/self.crypto are absent', () => {
      const mockGetRandomValues = jest.fn((arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) arr[i] = 99
        return arr
      })

      ;(globalThis as any).window = {
        crypto: { getRandomValues: mockGetRandomValues }
      }

      const Random = loadRandom()
      const bytes = Random(3)

      expect(bytes).toHaveLength(3)
      expect(bytes).toEqual([99, 99, 99])
      expect(mockGetRandomValues).toHaveBeenCalledTimes(1)
    })
  })

  // -------------------------------------------------------------------------
  // 4. noRand path – throws when no crypto is available anywhere
  // -------------------------------------------------------------------------
  describe('noRand path', () => {
    const hadSelf = typeof self !== 'undefined'
    const hadWindow = typeof window !== 'undefined'
    let originalSelf: any
    let originalWindow: any
    let originalProcess: any

    beforeEach(() => {
      // Shadow globalThis.crypto with undefined
      shadowCrypto(undefined)
      originalSelf = (globalThis as any).self
      delete (globalThis as any).self
      originalWindow = (globalThis as any).window
      delete (globalThis as any).window
      // Remove process entirely so that the Node < 18 require('crypto') branch is skipped
      originalProcess = (globalThis as any).process
      delete (globalThis as any).process
    })

    afterEach(() => {
      restoreCrypto()
      if (hadSelf) {
        (globalThis as any).self = originalSelf
      } else {
        delete (globalThis as any).self
      }
      if (hadWindow) {
        (globalThis as any).window = originalWindow
      } else {
        delete (globalThis as any).window
      }
      ;(globalThis as any).process = originalProcess
    })

    it('throws an error when no crypto source is available', () => {
      const Random = loadRandom()
      expect(() => Random(16)).toThrow(
        'No secure random number generator is available in this environment.'
      )
    })
  })

  // -------------------------------------------------------------------------
  // 5. Node.js < 18 require('crypto') fallback path
  // -------------------------------------------------------------------------
  describe('Node.js < 18 require(\'crypto\') fallback path', () => {
    beforeEach(() => {
      // Shadow globalThis.crypto with undefined so the first branch is skipped
      // and the constructor falls through to the process.release.name === 'node' check
      shadowCrypto(undefined)
    })

    afterEach(() => {
      restoreCrypto()
    })

    it('falls through to require("crypto").randomBytes when globalThis.crypto is absent', () => {
      // process.release.name === 'node' is already true in Jest / Node.
      // With globalThis.crypto shadowed as undefined the module should attempt require('crypto')
      // and use randomBytes successfully.
      const Random = loadRandom()
      const bytes = Random(8)
      expect(bytes).toHaveLength(8)
      bytes.forEach(b => {
        expect(b).toBeGreaterThanOrEqual(0)
        expect(b).toBeLessThanOrEqual(255)
      })
    })
  })

  // -------------------------------------------------------------------------
  // 6. Singleton caching – ayn is reused across calls
  // -------------------------------------------------------------------------
  describe('singleton caching', () => {
    it('caches the Rand instance across multiple calls within the same module scope', () => {
      // We cannot access `ayn` directly, but we can verify that calling the
      // exported function multiple times without resetting the module still
      // produces valid results (the cached instance is reused without error).
      jest.isolateModules(() => {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const Random = require('../../primitives/Random').default as (len: number) => number[]
        expect(Random(4)).toHaveLength(4)
        expect(Random(4)).toHaveLength(4)
        expect(Random(4)).toHaveLength(4)
      })
    })
  })
})
