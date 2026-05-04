import { jest } from '@jest/globals'

Object.defineProperty(globalThis, 'jest', {
  configurable: true,
  value: jest,
  writable: true
})
