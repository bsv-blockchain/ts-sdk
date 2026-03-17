import { toHex, fromBase58Check, toBase58Check, toArray } from '../primitives/utils.js'
import { Hash } from '../primitives/index.js'

/**
 * Takes a UHRP URL and removes any prefixes.
 * @param {string} URL - The UHRP URL.
 * @returns {string} - Normalized URL.
 */
export const normalizeURL = (URL: string): string => {
  if (URL.toLowerCase().startsWith('uhrp:')) URL = URL.slice(5)
  if (URL.startsWith('//')) URL = URL.slice(2)
  return URL
}

/**
 * Generates a UHRP URL from a given SHA-256 hash.
 * @param {number[]} hash - 32-byte SHA-256 hash.
 * @returns {string} - Base58Check encoded URL.
 */
export const getURLForHash = (hash: number[]): string => {
  if (hash.length !== 32) {
    throw new Error('Hash length must be 32 bytes (sha256)')
  }
  return toBase58Check(hash, toArray('ce00', 'hex'))
}

/**
 * Generates a UHRP URL for a given file.
 * Uses a streaming hash to avoid excessive memory usage with large files.
 * @param {Uint8Array | number[]} file - File content as a typed array or number array.
 * @returns {string} - Base58Check encoded URL.
 */
export const getURLForFile = (file: Uint8Array | number[]): string => {
  const data = file instanceof Uint8Array ? file : Uint8Array.from(file)
  const hasher = new Hash.SHA256()
  const chunkSize = 1024 * 1024
  for (let i = 0; i < data.length; i += chunkSize) {
    const chunk = data.subarray(i, i + chunkSize)
    hasher.update(Array.from(chunk))
  }
  const hash = hasher.digest()
  return getURLForHash(hash)
}

/**
 * Extracts the hash from a UHRP URL.
 * @param {string} URL - UHRP URL.
 * @returns {number[]} - Extracted SHA-256 hash.
 */
export const getHashFromURL = (URL: string): number[] => {
  URL = normalizeURL(URL)
  const { data, prefix } = fromBase58Check(URL, undefined, 2)
  if (data.length !== 32) {
    throw new Error('Invalid length!')
  }
  if (toHex(prefix as number[]) !== 'ce00') {
    throw new Error('Bad prefix')
  }
  return data as number[]
}

/**
 * Checks if a URL is a valid UHRP URL.
 * @param {string} URL - The URL to validate.
 * @returns {boolean} - True if valid, false otherwise.
 */
export const isValidURL = (URL: string): boolean => {
  try {
    getHashFromURL(URL)
    return true
  } catch {
    return false
  }
}
