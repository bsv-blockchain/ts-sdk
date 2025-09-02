import SatoshisPerKilobyte from './SatoshisPerKilobyte.js'
import Transaction from '../Transaction.js'

/**
 * Represents a live fee policy that fetches current rates from ARC GorillaPool.
 * Extends SatoshisPerKilobyte to reuse transaction size calculation logic.
 */
export default class LivePolicy extends SatoshisPerKilobyte {
  private static readonly ARC_POLICY_URL = 'https://arc.gorillapool.io/v1/policy'
  private static instance: LivePolicy | null = null
  private cachedRate: number | null = null
  private cacheTimestamp: number = 0
  private readonly cacheValidityMs: number

  /**
   * Constructs an instance of the live policy fee model.
   *
   * @param {number} cacheValidityMs - How long to cache the fee rate in milliseconds (default: 5 minutes)
   */
  constructor(cacheValidityMs: number = 5 * 60 * 1000) {
    super(100) // Initialize with dummy value, will be overridden by fetchFeeRate
    this.cacheValidityMs = cacheValidityMs
  }

  /**
   * Gets the singleton instance of LivePolicy to ensure cache sharing across the application.
   *
   * @param {number} cacheValidityMs - How long to cache the fee rate in milliseconds (default: 5 minutes)
   * @returns The singleton LivePolicy instance
   */
  static getInstance(cacheValidityMs: number = 5 * 60 * 1000): LivePolicy {
    if (!LivePolicy.instance) {
      LivePolicy.instance = new LivePolicy(cacheValidityMs)
    }
    return LivePolicy.instance
  }

  /**
   * Fetches the current fee rate from ARC GorillaPool API.
   * 
   * @returns The current satoshis per kilobyte rate
   */
  private async fetchFeeRate(): Promise<number> {
    const now = Date.now()
    
    // Return cached rate if still valid
    if (this.cachedRate !== null && (now - this.cacheTimestamp) < this.cacheValidityMs) {
      return this.cachedRate
    }

    try {
      const response = await fetch(LivePolicy.ARC_POLICY_URL)
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }
      
      const response_data = await response.json()
      
      if (!response_data.policy?.miningFee || typeof response_data.policy.miningFee.satoshis !== 'number' || typeof response_data.policy.miningFee.bytes !== 'number') {
        throw new Error('Invalid policy response format')
      }
      
      // Convert to satoshis per kilobyte
      const rate = (response_data.policy.miningFee.satoshis / response_data.policy.miningFee.bytes) * 1000
      
      // Cache the result
      this.cachedRate = rate
      this.cacheTimestamp = now
      
      return rate
    } catch (error) {
      // If we have a cached rate, use it as fallback
      if (this.cachedRate !== null) {
        console.warn('Failed to fetch live fee rate, using cached value:', error)
        return this.cachedRate
      }
      
      // Otherwise, use a reasonable default (100 sat/kb)
      console.warn('Failed to fetch live fee rate, using default 100 sat/kb:', error)
      return 100
    }
  }

  /**
   * Computes the fee for a given transaction using the current live rate.
   * Overrides the parent method to use dynamic rate fetching.
   *
   * @param tx The transaction for which a fee is to be computed.
   * @returns The fee in satoshis for the transaction.
   */
  async computeFee(tx: Transaction): Promise<number> {
    const rate = await this.fetchFeeRate()
    // Update the value property so parent's computeFee uses the live rate
    this.value = rate
    return super.computeFee(tx)
  }
}
