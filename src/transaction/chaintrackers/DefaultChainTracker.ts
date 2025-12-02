import WhatsOnChain from './WhatsOnChain.js'
import ChainTracker from '../ChainTracker.js'

export function defaultChainTracker (): ChainTracker {
  return new WhatsOnChain()
}
