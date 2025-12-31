import type { PeerMessage, IdentityKey } from '../types'

/**
 * Abstract communications layer.
 *
 * This intentionally mirrors the essential subset of message-box-client / MessageBoxClient.
 * RemittanceManager never talks directly to HTTP/WebSockets – it only uses this interface.
 */
export interface CommsLayer {
  /**
   * Sends a message over the store-and-forward channel. Returns the transport messageId.
   */
  sendMessage: (args: { recipient: IdentityKey; messageBox: string; body: string }, hostOverride?: string) => Promise<string>

  /**
   * Sends a message over the live channel (e.g. WebSocket). Returns the transport messageId.
   * Implementers may throw if live sending is not possible.
   * RemittanceManager will fall back to sendMessage where appropriate.
   */
  sendLiveMessage?: (args: { recipient: IdentityKey; messageBox: string; body: string }, hostOverride?: string) => Promise<string>

  /**
   * Lists pending messages for a message box.
   */
  listMessages: (args: { messageBox: string; host?: string }) => Promise<PeerMessage[]>

  /**
   * Acknowledges messages (deletes them from the server / inbox).
   */
  acknowledgeMessage: (args: { messageIds: string[] }) => Promise<void>

  /**
   * Optional live listener.
   */
  listenForLiveMessages?: (args: {
    messageBox: string
    overrideHost?: string
    onMessage: (msg: PeerMessage) => void
  }) => Promise<void>
}
