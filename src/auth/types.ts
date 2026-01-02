import { VerifiableCertificate } from './certificates/VerifiableCertificate.js'

export interface RequestedCertificateTypeIDAndFieldList {
  [certificateTypeID: string]: string[]
}

// Define the structure for the requested certificates set
export interface RequestedCertificateSet {
  certifiers: string[]
  types: RequestedCertificateTypeIDAndFieldList
}

export interface AuthMessage {
  version: string
  messageType:
  | 'initialRequest'
  | 'initialResponse'
  | 'certificateRequest'
  | 'certificateResponse'
  | 'general'
  identityKey: string // Sender's public key (used for identity verification)
  nonce?: string // Sender's nonce (256-bit random value)
  initialNonce?: string
  yourNonce?: string // The recipient's nonce from a previous message (if applicable)
  certificates?: VerifiableCertificate[] // Optional: List of certificates (if required/requested)
  requestedCertificates?: RequestedCertificateSet // Optional: List of requested certificates
  payload?: number[] // The actual message data (optional, could be a string or an object)
  signature?: number[] // Digital signature covering the entire message
}

export interface Transport {
  send: (message: AuthMessage) => Promise<void>
  onData: (callback: (message: AuthMessage) => Promise<void>) => Promise<void>
}

export interface PeerSession {
  isAuthenticated: boolean
  sessionNonce?: string
  peerNonce?: string
  peerIdentityKey?: string
  lastUpdate: number
  certificatesRequired?: boolean
  certificatesValidated?: boolean
}
