# Authenticated HTTP Requests with AuthFetch

**Duration**: 60 minutes  
**Prerequisites**: Node.js, basic TypeScript knowledge, understanding of HTTP and authentication  
**Learning Goals**:
- Understand BRC-103/104 authentication protocols
- Implement authenticated HTTP requests with AuthFetch
- Handle peer-to-peer authentication and certificate exchange
- Build secure API communication systems

## When to Use AuthFetch

**Use AuthFetch when you need:**
- BRC-103/104 cryptographic authentication
- Wallet-signed HTTP requests for identity verification
- Certificate-based peer authentication
- Secure peer-to-peer communication between BSV applications
- APIs that require cryptographic proof of identity

**For general HTTP client configuration, use [HTTP Client Configuration Guide](../guides/http-client-configuration.md) instead:**
- Custom HTTP client setup (Axios, fetch, etc.)
- Transaction broadcasting via ARC endpoints
- Environment-specific configuration (timeouts, retries)
- Testing and mocking HTTP clients
- Integration with existing HTTP infrastructure

## Introduction

AuthFetch is a specialized HTTP client that implements BRC-103 and BRC-104 authentication protocols for secure peer-to-peer communication in the BSV ecosystem. Unlike traditional API authentication (like JWT tokens), AuthFetch uses cryptographic signatures and certificate-based authentication.

## Key Features

- **BRC-103 Authentication**: Cryptographic request signing
- **BRC-104 Certificate Exchange**: Peer identity verification
- **Automatic Session Management**: Handles authentication state
- **Certificate Validation**: Verifies peer credentials
- **Secure Communication**: End-to-end authenticated requests

## What You'll Build

In this tutorial, you'll create:
- Basic authenticated HTTP client
- Peer-to-peer communication system
- Certificate exchange mechanism
- Secure API integration

## Setting Up AuthFetch with `WalletClient`

### Basic AuthFetch Configuration

```typescript
import { AuthFetch, WalletClient } from '@bsv/sdk'

async function createAuthFetch() {
  // Create wallet for authentication - connects to local wallet (e.g., Metanet Desktop)
  const wallet = new WalletClient('auto', 'localhost')
  
  // Check if wallet is connected
  try {
    const authStatus = await wallet.isAuthenticated()
    console.log('Wallet authenticated:', authStatus.authenticated)
    
    const network = await wallet.getNetwork()
    console.log('Connected to network:', network.network)
  } catch (error) {
    console.log('Wallet connection status:', error.message)
    // This is expected if no wallet is running
  }
  
  // Create AuthFetch instance
  const authFetch = new AuthFetch(wallet)
  
  console.log('AuthFetch client created')
  return authFetch
}

async function basicAuthenticatedRequest() {
  const authFetch = await createAuthFetch()
  
  try {
    // Make authenticated request to a real, working endpoint
    const response = await authFetch.fetch('https://httpbin.org/get', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-BSV-Tutorial': 'AuthFetch-Example'
      }
    })
    
    if (response.ok) {
      const data = await response.json()
      console.log('Authenticated request successful!')
      console.log('Request URL:', data.url)
      console.log('Headers sent:', Object.keys(data.headers).length)
      return data
    } else {
      console.error('Request failed:', response.status, response.statusText)
    }
  } catch (error) {
    console.error('Authentication error:', error.message)
    if (error.message.includes('No wallet available')) {
      console.log(' Install and run Metanet Desktop Wallet to test with real authentication')
      console.log('   For now, this demonstrates the AuthFetch API structure')
    }
  }
}

// Test the basic functionality
basicAuthenticatedRequest().catch(console.error)
```

### AuthFetch with Certificate Requirements

```typescript
import { AuthFetch, WalletClient } from '@bsv/sdk'

async function createAuthFetchWithCertificates() {
  const wallet = new WalletClient('auto', 'localhost')
  
  // Define required certificates from peers
  const requestedCertificates = {
    certifiers: {
      // Require identity certificates from trusted certifier
      'identity-certifier-key': {
        certificateTypes: ['identity-cert'],
        fieldsRequired: ['name', 'email']
      }
    },
    acquisitionProtocol: 'direct' as const
  }
  
  const authFetch = new AuthFetch(wallet, requestedCertificates)
  
  console.log('AuthFetch with certificate requirements created')
  return authFetch
}

async function testCertificateRequirements() {
  const authFetch = await createAuthFetchWithCertificates()
  
  try {
    // Test with a real endpoint that will show our certificate headers (using a dummy URL for demo purposes)
    const response = await authFetch.fetch('https://httpbin.org/headers', {
      method: 'GET'
    })
    
    if (response.ok) {
      const data = await response.json()
      console.log('Certificate-enabled request successful!')
      console.log('Headers sent to server:', data.headers)
      
      // AuthFetch will include certificate-related headers when available
      const certHeaders = Object.keys(data.headers).filter(h => 
        h.toLowerCase().includes('cert') || h.toLowerCase().includes('auth')
      )
      console.log('Certificate/Auth headers:', certHeaders)
      
    } else {
      console.error('Request failed:', response.status)
    }
  } catch (error) {
    console.error('Certificate request error:', error.message)
    if (error.message.includes('No wallet available')) {
      console.log(' Certificate exchange requires a connected wallet')
    }
  }
}

testCertificateRequirements().catch(console.error)
```

## Certificate Exchange and Verification

### Requesting Certificates from Peers

```typescript
import { AuthFetch, WalletClient } from '@bsv/sdk'

class CertificateManager {
  private authFetch: AuthFetch
  
  constructor(wallet: WalletClient) {
    this.authFetch = new AuthFetch(wallet)
  }
  
  async requestPeerCertificates(
    peerBaseUrl: string,
    certificateRequirements: any
  ): Promise<any[]> {
    try {
      console.log('Requesting certificates from peer:', peerBaseUrl)
      
      const certificates = await this.authFetch.sendCertificateRequest(
        peerBaseUrl,
        certificateRequirements
      )
      
      console.log('Received certificates:', certificates.length)
      return certificates
    } catch (error) {
      console.error('Certificate request failed:', error)
      throw error
    }
  }
  
  async verifyPeerIdentity(peerUrl: string): Promise<{
    verified: boolean
    identity: string | null
    certificates: any[]
  }> {
    const certificateRequirements = {
      certifiers: {
        'trusted-identity-provider': {
          certificateTypes: ['identity'],
          fieldsRequired: ['name']
        }
      },
      acquisitionProtocol: 'direct' as const
    }
    
    try {
      const certificates = await this.requestPeerCertificates(
        peerUrl,
        certificateRequirements
      )
      
      // Verify certificates (simplified verification)
      const verified = certificates.length > 0
      const identity = verified ? certificates[0].subject : null
      
      return { verified, identity, certificates }
    } catch (error) {
      console.error('Identity verification failed:', error)
      return { verified: false, identity: null, certificates: [] }
    }
  }
}

async function demonstrateCertificateExchange() {
  const wallet = new WalletClient('auto', 'localhost')
  const certManager = new CertificateManager(wallet)
  
  // Example peer URLs (replace with actual peer endpoints)
  const peerUrls = [
    'https://peer1.example.com',
    'https://peer2.example.com'
  ]
  
  for (const peerUrl of peerUrls) {
    console.log(`\n=== Verifying peer: ${peerUrl} ===`)
    
    try {
      const verification = await certManager.verifyPeerIdentity(peerUrl)
      
      if (verification.verified) {
        console.log(' Peer verified successfully')
        console.log('Identity:', verification.identity)
        console.log('Certificates received:', verification.certificates.length)
      } else {
        console.log(' Peer verification failed')
      }
    } catch (error) {
      console.log(' Peer unreachable or invalid')
    }
  }
}

demonstrateCertificateExchange().catch(console.error)
```

## Building Secure API Clients

### Authenticated API Client

```typescript
import { AuthFetch, WalletClient } from '@bsv/sdk'

class SecureAPIClient {
  private authFetch: AuthFetch
  private baseUrl: string
  
  constructor(baseUrl: string, wallet?: WalletClient) {
    this.baseUrl = baseUrl
    this.authFetch = new AuthFetch(wallet || new WalletClient('auto', 'localhost'))
  }
  
  async get(endpoint: string, options: any = {}): Promise<any> {
    return this.request('GET', endpoint, null, options)
  }
  
  async post(endpoint: string, data: any, options: any = {}): Promise<any> {
    return this.request('POST', endpoint, data, options)
  }
  
  async put(endpoint: string, data: any, options: any = {}): Promise<any> {
    return this.request('PUT', endpoint, data, options)
  }
  
  async delete(endpoint: string, options: any = {}): Promise<any> {
    return this.request('DELETE', endpoint, null, options)
  }
  
  private async request(
    method: string,
    endpoint: string,
    data: any = null,
    options: any = {}
  ): Promise<any> {
    const url = `${this.baseUrl}${endpoint}`
    
    const requestOptions: any = {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      }
    }
    
    if (data) {
      requestOptions.body = JSON.stringify(data)
    }
    
    try {
      console.log(`Making authenticated ${method} request to ${endpoint}`)
      
      const response = await this.authFetch.fetch(url, requestOptions)
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }
      
      const contentType = response.headers.get('content-type')
      if (contentType && contentType.includes('application/json')) {
        return await response.json()
      } else {
        return await response.text()
      }
    } catch (error) {
      console.error(`Request failed for ${method} ${endpoint}:`, error)
      throw error
    }
  }
  
  async healthCheck(): Promise<boolean> {
    try {
      await this.get('/health')
      return true
    } catch (error) {
      return false
    }
  }
}

async function demonstrateSecureAPIClient() {
  // Create secure API client using real, testable endpoints
  const apiClient = new SecureAPIClient('https://httpbin.org')
  
  try {
    // Health check using a real endpoint
    console.log('Testing API client with real endpoints...')
    
    // Test GET request
    const getResult = await apiClient.get('/get?test=true&client=secure')
    console.log('✅ GET request successful')
    console.log('Request URL:', getResult.url)
    console.log('Query parameters received:', getResult.args)
    
    // Test POST request with data
    const postResult = await apiClient.post('/post', {
      user: 'demo-user',
      action: 'test-post',
      timestamp: new Date().toISOString(),
      authenticated: true
    })
    console.log('✅ POST request successful')
    console.log('Data sent:', postResult.json)
    console.log('Content-Type:', postResult.headers['Content-Type'])
    
    // Test PUT request
    const putResult = await apiClient.put('/put', {
      resource: 'user-settings',
      theme: 'dark',
      notifications: true,
      updated: new Date().toISOString()
    })
    console.log('✅ PUT request successful')
    console.log('PUT data received:', putResult.json)
    
    // Test DELETE request
    const deleteResult = await apiClient.delete('/delete')
    console.log('✅ DELETE request successful')
    console.log('DELETE method confirmed:', deleteResult.url)
    
    // Test custom headers
    const headersResult = await apiClient.get('/headers')
    console.log('✅ Headers test successful')
    console.log('Custom headers sent:', Object.keys(headersResult.headers).length)
    
    return { 
      get: getResult, 
      post: postResult, 
      put: putResult, 
      delete: deleteResult,
      headers: headersResult
    }
  } catch (error) {
    console.error('API operations failed:', error.message)
    if (error.message.includes('No wallet available')) {
      console.log('💡 Install Metanet Desktop Wallet to test with real authentication')
      console.log('   The API calls work, but authentication requires a connected wallet')
    }
  }
}

demonstrateSecureAPIClient().catch(console.error)
```

### Multi-Peer Communication System

```typescript
import { AuthFetch, WalletClient } from '@bsv/sdk'

interface PeerInfo {
  url: string
  identity: string | null
  verified: boolean
  lastContact: Date
}

class PeerNetwork {
  private authFetch: AuthFetch
  private peers: Map<string, PeerInfo> = new Map()
  
  constructor(wallet?: WalletClient) {
    this.authFetch = new AuthFetch(wallet || new WalletClient('auto', 'localhost'))
  }
  
  async addPeer(peerUrl: string): Promise<boolean> {
    try {
      console.log(`Adding peer: ${peerUrl}`)
      
      // Verify peer identity
      const verification = await this.verifyPeer(peerUrl)
      
      const peerInfo: PeerInfo = {
        url: peerUrl,
        identity: verification.identity,
        verified: verification.verified,
        lastContact: new Date()
      }
      
      this.peers.set(peerUrl, peerInfo)
      
      console.log(`Peer ${peerUrl} ${verification.verified ? 'verified' : 'unverified'}`)
      return verification.verified
    } catch (error) {
      console.error(`Failed to add peer ${peerUrl}:`, error)
      return false
    }
  }
  
  private async verifyPeer(peerUrl: string): Promise<{
    verified: boolean
    identity: string | null
  }> {
    try {
      // Simple ping to verify peer is reachable
      const response = await this.authFetch.fetch(`${peerUrl}/ping`, {
        method: 'GET'
      })
      
      if (response.ok) {
        // In a real implementation, you would verify certificates here
        return { verified: true, identity: 'peer-identity' }
      } else {
        return { verified: false, identity: null }
      }
    } catch (error) {
      return { verified: false, identity: null }
    }
  }
  
  async broadcastMessage(message: any): Promise<{
    successful: string[]
    failed: string[]
  }> {
    const successful: string[] = []
    const failed: string[] = []
    
    console.log(`Broadcasting message to ${this.peers.size} peers`)
    
    const promises = Array.from(this.peers.entries()).map(async ([url, peerInfo]) => {
      try {
        const response = await this.authFetch.fetch(`${url}/message`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(message)
        })
        
        if (response.ok) {
          successful.push(url)
          // Update last contact
          peerInfo.lastContact = new Date()
        } else {
          failed.push(url)
        }
      } catch (error) {
        failed.push(url)
        console.error(`Failed to send message to ${url}:`, error)
      }
    })
    
    await Promise.all(promises)
    
    console.log(`Broadcast complete: ${successful.length} successful, ${failed.length} failed`)
    return { successful, failed }
  }
  
  async sendDirectMessage(peerUrl: string, message: any): Promise<any> {
    const peer = this.peers.get(peerUrl)
    if (!peer) {
      throw new Error(`Peer ${peerUrl} not found`)
    }
    
    if (!peer.verified) {
      throw new Error(`Peer ${peerUrl} not verified`)
    }
    
    try {
      const response = await this.authFetch.fetch(`${peerUrl}/direct-message`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(message)
      })
      
      if (response.ok) {
        peer.lastContact = new Date()
        return await response.json()
      } else {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }
    } catch (error) {
      console.error(`Direct message to ${peerUrl} failed:`, error)
      throw error
    }
  }
  
  getPeerStatus(): { total: number; verified: number; unverified: number } {
    const total = this.peers.size
    let verified = 0
    let unverified = 0
    
    for (const peer of this.peers.values()) {
      if (peer.verified) {
        verified++
      } else {
        unverified++
      }
    }
    
    return { total, verified, unverified }
  }
  
  listPeers(): PeerInfo[] {
    return Array.from(this.peers.values())
  }
}

async function demonstratePeerNetwork() {
  const network = new PeerNetwork()
  
  // Add peers (replace with actual peer URLs)
  const peerUrls = [
    'https://peer1.example.com',
    'https://peer2.example.com',
    'https://peer3.example.com'
  ]
  
  console.log('=== Setting up peer network ===')
  
  for (const peerUrl of peerUrls) {
    await network.addPeer(peerUrl)
  }
  
  const status = network.getPeerStatus()
  console.log('Network status:', status)
  
  // Broadcast message
  const broadcastMessage = {
    type: 'announcement',
    content: 'Hello from authenticated peer network!',
    timestamp: new Date().toISOString()
  }
  
  console.log('\n=== Broadcasting message ===')
  const broadcastResult = await network.broadcastMessage(broadcastMessage)
  console.log('Broadcast result:', broadcastResult)
  
  // Send direct message to first verified peer
  const peers = network.listPeers()
  const verifiedPeer = peers.find(p => p.verified)
  
  if (verifiedPeer) {
    console.log('\n=== Sending direct message ===')
    try {
      const directMessage = {
        type: 'direct',
        content: 'This is a direct authenticated message',
        timestamp: new Date().toISOString()
      }
      
      const response = await network.sendDirectMessage(verifiedPeer.url, directMessage)
      console.log('Direct message response:', response)
    } catch (error) {
      console.log('Direct message failed (expected in demo)')
    }
  }
  
  return { status, broadcastResult, peers }
}

demonstratePeerNetwork().catch(console.error)
```

## Advanced Authentication Patterns

### Session Management and Reconnection

```typescript
import { AuthFetch, WalletClient } from '@bsv/sdk'

class RobustAuthClient {
  private authFetch: AuthFetch
  private maxRetries: number = 3
  private retryDelay: number = 1000
  
  constructor(wallet?: WalletClient) {
    this.authFetch = new AuthFetch(wallet || new WalletClient('auto', 'localhost'))
  }
  
  async authenticatedRequest(
    url: string,
    options: any = {},
    retryCount: number = 0
  ): Promise<Response> {
    try {
      const response = await this.authFetch.fetch(url, options)
      
      if (response.status === 401 && retryCount < this.maxRetries) {
        console.log(`Authentication failed, retrying... (${retryCount + 1}/${this.maxRetries})`)
        
        // Wait and retry - AuthFetch will handle session management automatically
        await this.delay(this.retryDelay * (retryCount + 1))
        
        return this.authenticatedRequest(url, options, retryCount + 1)
      }
      
      return response
    } catch (error) {
      if (retryCount < this.maxRetries) {
        console.log(`Request failed, retrying... (${retryCount + 1}/${this.maxRetries})`)
        await this.delay(this.retryDelay * (retryCount + 1))
        return this.authenticatedRequest(url, options, retryCount + 1)
      }
      
      throw error
    }
  }
  
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }
  
  async batchRequests(requests: Array<{
    url: string
    options?: any
  }>): Promise<Array<{
    success: boolean
    response?: any
    error?: string
  }>> {
    const results = await Promise.allSettled(
      requests.map(req => this.authenticatedRequest(req.url, req.options))
    )
    
    return results.map((result, index) => {
      if (result.status === 'fulfilled') {
        return {
          success: true,
          response: result.value
        }
      } else {
        return {
          success: false,
          error: result.reason.message
        }
      }
    })
  }
}

async function demonstrateRobustAuthentication() {
  const robustClient = new RobustAuthClient()
  
  console.log('=== Testing robust authentication ===')
  
  // Single request with retry logic
  try {
    const response = await robustClient.authenticatedRequest('https://api.example.com/data')
    console.log('Single request successful:', response.ok)
  } catch (error) {
    console.log('Single request failed after retries:', error.message)
  }
  
  // Batch requests
  const batchRequests = [
    { url: 'https://api.example.com/endpoint1' },
    { url: 'https://api.example.com/endpoint2' },
    { url: 'https://api.example.com/endpoint3' }
  ]
  
  console.log('\n=== Testing batch requests ===')
  const batchResults = await robustClient.batchRequests(batchRequests)
  
  batchResults.forEach((result, index) => {
    console.log(`Request ${index + 1}:`, result.success ? 'SUCCESS' : `FAILED - ${result.error}`)
  })
  
  return batchResults
}

demonstrateRobustAuthentication().catch(console.error)
```

## Error Handling and Debugging

### Comprehensive Error Handling

```typescript
import { AuthFetch, WalletClient } from '@bsv/sdk'

enum AuthErrorType {
  NETWORK_ERROR = 'network_error',
  AUTHENTICATION_FAILED = 'authentication_failed',
  CERTIFICATE_INVALID = 'certificate_invalid',
  PEER_UNREACHABLE = 'peer_unreachable',
  SESSION_EXPIRED = 'session_expired'
}

class AuthError extends Error {
  constructor(
    public type: AuthErrorType,
    message: string,
    public originalError?: Error
  ) {
    super(message)
    this.name = 'AuthError'
  }
}

class AuthFetchWithErrorHandling {
  private authFetch: AuthFetch
  private debugMode: boolean = false
  
  constructor(wallet?: WalletClient, debugMode: boolean = false) {
    this.authFetch = new AuthFetch(wallet || new WalletClient('auto', 'localhost'))
    this.debugMode = debugMode
  }
  
  async safeRequest(url: string, options: any = {}): Promise<{
    success: boolean
    data?: any
    error?: AuthError
  }> {
    try {
      if (this.debugMode) {
        console.log(`[DEBUG] Making request to: ${url}`)
        console.log(`[DEBUG] Options:`, JSON.stringify(options, null, 2))
      }
      
      const response = await this.authFetch.fetch(url, options)
      
      if (this.debugMode) {
        console.log(`[DEBUG] Response status: ${response.status}`)
        console.log(`[DEBUG] Response headers:`, Object.fromEntries(response.headers.entries()))
      }
      
      if (!response.ok) {
        const errorType = this.categorizeHttpError(response.status)
        const errorMessage = await this.extractErrorMessage(response)
        
        return {
          success: false,
          error: new AuthError(errorType, errorMessage)
        }
      }
      
      const data = await this.parseResponse(response)
      return { success: true, data }
      
    } catch (error) {
      if (this.debugMode) {
        console.log(`[DEBUG] Request failed:`, error)
      }
      
      const authError = this.categorizeError(error)
      return { success: false, error: authError }
    }
  }
  
  private categorizeHttpError(status: number): AuthErrorType {
    switch (status) {
      case 401:
        return AuthErrorType.AUTHENTICATION_FAILED
      case 403:
        return AuthErrorType.CERTIFICATE_INVALID
      case 408:
      case 504:
        return AuthErrorType.PEER_UNREACHABLE
      default:
        return AuthErrorType.NETWORK_ERROR
    }
  }
  
  private async extractErrorMessage(response: Response): Promise<string> {
    try {
      const contentType = response.headers.get('content-type')
      if (contentType && contentType.includes('application/json')) {
        const errorData = await response.json()
        return errorData.message || errorData.error || `HTTP ${response.status}`
      } else {
        return await response.text() || `HTTP ${response.status}`
      }
    } catch {
      return `HTTP ${response.status}: ${response.statusText}`
    }
  }
  
  private async parseResponse(response: Response): Promise<any> {
    const contentType = response.headers.get('content-type')
    if (contentType && contentType.includes('application/json')) {
      return await response.json()
    } else {
      return await response.text()
    }
  }
  
  private categorizeError(error: any): AuthError {
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      return new AuthError(
        AuthErrorType.NETWORK_ERROR,
        'Network connection failed',
        error
      )
    }
    
    if (error.message.includes('certificate')) {
      return new AuthError(
        AuthErrorType.CERTIFICATE_INVALID,
        'Certificate validation failed',
        error
      )
    }
    
    if (error.message.includes('session')) {
      return new AuthError(
        AuthErrorType.SESSION_EXPIRED,
        'Authentication session expired',
        error
      )
    }
    
    return new AuthError(
      AuthErrorType.NETWORK_ERROR,
      error.message || 'Unknown error occurred',
      error
    )
  }
  
  async testConnectivity(urls: string[]): Promise<{
    reachable: string[]
    unreachable: string[]
    errors: Record<string, string>
  }> {
    const reachable: string[] = []
    const unreachable: string[] = []
    const errors: Record<string, string> = {}
    
    console.log(`Testing connectivity to ${urls.length} endpoints...`)
    
    const results = await Promise.allSettled(
      urls.map(url => this.safeRequest(`${url}/ping`))
    )
    
    results.forEach((result, index) => {
      const url = urls[index]
      
      if (result.status === 'fulfilled' && result.value.success) {
        reachable.push(url)
        console.log(` ${url} - reachable`)
      } else {
        unreachable.push(url)
        const error = result.status === 'fulfilled' 
          ? result.value.error?.message || 'Unknown error'
          : result.reason.message
        errors[url] = error
        console.log(` ${url} - ${error}`)
      }
    })
    
    return { reachable, unreachable, errors }
  }
}

async function demonstrateErrorHandling() {
  const authClient = new AuthFetchWithErrorHandling(undefined, true) // Debug mode on
  
  console.log('=== Testing error handling ===')
  
  // Test various scenarios
  const testUrls = [
    'https://httpbin.org/status/200',  // Should succeed
    'https://httpbin.org/status/401',  // Authentication error
    'https://httpbin.org/status/403',  // Certificate error
    'https://httpbin.org/status/500',  // Server error
    'https://invalid-domain-12345.com' // Network error
  ]
  
  for (const url of testUrls) {
    console.log(`\n--- Testing: ${url} ---`)
    const result = await authClient.safeRequest(url)
    
    if (result.success) {
      console.log(' Request successful')
    } else {
      console.log(` Request failed: ${result.error?.type} - ${result.error?.message}`)
    }
  }
  
  // Test connectivity to multiple endpoints
  console.log('\n=== Testing connectivity ===')
  const connectivityTest = await authClient.testConnectivity([
    'https://httpbin.org',
    'https://jsonplaceholder.typicode.com',
    'https://invalid-endpoint.example.com'
  ])
  
  console.log('Connectivity results:', connectivityTest)
  
  return connectivityTest
}

demonstrateErrorHandling().catch(console.error)
