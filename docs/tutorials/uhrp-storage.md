# Decentralized File Storage with UHRP

**Duration**: 75 minutes  
**Prerequisites**: Node.js, basic TypeScript knowledge, understanding of decentralized storage and `WalletClient` usage  
**Learning Goals**:
- Understand UHRP (Universal Hash Resource Protocol)
- Upload and download files using StorageUploader/StorageDownloader
- Implement decentralized file management systems
- Handle file integrity verification and expiration

## Introduction

UHRP (Universal Hash Resource Protocol) is a decentralized file storage system that uses content hashing for addressing and retrieval. The BSV SDK provides `StorageUploader` and `StorageDownloader` classes for seamless integration with UHRP storage networks.

## Prerequisites

### For Upload Operations
- **BRC-100 compliant wallet** (such as Metanet Desktop Wallet) must be installed and running
- **Wallet connection** accessible via JSON API (typically http://localhost:3321)
- **Sufficient wallet balance** for transaction fees and storage costs
- **UHRP storage service** - This tutorial uses `https://nanostore.babbage.systems`

### For Download Operations Only
- **No wallet connection required** - downloads work independently
- **Network access** to resolve UHRP URLs via lookup services

### Service Availability
**Important Note**: This tutorial uses `https://nanostore.babbage.systems`, which is a working UHRP storage service. The examples demonstrate correct SDK usage patterns and will work with:
- A running BRC-100 compliant wallet (such as Metanet Desktop Wallet)
- Sufficient wallet balance for storage fees

**Performance Note**: UHRP storage operations may take time to complete as they involve blockchain transactions and network propagation. Upload operations can take 10-30 seconds or more depending on network conditions.

**Network Propagation**: After uploading, files typically take 30-60 seconds to propagate across the UHRP network before they become available for download. This is normal behavior for decentralized storage systems and ensures content integrity verification.

## Key Features

- **Content-Addressed Storage**: Files identified by their hash
- **Decentralized Retrieval**: Multiple storage providers
- **Integrity Verification**: Automatic hash validation
- **Expiration Management**: Time-based file retention
- **Authenticated Upload**: Wallet-based authentication

## What You'll Build

- File upload system with UHRP
- Decentralized file retrieval
- File management dashboard
- Integrity verification system

## Setting Up UHRP Storage

### Basic File Upload

```typescript
import { StorageUploader, WalletClient } from '@bsv/sdk'

async function basicFileUpload() {
  const wallet = new WalletClient('auto', 'localhost')
  
  const uploader = new StorageUploader({
    storageURL: 'https://nanostore.babbage.systems',
    wallet
  })
  
  // Create sample file
  const fileData = new TextEncoder().encode('Hello, UHRP storage!')
  const file = {
    data: Array.from(fileData),
    type: 'text/plain'
  }
  
  try {
    const result = await uploader.publishFile({
      file,
      retentionPeriod: 60 * 24 * 7 // 7 days in minutes
    })
    
    console.log('File uploaded successfully!')
    console.log('UHRP URL:', result.uhrpURL)
    console.log('Published:', result.published)
    
    return result
  } catch (error) {
    console.error('Upload failed:', error)
    throw error
  }
}

basicFileUpload().catch(console.error)
```

### File Download and Verification

```typescript
import { StorageDownloader } from '@bsv/sdk'

async function basicFileDownload(uhrpUrl: string) {
  const downloader = new StorageDownloader({
    networkPreset: 'mainnet'
  })
  
  try {
    console.log('Downloading file:', uhrpUrl)
    
    const result = await downloader.download(uhrpUrl)
    
    console.log('File downloaded successfully!')
    console.log('MIME Type:', result.mimeType)
    console.log('Content length:', result.data.length, 'bytes')
    
    // Convert to string if text file
    if (result.mimeType?.startsWith('text/')) {
      const content = new TextDecoder().decode(new Uint8Array(result.data))
      console.log('Content:', content)
    }
    
    return result
  } catch (error) {
    console.error('Download failed:', error)
    throw error
  }
}

// Example usage (replace with actual UHRP URL)
// basicFileDownload('uhrp://abc123...').catch(console.error)
```

## Complete File Management System

### File Manager Class

```typescript
import { StorageUploader, StorageDownloader, WalletClient } from '@bsv/sdk'

interface FileMetadata {
  uhrpUrl: string
  originalName: string
  mimeType: string
  size: number
  uploadDate: Date
  expiryDate: Date
  tags: string[]
}

class UHRPFileManager {
  private uploader: StorageUploader
  private downloader: StorageDownloader
  private fileRegistry: Map<string, FileMetadata> = new Map()
  
  constructor(storageURL: string, wallet?: WalletClient) {
    this.uploader = new StorageUploader({
      storageURL,
      wallet: wallet || new WalletClient('auto', 'localhost')
    })
    
    this.downloader = new StorageDownloader({
      networkPreset: 'mainnet'
    })
  }
  
  async uploadFile(
    fileData: Uint8Array,
    fileName: string,
    mimeType: string,
    retentionDays: number = 30,
    tags: string[] = []
  ): Promise<FileMetadata> {
    const file = {
      data: Array.from(fileData),
      type: mimeType
    }
    
    const retentionMinutes = retentionDays * 24 * 60
    
    try {
      const result = await this.uploader.publishFile({
        file,
        retentionPeriod: retentionMinutes
      })
      
      const metadata: FileMetadata = {
        uhrpUrl: result.uhrpURL,
        originalName: fileName,
        mimeType,
        size: fileData.length,
        uploadDate: new Date(),
        expiryDate: new Date(Date.now() + retentionDays * 24 * 60 * 60 * 1000),
        tags
      }
      
      this.fileRegistry.set(result.uhrpURL, metadata)
      
      console.log(`File "${fileName}" uploaded successfully`)
      console.log('UHRP URL:', result.uhrpURL)
      
      return metadata
    } catch (error) {
      console.error(`Failed to upload "${fileName}":`, error)
      throw error
    }
  }
  
  async downloadFile(uhrpUrl: string): Promise<{
    data: Uint8Array
    metadata: FileMetadata | null
  }> {
    try {
      const result = await this.downloader.download(uhrpUrl)
      const metadata = this.fileRegistry.get(uhrpUrl) || null
      
      console.log('File downloaded:', uhrpUrl)
      
      return {
        data: new Uint8Array(result.data),
        metadata
      }
    } catch (error) {
      console.error('Download failed:', error)
      throw error
    }
  }
  
  async getFileInfo(uhrpUrl: string): Promise<any> {
    try {
      return await this.uploader.findFile(uhrpUrl)
    } catch (error) {
      console.error('Failed to get file info:', error)
      throw error
    }
  }
  
  async renewFile(uhrpUrl: string, additionalDays: number): Promise<any> {
    const additionalMinutes = additionalDays * 24 * 60
    
    try {
      const result = await this.uploader.renewFile(uhrpUrl, additionalMinutes)
      
      // Update local metadata if exists
      const metadata = this.fileRegistry.get(uhrpUrl)
      if (metadata) {
        metadata.expiryDate = new Date(Date.now() + additionalDays * 24 * 60 * 60 * 1000)
        this.fileRegistry.set(uhrpUrl, metadata)
      }
      
      console.log(`File renewed for ${additionalDays} days`)
      return result
    } catch (error) {
      console.error('Failed to renew file:', error)
      throw error
    }
  }
  
  listFiles(tag?: string): FileMetadata[] {
    const files = Array.from(this.fileRegistry.values())
    
    if (tag) {
      return files.filter(file => file.tags.includes(tag))
    }
    
    return files
  }
  
  getExpiringFiles(daysAhead: number = 7): FileMetadata[] {
    const cutoffDate = new Date(Date.now() + daysAhead * 24 * 60 * 60 * 1000)
    
    return Array.from(this.fileRegistry.values())
      .filter(file => file.expiryDate <= cutoffDate)
      .sort((a, b) => a.expiryDate.getTime() - b.expiryDate.getTime())
  }
}

async function demonstrateFileManager() {
  const fileManager = new UHRPFileManager('https://nanostore.babbage.systems')
  
  console.log('=== UHRP File Manager Demo ===')
  
  // Upload different types of files
  const textData = new TextEncoder().encode('This is a text document for UHRP storage.')
  const jsonData = new TextEncoder().encode(JSON.stringify({
    message: 'Hello from UHRP',
    timestamp: new Date().toISOString(),
    data: [1, 2, 3, 4, 5]
  }))
  
  try {
    // Upload text file
    const textFile = await fileManager.uploadFile(
      textData,
      'document.txt',
      'text/plain',
      30,
      ['document', 'text']
    )
    
    // Upload JSON file
    const jsonFile = await fileManager.uploadFile(
      jsonData,
      'data.json',
      'application/json',
      60,
      ['data', 'json']
    )
    
    console.log('\n=== File Registry ===')
    const allFiles = fileManager.listFiles()
    allFiles.forEach(file => {
      console.log(`${file.originalName}: ${file.uhrpUrl}`)
    })
    
    // Test download
    console.log('\n=== Testing Download ===')
    const downloadResult = await fileManager.downloadFile(textFile.uhrpUrl)
    const content = new TextDecoder().decode(downloadResult.data)
    console.log('Downloaded content:', content)
    
    // Check expiring files
    console.log('\n=== Expiring Files ===')
    const expiringFiles = fileManager.getExpiringFiles(365) // Next year
    expiringFiles.forEach(file => {
      console.log(`${file.originalName} expires: ${file.expiryDate.toISOString()}`)
    })
    
    return { textFile, jsonFile, allFiles }
  } catch (error) {
    console.error('Demo failed:', error)
  }
}

demonstrateFileManager().catch(console.error)

## Advanced Features

### Batch Operations

```typescript
import { StorageUploader, StorageDownloader, WalletClient } from '@bsv/sdk'

class BatchFileOperations {
  private uploader: StorageUploader
  private downloader: StorageDownloader
  
  constructor(storageURL: string, wallet?: WalletClient) {
    this.uploader = new StorageUploader({
      storageURL,
      wallet: wallet || new WalletClient('auto', 'localhost')
    })
    
    this.downloader = new StorageDownloader()
  }
  
  async batchUpload(files: Array<{
    data: Uint8Array
    name: string
    type: string
    retention?: number
  }>): Promise<Array<{
    success: boolean
    file: string
    uhrpUrl?: string
    error?: string
  }>> {
    console.log(`Starting batch upload of ${files.length} files...`)
    
    const results = await Promise.allSettled(
      files.map(async (file) => {
        const fileObj = {
          data: Array.from(file.data),
          type: file.type
        }
        
        const result = await this.uploader.publishFile({
          file: fileObj,
          retentionPeriod: (file.retention || 30) * 24 * 60
        })
        
        return { file: file.name, result }
      })
    )
    
    return results.map((result, index) => {
      const fileName = files[index].name
      
      if (result.status === 'fulfilled') {
        return {
          success: true,
          file: fileName,
          uhrpUrl: result.value.result.uhrpURL
        }
      } else {
        return {
          success: false,
          file: fileName,
          error: result.reason.message
        }
      }
    })
  }
  
  async batchDownload(uhrpUrls: string[]): Promise<Array<{
    success: boolean
    url: string
    data?: Uint8Array
    error?: string
  }>> {
    console.log(`Starting batch download of ${uhrpUrls.length} files...`)
    
    const results = await Promise.allSettled(
      uhrpUrls.map(url => this.downloader.download(url))
    )
    
    return results.map((result, index) => {
      const url = uhrpUrls[index]
      
      if (result.status === 'fulfilled') {
        return {
          success: true,
          url,
          data: new Uint8Array(result.value.data)
        }
      } else {
        return {
          success: false,
          url,
          error: result.reason.message
        }
      }
    })
  }
}

async function demonstrateBatchOperations() {
  const batchOps = new BatchFileOperations('https://nanostore.babbage.systems')
  
  // Prepare test files
  const testFiles = [
    {
      data: new TextEncoder().encode('File 1 content'),
      name: 'file1.txt',
      type: 'text/plain'
    },
    {
      data: new TextEncoder().encode('File 2 content'),
      name: 'file2.txt',
      type: 'text/plain'
    },
    {
      data: new TextEncoder().encode(JSON.stringify({ test: 'data' })),
      name: 'data.json',
      type: 'application/json'
    }
  ]
  
  console.log('=== Batch Upload Demo ===')
  const uploadResults = await batchOps.batchUpload(testFiles)
  
  uploadResults.forEach(result => {
    if (result.success) {
      console.log(`✅ ${result.file}: ${result.uhrpUrl}`)
    } else {
      console.log(`❌ ${result.file}: ${result.error}`)
    }
  })
  
  // Extract successful URLs for download test
  const successfulUrls = uploadResults
    .filter(r => r.success && r.uhrpUrl)
    .map(r => r.uhrpUrl!)
  
  if (successfulUrls.length > 0) {
    console.log('\n=== Batch Download Demo ===')
    const downloadResults = await batchOps.batchDownload(successfulUrls)
    
    downloadResults.forEach(result => {
      if (result.success) {
        console.log(`✅ Downloaded: ${result.url} (${result.data?.length} bytes)`)
      } else {
        console.log(`❌ Failed: ${result.url} - ${result.error}`)
      }
    })
  }
  
  return { uploadResults, downloadResults: [] }
}

demonstrateBatchOperations().catch(console.error)

## Troubleshooting

### Common Issues and Solutions

#### "No wallet available" Error
**Problem**: StorageUploader fails with "No wallet available over any communication substrate"
**Solution**: 
- Install and run a BRC-100 compliant wallet (e.g., Metanet Desktop Wallet)
- Ensure wallet is accessible at http://localhost:3321
- Verify wallet is fully synced and has sufficient balance

#### "401 Unauthorized" Error
**Problem**: Upload operations fail with HTTP 401 errors
**Solution**:
- Verify your wallet is properly authenticated
- Check that the UHRP storage service is available
- Ensure your wallet has sufficient balance for storage fees

#### "Invalid parameter UHRP url" Error
**Problem**: Download operations fail with invalid URL error
**Solution**:
- Verify the UHRP URL format (should start with `uhrp://`)
- Check that the file hasn’t expired
- Ensure network connectivity for UHRP lookup services

#### Download Works but Upload Fails
**Problem**: StorageDownloader works but StorageUploader fails
**Solution**: This is expected behavior without a wallet connection. StorageDownloader works independently, while StorageUploader requires wallet authentication.

#### Service Unavailable
**Problem**: UHRP storage service returns errors or is unreachable
**Solution**:
- Try alternative UHRP storage services
- Check service status and availability
- Consider setting up your own UHRP storage infrastructure

## Best Practices

### 1. File Management
- Use meaningful file names and metadata
- Implement proper retention policies
- Tag files for easy organization and retrieval

### 2. Error Handling
- Always validate file integrity after download
- Implement retry logic for network failures
- Handle storage quota and payment requirements

### 3. Performance
- Use batch operations for multiple files
- Implement caching for frequently accessed files
- Monitor file expiration and renewal needs

### 4. Security
- Encrypt sensitive files before upload
- Use authenticated storage endpoints
- Validate file types and sizes

## Summary

In this tutorial, you learned how to:

✅ **Upload files to UHRP storage** with StorageUploader  
✅ **Download and verify files** with StorageDownloader  
✅ **Build file management systems** with metadata tracking  
✅ **Implement batch operations** for multiple files  
✅ **Handle file expiration** and renewal  

UHRP provides a robust foundation for decentralized file storage with content addressing and integrity verification.

## Next Steps

- Learn about [Identity Management and Certificates](./identity-management.md)
- Explore [AuthFetch for Authenticated HTTP Requests](./authfetch-tutorial.md)
- Review [Security Best Practices](../guides/security-best-practices.md)

UHRP provides a robust foundation for decentralized file storage with content addressing and integrity verification.

The `WalletClient` provides the authentication and payment capabilities needed for UHRP operations.

## Setting Up UHRP with `WalletClient`

The `WalletClient` handles authentication automatically when you create `StorageUploader` and `StorageDownloader` instances.

### How `WalletClient` Enables UHRP

When you use UHRP with `WalletClient`:

- You can upload files to decentralized storage networks.
- You can download files from decentralized storage networks.
- You can manage file metadata and track file expiration.
- You can implement batch operations for multiple files.
