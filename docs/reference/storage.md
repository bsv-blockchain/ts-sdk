# API

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

## Interfaces

| |
| --- |
| [DownloadResult](#interface-downloadresult) |
| [DownloaderConfig](#interface-downloaderconfig) |
| [EstimateCostResult](#interface-estimatecostresult) |
| [FindFileData](#interface-findfiledata) |
| [HostScopeOptions](#interface-hostscopeoptions) |
| [RenewFileResult](#interface-renewfileresult) |
| [RenewPerHostResult](#interface-renewperhostresult) |
| [UploadFileResult](#interface-uploadfileresult) |
| [UploadableFile](#interface-uploadablefile) |
| [UploaderConfig](#interface-uploaderconfig) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Interface: DownloadResult

```ts
export interface DownloadResult {
    data: Uint8Array;
    mimeType: string | null;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: DownloaderConfig

```ts
export interface DownloaderConfig {
    networkPreset: "mainnet" | "testnet" | "local";
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: EstimateCostResult

```ts
export interface EstimateCostResult {
    quotes: Array<{
        host: string;
        amount: number;
    }>;
    resilienceLevel: number;
    totalForResilience: number;
    meetsResilienceThreshold: boolean;
}
```

#### Property meetsResilienceThreshold

False when `publishFile` would throw without uploading.

```ts
meetsResilienceThreshold: boolean
```

#### Property quotes

Cheapest-first quotes from configured providers.

```ts
quotes: Array<{
    host: string;
    amount: number;
}>
```

#### Property totalForResilience

Sum of the cheapest `resilienceLevel` amounts (or all collected, if below threshold).

```ts
totalForResilience: number
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: FindFileData

```ts
export interface FindFileData {
    name: string;
    size: string;
    mimeType: string;
    expiryTime: number;
    hostedBy?: string[];
}
```

#### Property hostedBy

Providers that reported this UHRP URL. Omitted in single-host mode.

```ts
hostedBy?: string[]
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: HostScopeOptions

```ts
export interface HostScopeOptions {
    hostedBy?: string[];
}
```

#### Property hostedBy

Restrict the operation to this subset of configured providers.

```ts
hostedBy?: string[]
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RenewFileResult

```ts
export interface RenewFileResult {
    status: string;
    prevExpiryTime?: number;
    newExpiryTime?: number;
    amount?: number;
    results?: RenewPerHostResult[];
}
```

See also: [RenewPerHostResult](./storage.md#interface-renewperhostresult)

#### Property amount

Total satoshis paid across every host that renewed.

```ts
amount?: number
```

#### Property results

Per-host outcomes. Omitted in single-host mode.

```ts
results?: RenewPerHostResult[]
```
See also: [RenewPerHostResult](./storage.md#interface-renewperhostresult)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RenewPerHostResult

```ts
export interface RenewPerHostResult {
    host: string;
    status: "success" | "error";
    prevExpiryTime?: number;
    newExpiryTime?: number;
    amount?: number;
    error?: string;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: UploadFileResult

```ts
export interface UploadFileResult {
    published: boolean;
    uhrpURL: string;
    hostedBy: string[];
}
```

#### Property hostedBy

Providers that successfully hosted the file.

```ts
hostedBy: string[]
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: UploadableFile

```ts
export interface UploadableFile {
    data: Uint8Array | number[];
    type: string;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: UploaderConfig

```ts
export interface UploaderConfig {
    storageURL?: string;
    storageURLs?: string[];
    resilienceLevel?: number;
    wallet: WalletInterface;
}
```

See also: [WalletInterface](./wallet.md#interface-walletinterface)

#### Property resilienceLevel

Minimum replicas to store the file on. Defaults to 1.

```ts
resilienceLevel?: number
```

#### Property storageURL

Legacy single-host URL. Mutually exclusive with `storageURLs`.

```ts
storageURL?: string
```

#### Property storageURLs

Explicit provider list. Takes precedence over `storageURL`.

```ts
storageURLs?: string[]
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Classes

| |
| --- |
| [RenewResiliencyError](#class-renewresiliencyerror) |
| [StorageDownloader](#class-storagedownloader) |
| [StorageUploader](#class-storageuploader) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Class: RenewResiliencyError

Thrown by `renewFile` when successful renewals fall below the resilience
threshold. Per-host outcomes are attached so callers can reconcile which
providers were billed.

```ts
export class RenewResiliencyError extends Error {
    readonly results: RenewPerHostResult[];
    readonly requiredSuccesses: number;
    readonly successCount: number;
    constructor(message: string, results: RenewPerHostResult[], requiredSuccesses: number, successCount: number) 
}
```

See also: [RenewPerHostResult](./storage.md#interface-renewperhostresult)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: StorageDownloader

```ts
export class StorageDownloader {
    constructor(config?: DownloaderConfig) 
    public async resolve(uhrpUrl: string): Promise<string[]> 
    public async download(uhrpUrl: string): Promise<DownloadResult> 
}
```

See also: [DownloadResult](./storage.md#interface-downloadresult), [DownloaderConfig](./storage.md#interface-downloaderconfig)

#### Method download

Downloads the content from the UHRP URL after validating the hash for integrity.

```ts
public async download(uhrpUrl: string): Promise<DownloadResult> 
```
See also: [DownloadResult](./storage.md#interface-downloadresult)

Returns

A promise that resolves to the downloaded content.

Argument Details

+ **uhrpUrl**
  + The UHRP URL to download.

#### Method resolve

Resolves the UHRP URL to a list of HTTP URLs where content can be downloaded.

```ts
public async resolve(uhrpUrl: string): Promise<string[]> 
```

Returns

A promise that resolves to an array of HTTP URLs.

Argument Details

+ **uhrpUrl**
  + The UHRP URL to resolve.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: StorageUploader

Client for publishing, finding, listing, and renewing UHRP-hosted files
across one or more storage providers.

```ts
export class StorageUploader {
    constructor(config: UploaderConfig) 
    public async estimateCost(params: {
        fileSize: number;
        retentionPeriod: number;
    }): Promise<EstimateCostResult> 
    public async publishFile(params: {
        file: UploadableFile;
        retentionPeriod: number;
    }): Promise<UploadFileResult> 
    public async findFile(uhrpUrl: string, options: HostScopeOptions = {}): Promise<FindFileData> 
    public async listUploads(options: HostScopeOptions = {}): Promise<any> 
    public async renewFile(uhrpUrl: string, additionalMinutes: number, options: HostScopeOptions = {}): Promise<RenewFileResult> 
}
```

See also: [EstimateCostResult](./storage.md#interface-estimatecostresult), [FindFileData](./storage.md#interface-findfiledata), [HostScopeOptions](./storage.md#interface-hostscopeoptions), [RenewFileResult](./storage.md#interface-renewfileresult), [UploadFileResult](./storage.md#interface-uploadfileresult), [UploadableFile](./storage.md#interface-uploadablefile), [UploaderConfig](./storage.md#interface-uploaderconfig)

#### Method estimateCost

Queries the unauthenticated `/quote` endpoint on up to `2 * resilienceLevel`
providers and returns the cheapest-first quote list plus the aggregate
cost `publishFile` would pay. No provider is billed.

```ts
public async estimateCost(params: {
    fileSize: number;
    retentionPeriod: number;
}): Promise<EstimateCostResult> 
```
See also: [EstimateCostResult](./storage.md#interface-estimatecostresult)

#### Method findFile

Fans `/find` out across configured hosts (UHRP storage is host-local,
so any one host may not know the file) and returns the record with the
longest remaining expiry. Single-host configurations preserve the
legacy error-message contract verbatim.

```ts
public async findFile(uhrpUrl: string, options: HostScopeOptions = {}): Promise<FindFileData> 
```
See also: [FindFileData](./storage.md#interface-findfiledata), [HostScopeOptions](./storage.md#interface-hostscopeoptions)

#### Method listUploads

Unions `/list` output across configured hosts, merging duplicate UHRP
URLs by the longest expiry observed. One failing host does not hide
the rest. Single-host configurations preserve the legacy error contract.

```ts
public async listUploads(options: HostScopeOptions = {}): Promise<any> 
```
See also: [HostScopeOptions](./storage.md#interface-hostscopeoptions)

#### Method publishFile

Publishes a file across the cheapest configured providers, falling
through to the next-cheapest quote if a paid upload fails. Throws when
the resilience threshold cannot be met.

```ts
public async publishFile(params: {
    file: UploadableFile;
    retentionPeriod: number;
}): Promise<UploadFileResult> 
```
See also: [UploadFileResult](./storage.md#interface-uploadfileresult), [UploadableFile](./storage.md#interface-uploadablefile)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Functions

## Types

## Enums

## Variables

| |
| --- |
| [DEFAULT_UHRP_SERVERS](#variable-default_uhrp_servers) |
| [getHashFromURL](#variable-gethashfromurl) |
| [getURLForFile](#variable-geturlforfile) |
| [getURLForHash](#variable-geturlforhash) |
| [isValidURL](#variable-isvalidurl) |
| [normalizeURL](#variable-normalizeurl) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Variable: DEFAULT_UHRP_SERVERS

```ts
DEFAULT_UHRP_SERVERS: string[] = [
    "https://nanostore.babbage.systems",
    "https://bsv-storage-cloudflare.dev-a3e.workers.dev"
]
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: getHashFromURL

```ts
getHashFromURL = (URL: string): number[] => {
    URL = normalizeURL(URL);
    const { data, prefix } = fromBase58Check(URL, undefined, 2);
    if (data.length !== 32) {
        throw new Error("Invalid length!");
    }
    if (toHex(prefix as number[]) !== "ce00") {
        throw new Error("Bad prefix");
    }
    return data as number[];
}
```

See also: [fromBase58Check](./primitives.md#variable-frombase58check), [normalizeURL](./storage.md#variable-normalizeurl), [toHex](./primitives.md#variable-tohex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: getURLForFile

```ts
getURLForFile = (file: Uint8Array | number[]): string => {
    const data = file instanceof Uint8Array ? file : Uint8Array.from(file);
    const hasher = new Hash.SHA256();
    const chunkSize = 1024 * 1024;
    for (let i = 0; i < data.length; i += chunkSize) {
        const chunk = data.subarray(i, i + chunkSize);
        hasher.update(Array.from(chunk));
    }
    const hash = hasher.digest();
    return getURLForHash(hash);
}
```

See also: [SHA256](./primitives.md#class-sha256), [getURLForHash](./storage.md#variable-geturlforhash)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: getURLForHash

```ts
getURLForHash = (hash: number[]): string => {
    if (hash.length !== 32) {
        throw new Error("Hash length must be 32 bytes (sha256)");
    }
    return toBase58Check(hash, toArray("ce00", "hex"));
}
```

See also: [toArray](./primitives.md#variable-toarray), [toBase58Check](./primitives.md#variable-tobase58check)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: isValidURL

```ts
isValidURL = (URL: string): boolean => {
    try {
        getHashFromURL(URL);
        return true;
    }
    catch {
        return false;
    }
}
```

See also: [getHashFromURL](./storage.md#variable-gethashfromurl)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: normalizeURL

```ts
normalizeURL = (URL: string): string => {
    if (URL.toLowerCase().startsWith("uhrp:"))
        URL = URL.slice(5);
    if (URL.startsWith("//"))
        URL = URL.slice(2);
    return URL;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
