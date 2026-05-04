# API

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

## Interfaces

| |
| --- |
| [KVContext](#interface-kvcontext) |
| [KVStoreConfig](#interface-kvstoreconfig) |
| [KVStoreEntry](#interface-kvstoreentry) |
| [KVStoreGetOptions](#interface-kvstoregetoptions) |
| [KVStoreLookupResult](#interface-kvstorelookupresult) |
| [KVStoreQuery](#interface-kvstorequery) |
| [KVStoreRemoveOptions](#interface-kvstoreremoveoptions) |
| [KVStoreSetOptions](#interface-kvstoresetoptions) |
| [KVStoreToken](#interface-kvstoretoken) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Interface: KVContext

```ts
export interface KVContext {
    key: string;
    protocolID: WalletProtocol;
}
```

See also: [WalletProtocol](./wallet.md#type-walletprotocol)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: KVStoreConfig

Configuration interface for GlobalKVStore operations.
Defines all options for connecting to overlay services and managing KVStore behavior.

```ts
export interface KVStoreConfig {
    overlayHost?: string;
    protocolID?: WalletProtocol;
    serviceName?: string;
    tokenAmount?: number;
    topics?: string[];
    originator?: string;
    wallet?: WalletInterface;
    networkPreset?: "mainnet" | "testnet" | "local";
    acceptDelayedBroadcast?: boolean;
    overlayBroadcast?: boolean;
    tokenSetDescription?: string;
    tokenUpdateDescription?: string;
    tokenRemovalDescription?: string;
}
```

See also: [WalletInterface](./wallet.md#interface-walletinterface), [WalletProtocol](./wallet.md#type-walletprotocol)

#### Property acceptDelayedBroadcast

Whether to accept delayed broadcast

```ts
acceptDelayedBroadcast?: boolean
```

#### Property networkPreset

Network preset for overlay services

```ts
networkPreset?: "mainnet" | "testnet" | "local"
```

#### Property originator

Originator

```ts
originator?: string
```

#### Property overlayBroadcast

Whether to let overlay handle broadcasting (prevents UTXO spending on rejection)

```ts
overlayBroadcast?: boolean
```

#### Property overlayHost

The overlay service host URL

```ts
overlayHost?: string
```

#### Property protocolID

Protocol ID for the KVStore protocol

```ts
protocolID?: WalletProtocol
```
See also: [WalletProtocol](./wallet.md#type-walletprotocol)

#### Property serviceName

Service name for overlay submission

```ts
serviceName?: string
```

#### Property tokenAmount

Amount of satoshis for each token

```ts
tokenAmount?: number
```

#### Property tokenRemovalDescription

Description for token removal

```ts
tokenRemovalDescription?: string
```

#### Property tokenSetDescription

Description for token set

```ts
tokenSetDescription?: string
```

#### Property tokenUpdateDescription

Description for token update

```ts
tokenUpdateDescription?: string
```

#### Property topics

Topics for overlay submission

```ts
topics?: string[]
```

#### Property wallet

Wallet interface for operations

```ts
wallet?: WalletInterface
```
See also: [WalletInterface](./wallet.md#interface-walletinterface)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: KVStoreEntry

KVStore entry returned from queries

```ts
export interface KVStoreEntry {
    key: string;
    value: string;
    controller: PubKeyHex;
    protocolID: WalletProtocol;
    tags?: string[];
    token?: KVStoreToken;
    history?: string[];
}
```

See also: [KVStoreToken](./kvstore.md#interface-kvstoretoken), [PubKeyHex](./wallet.md#type-pubkeyhex), [WalletProtocol](./wallet.md#type-walletprotocol)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: KVStoreGetOptions

Options for configuring KVStore get operations (local processing)

```ts
export interface KVStoreGetOptions {
    history?: boolean;
    includeToken?: boolean;
    serviceName?: string;
}
```

#### Property history

Whether to build and include history for each entry

```ts
history?: boolean
```

#### Property includeToken

Whether to include token transaction data in results

```ts
includeToken?: boolean
```

#### Property serviceName

Service name for overlay retrieval

```ts
serviceName?: string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: KVStoreLookupResult

Result structure for KVStore lookups from overlay services.
Contains the transaction output information for a found key-value pair.

```ts
export interface KVStoreLookupResult {
    txid: string;
    outputIndex: number;
    outputScript: string;
    satoshis: number;
    history?: (output: any, currentDepth: number) => Promise<boolean>;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: KVStoreQuery

Query parameters for KVStore lookups from overlay services.
Must include at least one selector: key, controller, protocolID, or non-empty tags.
Pagination and ordering fields only refine selector-based lookups.

```ts
export interface KVStoreQuery {
    key?: string;
    controller?: PubKeyHex;
    protocolID?: WalletProtocol;
    tags?: string[];
    tagQueryMode?: "all" | "any";
    limit?: number;
    skip?: number;
    sortOrder?: "asc" | "desc";
}
```

See also: [PubKeyHex](./wallet.md#type-pubkeyhex), [WalletProtocol](./wallet.md#type-walletprotocol)

#### Property tagQueryMode

Controls tag matching behavior when tags are specified.
- 'all': Requires all specified tags to be present (default)
- 'any': Requires at least one of the specified tags to be present

```ts
tagQueryMode?: "all" | "any"
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: KVStoreRemoveOptions

```ts
export interface KVStoreRemoveOptions {
    protocolID?: WalletProtocol;
    tokenRemovalDescription?: string;
}
```

See also: [WalletProtocol](./wallet.md#type-walletprotocol)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: KVStoreSetOptions

```ts
export interface KVStoreSetOptions {
    protocolID?: WalletProtocol;
    tokenSetDescription?: string;
    tokenUpdateDescription?: string;
    tokenAmount?: number;
    tags?: string[];
}
```

See also: [WalletProtocol](./wallet.md#type-walletprotocol)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: KVStoreToken

Token structure containing a KVStore token from overlay services.
Wraps the transaction data and metadata for a key-value pair.

```ts
export interface KVStoreToken {
    txid: string;
    outputIndex: number;
    satoshis: number;
    beef: Beef;
}
```

See also: [Beef](./transaction.md#class-beef)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Classes

| |
| --- |
| [GlobalKVStore](#class-globalkvstore) |
| [LocalKVStore](#class-localkvstore) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Class: GlobalKVStore

Implements a global key-value storage system which uses an overlay service to track key-value pairs.
Each key-value pair is represented by a PushDrop token output.
Allows getting, setting, and removing key-value pairs with optional fetching by protocolID and history tracking.

```ts
export class GlobalKVStore {
    constructor(config: KVStoreConfig = {}) 
    async get(query: KVStoreQuery, options: KVStoreGetOptions = {}): Promise<KVStoreEntry | KVStoreEntry[] | undefined> 
    async set(key: string, value: string, options: KVStoreSetOptions = {}): Promise<OutpointString> 
    async remove(key: string, outputs?: CreateActionOutput[], options: KVStoreRemoveOptions = {}): Promise<HexString> 
}
```

See also: [CreateActionOutput](./wallet.md#interface-createactionoutput), [HexString](./wallet.md#type-hexstring), [KVStoreConfig](./kvstore.md#interface-kvstoreconfig), [KVStoreEntry](./kvstore.md#interface-kvstoreentry), [KVStoreGetOptions](./kvstore.md#interface-kvstoregetoptions), [KVStoreQuery](./kvstore.md#interface-kvstorequery), [KVStoreRemoveOptions](./kvstore.md#interface-kvstoreremoveoptions), [KVStoreSetOptions](./kvstore.md#interface-kvstoresetoptions), [OutpointString](./wallet.md#type-outpointstring)

#### Constructor

Creates an instance of the GlobalKVStore.

```ts
constructor(config: KVStoreConfig = {}) 
```
See also: [KVStoreConfig](./kvstore.md#interface-kvstoreconfig)

Argument Details

+ **config**
  + Configuration options for the KVStore. Defaults to empty object.
+ **config.wallet**
  + Wallet to use for operations. Defaults to WalletClient.

Throws

If the configuration contains invalid parameters.

#### Method get

Retrieves data from the KVStore.
Can query by key+controller (single result), protocolID, controller, or key (multiple results).

```ts
async get(query: KVStoreQuery, options: KVStoreGetOptions = {}): Promise<KVStoreEntry | KVStoreEntry[] | undefined> 
```
See also: [KVStoreEntry](./kvstore.md#interface-kvstoreentry), [KVStoreGetOptions](./kvstore.md#interface-kvstoregetoptions), [KVStoreQuery](./kvstore.md#interface-kvstorequery)

Returns

Single entry for key+controller queries, array for all other queries

Argument Details

+ **query**
  + Query parameters sent to overlay
+ **options**
  + Configuration options for the get operation

#### Method remove

Removes the key-value pair associated with the given key from the overlay service.

```ts
async remove(key: string, outputs?: CreateActionOutput[], options: KVStoreRemoveOptions = {}): Promise<HexString> 
```
See also: [CreateActionOutput](./wallet.md#interface-createactionoutput), [HexString](./wallet.md#type-hexstring), [KVStoreRemoveOptions](./kvstore.md#interface-kvstoreremoveoptions)

Returns

A promise that resolves to the txid of the removal transaction if successful.

Argument Details

+ **key**
  + The key to remove.
+ **outputs**
  + Additional outputs to include in the removal transaction.
+ **options**
  + Optional parameters for the removal operation.

Throws

If the key is invalid.

If the key does not exist in the store.

If the overlay service is unreachable or the transaction fails.

If there are existing tokens that cannot be unlocked.

#### Method set

Sets a key-value pair. The current user (wallet identity) becomes the controller.

```ts
async set(key: string, value: string, options: KVStoreSetOptions = {}): Promise<OutpointString> 
```
See also: [KVStoreSetOptions](./kvstore.md#interface-kvstoresetoptions), [OutpointString](./wallet.md#type-outpointstring)

Returns

The outpoint of the created token

Argument Details

+ **key**
  + The key to set (user computes this however they want)
+ **value**
  + The value to store
+ **options**
  + Configuration options for the set operation

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: LocalKVStore

Implements a key-value storage system backed by transaction outputs managed by a wallet.
Each key-value pair is represented by a PushDrop token output in a specific context (basket).
Allows setting, getting, and removing key-value pairs, with optional encryption.

```ts
export default class LocalKVStore {
    acceptDelayedBroadcast: boolean = false;
    constructor(wallet: WalletInterface = new WalletClient(), context = "kvstore default", encrypt = true, originator?: string, acceptDelayedBroadcast = false) 
    async get(key: string, defaultValue: string | undefined = undefined): Promise<string | undefined> 
    async set(key: string, value: string): Promise<OutpointString> 
    async remove(key: string): Promise<string[]> 
}
```

See also: [OutpointString](./wallet.md#type-outpointstring), [WalletClient](./wallet.md#class-walletclient), [WalletInterface](./wallet.md#interface-walletinterface), [encrypt](./messages.md#variable-encrypt)

#### Constructor

Creates an instance of the localKVStore.

```ts
constructor(wallet: WalletInterface = new WalletClient(), context = "kvstore default", encrypt = true, originator?: string, acceptDelayedBroadcast = false) 
```
See also: [WalletClient](./wallet.md#class-walletclient), [WalletInterface](./wallet.md#interface-walletinterface), [encrypt](./messages.md#variable-encrypt)

Argument Details

+ **wallet**
  + The wallet interface to use. Defaults to a new WalletClient instance.
+ **context**
  + The context (basket) for namespacing keys. Defaults to 'kvstore default'.
+ **encrypt**
  + Whether to encrypt values. Defaults to true.
+ **originator**
  + — An originator to use with PushDrop and the wallet, if provided.

Throws

If the context is missing or empty.

#### Method get

Retrieves the value associated with a given key.

```ts
async get(key: string, defaultValue: string | undefined = undefined): Promise<string | undefined> 
```

Returns

A promise that resolves to the value as a string,
the defaultValue if the key is not found, or undefined if no defaultValue is provided.

Argument Details

+ **key**
  + The key to retrieve the value for.
+ **defaultValue**
  + The value to return if the key is not found.

Throws

If too many outputs are found for the key (ambiguous state).

If the found output's locking script cannot be decoded or represents an invalid token format.

#### Method remove

Removes the key-value pair associated with the given key.
It finds the existing output(s) for the key and spends them without creating a new output.
If multiple outputs exist, they are all spent in the same transaction.
If the key does not exist, it does nothing.
If signing the removal transaction fails, it relinquishes the original outputs instead of spending.

```ts
async remove(key: string): Promise<string[]> 
```

Returns

A promise that resolves to the txids of the removal transactions if successful.

Argument Details

+ **key**
  + The key to remove.

#### Method set

Sets or updates the value associated with a given key atomically.
If the key already exists (one or more outputs found), it spends the existing output(s)
and creates a new one with the updated value. If multiple outputs exist for the key,
they are collapsed into a single new output.
If the key does not exist, it creates a new output.
Handles encryption if enabled.
If signing the update/collapse transaction fails, it relinquishes the original outputs and starts over with a new chain.
Ensures atomicity by locking the key during the operation, preventing concurrent updates
to the same key from missing earlier changes.

```ts
async set(key: string, value: string): Promise<OutpointString> 
```
See also: [OutpointString](./wallet.md#type-outpointstring)

Returns

A promise that resolves to the outpoint string (txid.vout) of the new or updated token output.

Argument Details

+ **key**
  + The key to set or update.
+ **value**
  + The value to associate with the key.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Functions

## Types

## Enums

## Variables

| |
| --- |
| [kvProtocol](#variable-kvprotocol) |
| [kvStoreInterpreter](#variable-kvstoreinterpreter) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Variable: kvProtocol

```ts
kvProtocol = {
    protocolID: 0,
    key: 1,
    value: 2,
    controller: 3,
    tags: 4,
    signature: 5
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: kvStoreInterpreter

```ts
kvStoreInterpreter: InterpreterFunction<string, KVContext> = async (transaction: Transaction, outputIndex: number, ctx?: KVContext): Promise<string | undefined> => {
    try {
        const output = transaction.outputs[outputIndex];
        if (output == null || output.lockingScript == null)
            return undefined;
        if (ctx == null || ctx.key == null)
            return undefined;
        const decoded = PushDrop.decode(output.lockingScript);
        const expectedFieldCount = Object.keys(kvProtocol).length;
        const hasTagsField = decoded.fields.length === expectedFieldCount;
        const isOldFormat = decoded.fields.length === expectedFieldCount - 1;
        if (!isOldFormat && !hasTagsField)
            return undefined;
        const key = Utils.toUTF8(decoded.fields[kvProtocol.key]);
        const protocolID = Utils.toUTF8(decoded.fields[kvProtocol.protocolID]);
        if (key !== ctx.key || protocolID !== JSON.stringify(ctx.protocolID))
            return undefined;
        try {
            return Utils.toUTF8(decoded.fields[kvProtocol.value]);
        }
        catch {
            return undefined;
        }
    }
    catch {
        return undefined;
    }
}
```

See also: [KVContext](./kvstore.md#interface-kvcontext), [PushDrop](./script.md#class-pushdrop), [Transaction](./transaction.md#class-transaction), [kvProtocol](./kvstore.md#variable-kvprotocol), [toUTF8](./primitives.md#variable-toutf8)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
