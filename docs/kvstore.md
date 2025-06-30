# API

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

## Interfaces

## Classes

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

