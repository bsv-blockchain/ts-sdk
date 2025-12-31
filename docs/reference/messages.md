# API

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Variables](#variables)

## Interfaces

## Classes

## Functions

## Variables

| |
| --- |
| [decrypt](#variable-decrypt) |
| [encrypt](#variable-encrypt) |
| [sign](#variable-sign) |
| [verify](#variable-verify) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Variables](#variables)

---

### Variable: decrypt

```ts
decrypt = (message: number[], recipient: PrivateKey): number[] => {
    const reader = new Reader(message);
    const messageVersion = toHex(reader.read(4));
    if (messageVersion !== VERSION) {
        throw new Error(`Message version mismatch: Expected ${VERSION}, received ${messageVersion}`);
    }
    const sender = PublicKey.fromString(toHex(reader.read(33)));
    const expectedRecipientDER = toHex(reader.read(33));
    const actualRecipientDER = recipient
        .toPublicKey()
        .encode(true, "hex") as string;
    if (expectedRecipientDER !== actualRecipientDER) {
        throw new Error(`The encrypted message expects a recipient public key of ${expectedRecipientDER}, but the provided key is ${actualRecipientDER}`);
    }
    const keyID = toBase64(reader.read(32));
    const encrypted = reader.read(reader.bin.length - reader.pos);
    const invoiceNumber = `2-message encryption-${keyID}`;
    const signingPriv = sender.deriveChild(recipient, invoiceNumber);
    const recipientPub = recipient.deriveChild(sender, invoiceNumber);
    const sharedSecret = signingPriv.deriveSharedSecret(recipientPub);
    const symmetricKey = new SymmetricKey(sharedSecret.encode(true).slice(1));
    return symmetricKey.decrypt(encrypted) as number[];
}
```

See also: [PrivateKey](./primitives.md#class-privatekey), [PublicKey](./primitives.md#class-publickey), [Reader](./primitives.md#class-reader), [SymmetricKey](./primitives.md#class-symmetrickey), [encode](./primitives.md#variable-encode), [toBase64](./primitives.md#function-tobase64), [toHex](./primitives.md#variable-tohex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Variables](#variables)

---
### Variable: encrypt

```ts
encrypt = (message: number[], sender: PrivateKey, recipient: PublicKey): number[] => {
    const keyID = Random(32);
    const keyIDBase64 = toBase64(keyID);
    const invoiceNumber = `2-message encryption-${keyIDBase64}`;
    const signingPriv = sender.deriveChild(recipient, invoiceNumber);
    const recipientPub = recipient.deriveChild(sender, invoiceNumber);
    const sharedSecret = signingPriv.deriveSharedSecret(recipientPub);
    const symmetricKey = new SymmetricKey(sharedSecret.encode(true).slice(1));
    const encrypted = symmetricKey.encrypt(message) as number[];
    const senderPublicKey = sender.toPublicKey().encode(true);
    const version = toArray(VERSION, "hex");
    return [
        ...version,
        ...senderPublicKey,
        ...recipient.encode(true),
        ...keyID,
        ...encrypted
    ];
}
```

See also: [PrivateKey](./primitives.md#class-privatekey), [PublicKey](./primitives.md#class-publickey), [SymmetricKey](./primitives.md#class-symmetrickey), [encode](./primitives.md#variable-encode), [toArray](./primitives.md#variable-toarray), [toBase64](./primitives.md#function-tobase64)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Variables](#variables)

---
### Variable: sign

```ts
sign = (message: number[], signer: PrivateKey, verifier?: PublicKey): number[] => {
    const recipientAnyone = typeof verifier !== "object";
    if (recipientAnyone) {
        const curve = new Curve();
        const anyone = new PrivateKey(1);
        const anyonePoint = curve.g.mul(anyone);
        verifier = new PublicKey(anyonePoint.x, anyonePoint.y);
    }
    const keyID = Random(32);
    const keyIDBase64 = toBase64(keyID);
    const invoiceNumber = `2-message signing-${keyIDBase64}`;
    const signingKey = signer.deriveChild(verifier, invoiceNumber);
    const signature = signingKey.sign(message).toDER();
    const senderPublicKey = signer.toPublicKey().encode(true);
    const version = toArray(VERSION, "hex");
    return [
        ...version,
        ...senderPublicKey,
        ...(recipientAnyone ? [0] : verifier.encode(true)),
        ...keyID,
        ...signature
    ];
}
```

See also: [Curve](./primitives.md#class-curve), [PrivateKey](./primitives.md#class-privatekey), [PublicKey](./primitives.md#class-publickey), [encode](./primitives.md#variable-encode), [toArray](./primitives.md#variable-toarray), [toBase64](./primitives.md#function-tobase64)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Variables](#variables)

---
### Variable: verify

```ts
verify = (message: number[], sig: number[], recipient?: PrivateKey): boolean => {
    const reader = new Reader(sig);
    const messageVersion = toHex(reader.read(4));
    if (messageVersion !== VERSION) {
        throw new Error(`Message version mismatch: Expected ${VERSION}, received ${messageVersion}`);
    }
    const signer = PublicKey.fromString(toHex(reader.read(33)));
    const [verifierFirst] = reader.read(1);
    if (verifierFirst === 0) {
        recipient = new PrivateKey(1);
    }
    else {
        const verifierRest = reader.read(32);
        const verifierDER = toHex([verifierFirst, ...verifierRest]);
        if (typeof recipient !== "object") {
            throw new Error(`This signature can only be verified with knowledge of a specific private key. The associated public key is: ${verifierDER}`);
        }
        const recipientDER = recipient.toPublicKey().encode(true, "hex") as string;
        if (verifierDER !== recipientDER) {
            throw new Error(`The recipient public key is ${recipientDER} but the signature requres the recipient to have public key ${verifierDER}`);
        }
    }
    const keyID = toBase64(reader.read(32));
    const signatureDER = toHex(reader.read(reader.bin.length - reader.pos));
    const signature = Signature.fromDER(signatureDER, "hex");
    const invoiceNumber = `2-message signing-${keyID}`;
    const signingKey = signer.deriveChild(recipient, invoiceNumber);
    const verified = signingKey.verify(message, signature);
    return verified;
}
```

See also: [PrivateKey](./primitives.md#class-privatekey), [PublicKey](./primitives.md#class-publickey), [Reader](./primitives.md#class-reader), [Signature](./primitives.md#class-signature), [encode](./primitives.md#variable-encode), [toBase64](./primitives.md#function-tobase64), [toHex](./primitives.md#variable-tohex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Variables](#variables)

---
