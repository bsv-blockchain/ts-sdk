# API

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

## Interfaces

### Interface: JacobianPointBI

```ts
export interface JacobianPointBI {
    X: bigint;
    Y: bigint;
    Z: bigint;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Classes

| | | |
| --- | --- | --- |
| [BasePoint](#class-basepoint) | [PointInFiniteField](#class-pointinfinitefield) | [SHA256HMAC](#class-sha256hmac) |
| [BigNumber](#class-bignumber) | [Polynomial](#class-polynomial) | [SHA512](#class-sha512) |
| [Curve](#class-curve) | [PrivateKey](#class-privatekey) | [SHA512HMAC](#class-sha512hmac) |
| [DRBG](#class-drbg) | [PublicKey](#class-publickey) | [Schnorr](#class-schnorr) |
| [JacobianPoint](#class-jacobianpoint) | [RIPEMD160](#class-ripemd160) | [Signature](#class-signature) |
| [K256](#class-k256) | [Reader](#class-reader) | [SymmetricKey](#class-symmetrickey) |
| [KeyShares](#class-keyshares) | [ReductionContext](#class-reductioncontext) | [TransactionSignature](#class-transactionsignature) |
| [Mersenne](#class-mersenne) | [SHA1](#class-sha1) | [Writer](#class-writer) |
| [MontgomoryMethod](#class-montgomorymethod) | [SHA1HMAC](#class-sha1hmac) |  |
| [Point](#class-point) | [SHA256](#class-sha256) |  |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Class: BasePoint

Base class for Point (affine coordinates) and JacobianPoint classes,
defining their curve and type.

```ts
export default abstract class BasePoint {
    curve: Curve;
    type: "affine" | "jacobian";
    precomputed: {
        doubles?: {
            step: number;
            points: BasePoint[];
        };
        naf?: {
            wnd: number;
            points: BasePoint[];
        };
        beta?: BasePoint | null;
    } | null;
    constructor(type: "affine" | "jacobian") 
}
```

See also: [Curve](./primitives.md#class-curve)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: BigNumber

JavaScript numbers are only precise up to 53 bits. Since Bitcoin relies on
256-bit cryptography, this BigNumber class enables operations on larger
numbers.

```ts
export default class BigNumber {
    public static readonly zeros: string[] 
    static readonly groupSizes: number[] 
    static readonly groupBases: number[] 
    static readonly wordSize: number = 26;
    public red: ReductionContext | null;
    public get negative(): number 
    public set negative(val: number) 
    public get words(): number[] 
    public set words(newWords: number[]) 
    public get length(): number 
    static isBN(num: any): boolean 
    static max(left: BigNumber, right: BigNumber): BigNumber 
    static min(left: BigNumber, right: BigNumber): BigNumber 
    constructor(number: number | string | number[] | bigint | undefined = 0, base: number | "be" | "le" | "hex" = 10, endian: "be" | "le" = "be") 
    copy(dest: BigNumber): void 
    static move(dest: BigNumber, src: BigNumber): void 
    clone(): BigNumber 
    expand(size: number): this 
    strip(): this 
    normSign(): this { if (this._magnitude === 0n)
        this._sign = 0; return this; }
    inspect(): string 
    toString(base: number | "hex" = 10, padding: number = 1): string 
    toNumber(): number 
    toJSON(): string 
    toArray(endian: "le" | "be" = "be", length?: number): number[] 
    bitLength(): number { if (this._magnitude === 0n)
        return 0; return this._magnitude.toString(2).length; }
    static toBitArray(num: BigNumber): Array<0 | 1> 
    toBitArray(): Array<0 | 1> 
    zeroBits(): number 
    byteLength(): number { if (this._magnitude === 0n)
        return 0; return Math.ceil(this.bitLength() / 8); }
    toTwos(width: number): BigNumber 
    fromTwos(width: number): BigNumber 
    isNeg(): boolean 
    neg(): BigNumber 
    ineg(): this { if (this._magnitude !== 0n)
        this._sign = this._sign === 1 ? 0 : 1; return this; }
    iuor(num: BigNumber): this 
    iuand(num: BigNumber): this 
    iuxor(num: BigNumber): this 
    ior(num: BigNumber): this 
    iand(num: BigNumber): this 
    ixor(num: BigNumber): this 
    or(num: BigNumber): BigNumber 
    uor(num: BigNumber): BigNumber 
    and(num: BigNumber): BigNumber 
    uand(num: BigNumber): BigNumber 
    xor(num: BigNumber): BigNumber 
    uxor(num: BigNumber): BigNumber 
    inotn(width: number): this 
    notn(width: number): BigNumber 
    setn(bit: number, val: any): this { this.assert(typeof bit === "number" && bit >= 0); const Bb = BigInt(bit); if (val === 1 || val === true)
        this._magnitude |= (1n << Bb);
    else
        this._magnitude &= ~(1n << Bb); const wnb = Math.floor(bit / BigNumber.wordSize) + 1; this._nominalWordLength = Math.max(this._nominalWordLength, wnb); this._finishInitialization(); return this.strip(); }
    iadd(num: BigNumber): this 
    add(num: BigNumber): BigNumber 
    isub(num: BigNumber): this 
    sub(num: BigNumber): BigNumber 
    mul(num: BigNumber): BigNumber 
    imul(num: BigNumber): this 
    imuln(num: number): this 
    muln(num: number): BigNumber 
    sqr(): BigNumber 
    isqr(): this 
    pow(num: BigNumber): BigNumber 
    iushln(bits: number): this { this.assert(typeof bits === "number" && bits >= 0); if (bits === 0)
        return this; this._magnitude <<= BigInt(bits); this._finishInitialization(); return this.strip(); }
    ishln(bits: number): this 
    iushrn(bits: number, hint?: number, extended?: BigNumber): this 
    ishrn(bits: number, hint?: number, extended?: BigNumber): this 
    shln(bits: number): BigNumber 
    ushln(bits: number): BigNumber 
    shrn(bits: number): BigNumber 
    ushrn(bits: number): BigNumber 
    testn(bit: number): boolean 
    imaskn(bits: number): this 
    maskn(bits: number): BigNumber 
    iaddn(num: number): this 
    _iaddn(num: number): this 
    isubn(num: number): this 
    addn(num: number): BigNumber 
    subn(num: number): BigNumber 
    iabs(): this 
    abs(): BigNumber 
    divmod(num: BigNumber, mode?: "div" | "mod", positive?: boolean): any 
    div(num: BigNumber): BigNumber 
    mod(num: BigNumber): BigNumber 
    umod(num: BigNumber): BigNumber 
    divRound(num: BigNumber): BigNumber 
    modrn(numArg: number): number 
    idivn(num: number): this 
    divn(num: number): BigNumber 
    egcd(p: BigNumber): {
        a: BigNumber;
        b: BigNumber;
        gcd: BigNumber;
    } 
    gcd(num: BigNumber): BigNumber 
    invm(num: BigNumber): BigNumber 
    isEven(): boolean 
    isOdd(): boolean 
    andln(num: number): number 
    bincn(bit: number): this 
    isZero(): boolean 
    cmpn(num: number): 1 | 0 | -1 { this.assert(Math.abs(num) <= BigNumber.MAX_IMULN_ARG, "Number is too big"); const tV = this._getSignedValue(); const nV = BigInt(num); if (tV < nV)
        return -1; if (tV > nV)
        return 1; return 0; }
    cmp(num: BigNumber): 1 | 0 | -1 { const tV = this._getSignedValue(); const nV = num._getSignedValue(); if (tV < nV)
        return -1; if (tV > nV)
        return 1; return 0; }
    ucmp(num: BigNumber): 1 | 0 | -1 { if (this._magnitude < num._magnitude)
        return -1; if (this._magnitude > num._magnitude)
        return 1; return 0; }
    gtn(num: number): boolean 
    gt(num: BigNumber): boolean 
    gten(num: number): boolean 
    gte(num: BigNumber): boolean 
    ltn(num: number): boolean 
    lt(num: BigNumber): boolean 
    lten(num: number): boolean 
    lte(num: BigNumber): boolean 
    eqn(num: number): boolean 
    eq(num: BigNumber): boolean 
    toRed(ctx: ReductionContext): BigNumber 
    fromRed(): BigNumber 
    forceRed(ctx: ReductionContext): this 
    redAdd(num: BigNumber): BigNumber 
    redIAdd(num: BigNumber): BigNumber 
    redSub(num: BigNumber): BigNumber 
    redISub(num: BigNumber): BigNumber 
    redShl(num: number): BigNumber 
    redMul(num: BigNumber): BigNumber 
    redIMul(num: BigNumber): BigNumber 
    redSqr(): BigNumber 
    redISqr(): BigNumber 
    redSqrt(): BigNumber 
    redInvm(): BigNumber 
    redNeg(): BigNumber 
    redPow(num: BigNumber): BigNumber 
    static fromHex(hex: string, endian?: "le" | "be" | "little" | "big"): BigNumber 
    toHex(byteLength: number = 0): string 
    static fromJSON(str: string): BigNumber 
    static fromNumber(n: number): BigNumber 
    static fromString(str: string, base?: number | "hex"): BigNumber 
    static fromSm(bytes: number[], endian: "big" | "little" = "big"): BigNumber 
    toSm(endian: "big" | "little" = "big"): number[] 
    static fromBits(bits: number, strict: boolean = false): BigNumber 
    toBits(): number 
    static fromScriptNum(num: number[], requireMinimal: boolean = false, maxNumSize?: number): BigNumber 
    toScriptNum(): number[] 
    _invmp(p: BigNumber): BigNumber 
    mulTo(num: BigNumber, out: BigNumber): BigNumber 
}
```

See also: [ReductionContext](./primitives.md#class-reductioncontext), [red](./primitives.md#function-red), [toArray](./primitives.md#variable-toarray), [toHex](./primitives.md#variable-tohex)

#### Constructor

```ts
constructor(number: number | string | number[] | bigint | undefined = 0, base: number | "be" | "le" | "hex" = 10, endian: "be" | "le" = "be") 
```

Argument Details

+ **number**
  + The number (various types accepted) to construct a BigNumber from. Default is 0.
+ **base**
  + The base of number provided. By default is 10.
+ **endian**
  + The endianness provided. By default is 'big endian'.

#### Property red

Reduction context of the big number.

```ts
public red: ReductionContext | null
```
See also: [ReductionContext](./primitives.md#class-reductioncontext)

#### Property wordSize

The word size of big number chunks.

```ts
static readonly wordSize: number = 26
```

Example

```ts
console.log(BigNumber.wordSize);  // output: 26
```

#### Method _invmp

Compute the multiplicative inverse of the current BigNumber in the modulus field specified by `p`.
The multiplicative inverse is a number which when multiplied with the current BigNumber gives '1' in the modulus field.

```ts
_invmp(p: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

The multiplicative inverse `BigNumber` in the modulus field specified by `p`.

Argument Details

+ **p**
  + The `BigNumber` specifying the modulus field.

#### Method bitLength

Calculates the number of bits required to represent the BigNumber.

```ts
bitLength(): number { if (this._magnitude === 0n)
    return 0; return this._magnitude.toString(2).length; }
```

Returns

The bit length of the BigNumber.

#### Method byteLength

Calculates the number of bytes required to represent the BigNumber.

```ts
byteLength(): number { if (this._magnitude === 0n)
    return 0; return Math.ceil(this.bitLength() / 8); }
```

Returns

The byte length of the BigNumber.

#### Method fromBits

Creates a BigNumber from a number representing the "bits" value in a block header.

```ts
static fromBits(bits: number, strict: boolean = false): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns a BigNumber equivalent to the "bits" value in a block header.

Argument Details

+ **bits**
  + The number representing the bits value in a block header.
+ **strict**
  + If true, an error is thrown if the number has negative bit set.

Throws

Will throw an error if `strict` is `true` and the number has negative bit set.

#### Method fromHex

Creates a BigNumber from a hexadecimal string.

```ts
static fromHex(hex: string, endian?: "le" | "be" | "little" | "big"): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns a BigNumber created from the hexadecimal input string.

Argument Details

+ **hex**
  + The hexadecimal string to create a BigNumber from.
+ **endian**
  + Optional endianness for parsing the hex string.

Example

```ts
const exampleHex = 'a1b2c3';
const bigNumber = BigNumber.fromHex(exampleHex);
```

#### Method fromJSON

Creates a BigNumber from a JSON-serialized string.

```ts
static fromJSON(str: string): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns a BigNumber created from the JSON input string.

Argument Details

+ **str**
  + The JSON-serialized string to create a BigNumber from.

#### Method fromNumber

Creates a BigNumber from a number.

```ts
static fromNumber(n: number): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns a BigNumber equivalent to the input number.

Argument Details

+ **n**
  + The number to create a BigNumber from.

#### Method fromScriptNum

Creates a BigNumber from the format used in Bitcoin scripts.

```ts
static fromScriptNum(num: number[], requireMinimal: boolean = false, maxNumSize?: number): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns a BigNumber equivalent to the number used in a Bitcoin script.

Argument Details

+ **num**
  + The number in the format used in Bitcoin scripts.
+ **requireMinimal**
  + If true, non-minimally encoded values will throw an error.
+ **maxNumSize**
  + The maximum allowed size for the number.

#### Method fromSm

Creates a BigNumber from a signed magnitude number.

```ts
static fromSm(bytes: number[], endian: "big" | "little" = "big"): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns a BigNumber equivalent to the signed magnitude number interpreted with specified endianess.

Argument Details

+ **bytes**
  + The signed magnitude number to convert to a BigNumber.
+ **endian**
  + Defines endianess. If not provided, big endian is assumed.

#### Method fromString

Creates a BigNumber from a string, considering an optional base.

```ts
static fromString(str: string, base?: number | "hex"): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns a BigNumber equivalent to the string after conversion from the specified base.

Argument Details

+ **str**
  + The string to create a BigNumber from.
+ **base**
  + The base used for conversion. If not provided, base 10 is assumed.

#### Method isBN

Checks whether a value is an instance of BigNumber. Regular JS numbers fail this check.

```ts
static isBN(num: any): boolean 
```

Returns

- Returns a boolean value determining whether or not the checked num parameter is a BigNumber.

Argument Details

+ **num**
  + The value to be checked.

#### Method max

Returns the bigger value between two BigNumbers

```ts
static max(left: BigNumber, right: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

- Returns the bigger BigNumber between left and right.

Argument Details

+ **left**
  + The first BigNumber to be compared.
+ **right**
  + The second BigNumber to be compared.

#### Method min

Returns the smaller value between two BigNumbers

```ts
static min(left: BigNumber, right: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

- Returns the smaller value between left and right.

Argument Details

+ **left**
  + The first BigNumber to be compared.
+ **right**
  + The second BigNumber to be compared.

#### Method mulTo

Performs multiplication between the BigNumber instance and a given BigNumber.
It chooses the multiplication method based on the lengths of the numbers to optimize execution time.

```ts
mulTo(num: BigNumber, out: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

The BigNumber resulting from the multiplication operation.

Argument Details

+ **num**
  + The BigNumber multiply with.
+ **out**
  + The BigNumber where to store the result.

#### Method toArray

Converts the BigNumber instance to an array of bytes.

```ts
toArray(endian: "le" | "be" = "be", length?: number): number[] 
```

Returns

Array of bytes representing the BigNumber.

Argument Details

+ **endian**
  + Endianness of the output array, defaults to 'be'.
+ **length**
  + Optional length of the output array.

#### Method toBitArray

Converts a BigNumber to an array of bits.

```ts
static toBitArray(num: BigNumber): Array<0 | 1> 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

An array of bits.

Argument Details

+ **num**
  + The BigNumber to convert.

#### Method toBits

Converts this BigNumber to a number representing the "bits" value in a block header.

```ts
toBits(): number 
```

Returns

Returns a number equivalent to the "bits" value in a block header.

#### Method toHex

Converts this BigNumber to a hexadecimal string.

```ts
toHex(byteLength: number = 0): string 
```

Returns

Returns a string representing the hexadecimal value of this BigNumber.

Argument Details

+ **length**
  + The minimum length of the hex string

Example

```ts
const bigNumber = new BigNumber(255)
const hex = bigNumber.toHex()
```

#### Method toJSON

Converts the BigNumber instance to a JSON-formatted string.

```ts
toJSON(): string 
```

Returns

The JSON string representation of the BigNumber instance.

#### Method toNumber

Converts the BigNumber instance to a JavaScript number.
Please note that JavaScript numbers are only precise up to 53 bits.

```ts
toNumber(): number 
```

Returns

The JavaScript number representation of the BigNumber instance.

Throws

If the BigNumber instance cannot be safely stored in a JavaScript number

#### Method toScriptNum

Converts this BigNumber to a number in the format used in Bitcoin scripts.

```ts
toScriptNum(): number[] 
```

Returns

Returns the equivalent to this BigNumber as a Bitcoin script number.

#### Method toSm

Converts this BigNumber to a signed magnitude number.

```ts
toSm(endian: "big" | "little" = "big"): number[] 
```

Returns

Returns an array equivalent to this BigNumber interpreted as a signed magnitude with specified endianess.

Argument Details

+ **endian**
  + Defines endianess. If not provided, big endian is assumed.

#### Method toString

function toString() { [native code] }

Converts the BigNumber instance to a string representation.

```ts
toString(base: number | "hex" = 10, padding: number = 1): string 
```

Returns

The string representation of the BigNumber instance

Argument Details

+ **base**
  + The base for representing number. Default is 10. Other accepted values are 16 and 'hex'.
+ **padding**
  + Represents the minimum number of digits to represent the BigNumber as a string. Default is 1.

#### Method zeroBits

Returns the number of trailing zero bits in the big number.

```ts
zeroBits(): number 
```

Returns

Returns the number of trailing zero bits
in the binary representation of the big number.

Example

```ts
const bn = new BigNumber('8'); // binary: 1000
const zeroBits = bn.zeroBits(); // 3
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: Curve

```ts
export default class Curve {
    p: BigNumber;
    red: ReductionContext;
    redN: BigNumber | null;
    zero: BigNumber;
    one: BigNumber;
    two: BigNumber;
    g: Point;
    n: BigNumber;
    a: BigNumber;
    b: BigNumber;
    tinv: BigNumber;
    zeroA: boolean;
    threeA: boolean;
    endo: {
        beta: BigNumber;
        lambda: BigNumber;
        basis: Array<{
            a: BigNumber;
            b: BigNumber;
        }>;
    } | undefined;
    _endoWnafT1: BigNumber[];
    _endoWnafT2: BigNumber[];
    _wnafT1: BigNumber[];
    _wnafT2: BigNumber[];
    _wnafT3: BigNumber[];
    _wnafT4: BigNumber[];
    _bitLength: number;
    static assert(expression: unknown, message: string = "Elliptic curve assertion failed"): void 
    getNAF(num: BigNumber, w: number, bits: number): number[] 
    getJSF(k1: BigNumber, k2: BigNumber): number[][] 
    static cachedProperty(obj, name: string, computer): void 
    static parseBytes(bytes: string | number[]): number[] 
    static intFromLE(bytes: number[]): BigNumber 
    constructor() 
    _getEndomorphism(conf): {
        beta: BigNumber;
        lambda: BigNumber;
        basis: Array<{
            a: BigNumber;
            b: BigNumber;
        }>;
    } | undefined 
    _getEndoRoots(num: BigNumber): [
        BigNumber,
        BigNumber
    ] 
    _getEndoBasis(lambda: BigNumber): [
        {
            a: BigNumber;
            b: BigNumber;
        },
        {
            a: BigNumber;
            b: BigNumber;
        }
    ] 
    _endoSplit(k: BigNumber): {
        k1: BigNumber;
        k2: BigNumber;
    } 
    validate(point: Point): boolean 
}
```

See also: [BigNumber](./primitives.md#class-bignumber), [Point](./primitives.md#class-point), [ReductionContext](./primitives.md#class-reductioncontext), [red](./primitives.md#function-red)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: DRBG

This class behaves as a HMAC-based deterministic random bit generator (DRBG). It implements a deterministic random number generator using SHA256HMAC HASH function. It takes an initial entropy and nonce when instantiated for seeding purpose.

Example

```ts
const drbg = new DRBG('af12de...', '123ef...');
```

```ts
export default class DRBG {
    K: number[];
    V: number[];
    constructor(entropy: number[] | string, nonce: number[] | string) 
    hmac(): SHA256HMAC 
    update(seed?): void 
    generate(len: number): string 
}
```

See also: [SHA256HMAC](./primitives.md#class-sha256hmac)

#### Method generate

Generates deterministic random hexadecimal string of given length.
In every generation process, it also updates the internal state `K` and `V`.

```ts
generate(len: number): string 
```

Returns

The required deterministic random hexadecimal string.

Argument Details

+ **len**
  + The length of required random number.

Example

```ts
const randomHex = drbg.generate(256);
```

#### Method hmac

Generates HMAC using the K value of the instance. This method is used internally for operations.

```ts
hmac(): SHA256HMAC 
```
See also: [SHA256HMAC](./primitives.md#class-sha256hmac)

Returns

The SHA256HMAC object created with K value.

Example

```ts
const hmac = drbg.hmac();
```

#### Method update

Updates the `K` and `V` values of the instance based on the seed.
The seed if not provided uses `V` as seed.

```ts
update(seed?): void 
```

Returns

Nothing, but updates the internal state `K` and `V` value.

Argument Details

+ **seed**
  + an optional value that used to update `K` and `V`. Default is `undefined`.

Example

```ts
drbg.update('e13af...');
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: JacobianPoint

The `JacobianPoint` class extends the `BasePoint` class for handling Jacobian coordinates on an Elliptic Curve.
This class defines the properties and the methods needed to work with points in Jacobian coordinates.

The Jacobian coordinates represent a point (x, y, z) on an Elliptic Curve such that the usual (x, y) coordinates are given by (x/z^2, y/z^3).

Example

```ts
const pointJ = new JacobianPoint('3', '4', '1');
```

```ts
export default class JacobianPoint extends BasePoint {
    x: BigNumber;
    y: BigNumber;
    z: BigNumber;
    zOne: boolean;
    constructor(x: string | BigNumber | null, y: string | BigNumber | null, z: string | BigNumber | null) 
    toP(): Point 
    neg(): JacobianPoint 
    add(p: JacobianPoint): JacobianPoint 
    mixedAdd(p: Point): JacobianPoint 
    dblp(pow: number): JacobianPoint 
    dbl(): JacobianPoint 
    eq(p: Point | JacobianPoint): boolean 
    eqXToP(x: BigNumber): boolean 
    inspect(): string 
    isInfinity(): boolean 
}
```

See also: [BasePoint](./primitives.md#class-basepoint), [BigNumber](./primitives.md#class-bignumber), [Point](./primitives.md#class-point)

#### Constructor

Constructs a new `JacobianPoint` instance.

```ts
constructor(x: string | BigNumber | null, y: string | BigNumber | null, z: string | BigNumber | null) 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Argument Details

+ **x**
  + If `null`, the x-coordinate will default to the curve's defined 'one' constant.
If `x` is not a BigNumber, `x` will be converted to a `BigNumber` assuming it is a hex string.
+ **y**
  + If `null`, the y-coordinate will default to the curve's defined 'one' constant.
If `y` is not a BigNumber, `y` will be converted to a `BigNumber` assuming it is a hex string.
+ **z**
  + If `null`, the z-coordinate will default to 0.
If `z` is not a BigNumber, `z` will be converted to a `BigNumber` assuming it is a hex string.

Example

```ts
const pointJ1 = new JacobianPoint(null, null, null); // creates point at infinity
const pointJ2 = new JacobianPoint('3', '4', '1'); // creates point (3, 4, 1)
```

#### Property x

The `x` coordinate of the point in the Jacobian form.

```ts
x: BigNumber
```
See also: [BigNumber](./primitives.md#class-bignumber)

#### Property y

The `y` coordinate of the point in the Jacobian form.

```ts
y: BigNumber
```
See also: [BigNumber](./primitives.md#class-bignumber)

#### Property z

The `z` coordinate of the point in the Jacobian form.

```ts
z: BigNumber
```
See also: [BigNumber](./primitives.md#class-bignumber)

#### Property zOne

Flag that indicates if the `z` coordinate is one.

```ts
zOne: boolean
```

#### Method add

Addition operation in the Jacobian coordinates. It takes a Jacobian point as an argument
and returns a new Jacobian point as a result of the addition. In the special cases,
when either one of the points is the point at infinity, it will return the other point.

```ts
add(p: JacobianPoint): JacobianPoint 
```
See also: [JacobianPoint](./primitives.md#class-jacobianpoint)

Returns

Returns a new Jacobian point as the result of the addition.

Argument Details

+ **p**
  + The Jacobian point to be added.

Example

```ts
const p1 = new JacobianPoint(x1, y1, z1)
const p2 = new JacobianPoint(x2, y2, z2)
const result = p1.add(p2)
```

#### Method dbl

Point doubling operation in the Jacobian coordinates. A special case is when the point is the point at infinity, in this case, this function will return the point itself.

```ts
dbl(): JacobianPoint 
```
See also: [JacobianPoint](./primitives.md#class-jacobianpoint)

Returns

Returns a new Jacobian point as the result of the doubling.

Example

```ts
const jp = new JacobianPoint(x, y, z)
const result = jp.dbl()
```

#### Method dblp

Multiple doubling operation. It doubles the Jacobian point as many times as the pow parameter specifies. If pow is 0 or the point is the point at infinity, it will return the point itself.

```ts
dblp(pow: number): JacobianPoint 
```
See also: [JacobianPoint](./primitives.md#class-jacobianpoint)

Returns

Returns a new Jacobian point as the result of multiple doublings.

Argument Details

+ **pow**
  + The number of times the point should be doubled.

Example

```ts
const jp = new JacobianPoint(x, y, z)
const result = jp.dblp(3)
```

#### Method eq

Equality check operation. It checks whether the affine or Jacobian point is equal to this Jacobian point.

```ts
eq(p: Point | JacobianPoint): boolean 
```
See also: [JacobianPoint](./primitives.md#class-jacobianpoint), [Point](./primitives.md#class-point)

Returns

Returns true if the points are equal, otherwise returns false.

Argument Details

+ **p**
  + The affine or Jacobian point to compare with.

Example

```ts
const jp1 = new JacobianPoint(x1, y1, z1)
const jp2 = new JacobianPoint(x2, y2, z2)
const areEqual = jp1.eq(jp2)
```

#### Method eqXToP

Equality check operation in relation to an x coordinate of a point in projective coordinates.
It checks whether the x coordinate of the Jacobian point is equal to the provided x coordinate
of a point in projective coordinates.

```ts
eqXToP(x: BigNumber): boolean 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns true if the x coordinates are equal, otherwise returns false.

Argument Details

+ **x**
  + The x coordinate of a point in projective coordinates.

Example

```ts
const jp = new JacobianPoint(x1, y1, z1)
const isXEqual = jp.eqXToP(x2)
```

#### Method inspect

Returns the string representation of the JacobianPoint instance.

```ts
inspect(): string 
```

Returns

Returns the string description of the JacobianPoint. If the JacobianPoint represents a point at infinity, the return value of this function is '<EC JPoint Infinity>'. For a normal point, it returns the string description format as '<EC JPoint x: x-coordinate y: y-coordinate z: z-coordinate>'.

Example

```ts
const point = new JacobianPoint('5', '6', '1');
console.log(point.inspect()); // Output: '<EC JPoint x: 5 y: 6 z: 1>'
```

#### Method isInfinity

Checks whether the JacobianPoint instance represents a point at infinity.

```ts
isInfinity(): boolean 
```

Returns

Returns true if the JacobianPoint's z-coordinate equals to zero (which represents the point at infinity in Jacobian coordinates). Returns false otherwise.

Example

```ts
const point = new JacobianPoint('5', '6', '0');
console.log(point.isInfinity()); // Output: true
```

#### Method mixedAdd

Mixed addition operation. This function combines the standard point addition with
the transformation from the affine to Jacobian coordinates. It first converts
the affine point to Jacobian, and then preforms the addition.

```ts
mixedAdd(p: Point): JacobianPoint 
```
See also: [JacobianPoint](./primitives.md#class-jacobianpoint), [Point](./primitives.md#class-point)

Returns

Returns the result of the mixed addition as a new Jacobian point.

Argument Details

+ **p**
  + The affine point to be added.

Example

```ts
const jp = new JacobianPoint(x1, y1, z1)
const ap = new Point(x2, y2)
const result = jp.mixedAdd(ap)
```

#### Method neg

Negation operation. It returns the additive inverse of the Jacobian point.

```ts
neg(): JacobianPoint 
```
See also: [JacobianPoint](./primitives.md#class-jacobianpoint)

Returns

Returns a new Jacobian point as the result of the negation.

Example

```ts
const jp = new JacobianPoint(x, y, z)
const result = jp.neg()
```

#### Method toP

Converts the `JacobianPoint` object instance to standard affine `Point` format and returns `Point` type.

```ts
toP(): Point 
```
See also: [Point](./primitives.md#class-point)

Returns

The `Point`(affine) object representing the same point as the original `JacobianPoint`.

If the initial `JacobianPoint` represents point at infinity, an instance of `Point` at infinity is returned.

Example

```ts
const pointJ = new JacobianPoint('3', '4', '1');
const pointP = pointJ.toP();  // The point in affine coordinates.
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: K256

A class representing K-256, a prime number with optimizations, specifically used in the secp256k1 curve.
It extends the functionalities of the Mersenne class.
K-256 prime is represented as 'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f'

Example

```ts
const k256 = new K256();
```

```ts
export default class K256 extends Mersenne {
    constructor() 
    split(input: BigNumber, output: BigNumber): void 
    imulK(num: BigNumber): BigNumber 
}
```

See also: [BigNumber](./primitives.md#class-bignumber), [Mersenne](./primitives.md#class-mersenne)

#### Constructor

Constructor for the K256 class.
Creates an instance of K256 using the super constructor from Mersenne.

```ts
constructor() 
```

Example

```ts
const k256 = new K256();
```

#### Method imulK

Multiplies a BigNumber ('num') with the constant 'K' in-place and returns the result.
'K' is equal to 0x1000003d1 or in decimal representation: [ 64, 977 ].

```ts
imulK(num: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns the mutated BigNumber after multiplication.

Argument Details

+ **num**
  + The BigNumber to multiply with K.

Example

```ts
const number = new BigNumber(12345);
const result = k256.imulK(number);
```

#### Method split

Splits a BigNumber into a new BigNumber based on specific computation
rules. This method modifies the input and output big numbers.

```ts
split(input: BigNumber, output: BigNumber): void 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Argument Details

+ **input**
  + The BigNumber to be split.
+ **output**
  + The BigNumber that results from the split.

Example

```ts
const input = new BigNumber(3456);
const output = new BigNumber(0);
k256.split(input, output);
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: KeyShares

Example

```ts
const key = PrivateKey.fromShares(shares)
```

```ts
export class KeyShares {
    points: PointInFiniteField[];
    threshold: number;
    integrity: string;
    constructor(points: PointInFiniteField[], threshold: number, integrity: string) 
    static fromBackupFormat(shares: string[]): KeyShares 
    toBackupFormat(): string[] 
}
```

See also: [PointInFiniteField](./primitives.md#class-pointinfinitefield)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: Mersenne

A representation of a pseudo-Mersenne prime.
A pseudo-Mersenne prime has the general form 2^n - k, where n and k are integers.

```ts
export default class Mersenne {
    name: string;
    p: BigNumber;
    k: BigNumber;
    n: number;
    constructor(name: string, p: string) 
    ireduce(num: BigNumber): BigNumber 
    split(input: BigNumber, out: BigNumber): void 
    imulK(num: BigNumber): BigNumber 
}
```

See also: [BigNumber](./primitives.md#class-bignumber)

#### Constructor

```ts
constructor(name: string, p: string) 
```

Argument Details

+ **name**
  + An identifier for the Mersenne instance.
+ **p**
  + A string representation of the pseudo-Mersenne prime, expressed in hexadecimal.

Example

```ts
const mersenne = new Mersenne('M31', '7FFFFFFF');
```

#### Property k

The constant subtracted from 2^n to derive a pseudo-Mersenne prime.

```ts
k: BigNumber
```
See also: [BigNumber](./primitives.md#class-bignumber)

#### Property n

The exponent which determines the magnitude of the prime.

```ts
n: number
```

#### Property name

The identifier for the Mersenne instance.

```ts
name: string
```

#### Property p

BigNumber equivalent to 2^n - k.

```ts
p: BigNumber
```
See also: [BigNumber](./primitives.md#class-bignumber)

#### Method imulK

Performs an in-place multiplication of the parameter by constant k.

```ts
imulK(num: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

The result of the multiplication, in BigNumber format.

Argument Details

+ **num**
  + The BigNumber to multiply with k.

Example

```ts
const multiplied = mersenne.imulK(new BigNumber('2345', 16));
```

#### Method ireduce

Reduces an input BigNumber in place, under the assumption that
it is less than the square of the pseudo-Mersenne prime.

```ts
ireduce(num: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

The reduced BigNumber.

Argument Details

+ **num**
  + The BigNumber to be reduced.

Example

```ts
const reduced = mersenne.ireduce(new BigNumber('2345', 16));
```

#### Method split

Shifts bits of the input BigNumber to the right, in place,
to meet the magnitude of the pseudo-Mersenne prime.

```ts
split(input: BigNumber, out: BigNumber): void 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Argument Details

+ **input**
  + The BigNumber to be shifted (will contain HI part).
+ **out**
  + The BigNumber to hold the shifted result (LO part).

Example

```ts
mersenne.split(new BigNumber('2345', 16), new BigNumber());
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: MontgomoryMethod

Represents a Montgomery reduction context, which is a mathematical method
for performing modular multiplication without division.

Montgomery reduction is an algorithm used mainly in cryptography which can
help to speed up calculations in contexts where there are many repeated
computations.

This class extends the `ReductionContext` class.

```ts
export default class MontgomoryMethod extends ReductionContext {
    shift: number;
    r: BigNumber;
    r2: BigNumber;
    rinv: BigNumber;
    minv: BigNumber;
    constructor(m: BigNumber | "k256") 
    convertTo(num: BigNumber): BigNumber 
    convertFrom(num: BigNumber): BigNumber 
    imul(a: BigNumber, b: BigNumber): BigNumber 
    mul(a: BigNumber, b: BigNumber): BigNumber 
    invm(a: BigNumber): BigNumber 
}
```

See also: [BigNumber](./primitives.md#class-bignumber), [ReductionContext](./primitives.md#class-reductioncontext)

#### Constructor

```ts
constructor(m: BigNumber | "k256") 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Argument Details

+ **m**
  + The modulus to be used for the Montgomery method reductions.

#### Property minv

The modular multiplicative inverse of `m` mod `r`.

```ts
minv: BigNumber
```
See also: [BigNumber](./primitives.md#class-bignumber)

#### Property r

The 2^shift, shifted left by the bit length of modulus `m`.

```ts
r: BigNumber
```
See also: [BigNumber](./primitives.md#class-bignumber)

#### Property r2

The square of `r` modulo `m`.

```ts
r2: BigNumber
```
See also: [BigNumber](./primitives.md#class-bignumber)

#### Property rinv

The modular multiplicative inverse of `r` mod `m`.

```ts
rinv: BigNumber
```
See also: [BigNumber](./primitives.md#class-bignumber)

#### Property shift

The number of bits in the modulus.

```ts
shift: number
```

#### Method convertFrom

Converts a number from the Montgomery domain back to the original domain.

```ts
convertFrom(num: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

The result of the conversion from the Montgomery domain.

Argument Details

+ **num**
  + The number to be converted from the Montgomery domain.

Example

```ts
const montMethod = new MontgomoryMethod(m);
const convertedNum = montMethod.convertFrom(num);
```

#### Method convertTo

Converts a number into the Montgomery domain.

```ts
convertTo(num: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

The result of the conversion into the Montgomery domain.

Argument Details

+ **num**
  + The number to be converted into the Montgomery domain.

Example

```ts
const montMethod = new MontgomoryMethod(m);
const convertedNum = montMethod.convertTo(num);
```

#### Method imul

Performs an in-place multiplication of two numbers in the Montgomery domain.

```ts
imul(a: BigNumber, b: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

The result of the in-place multiplication.

Argument Details

+ **a**
  + The first number to multiply.
+ **b**
  + The second number to multiply.

Example

```ts
const montMethod = new MontgomoryMethod(m);
const product = montMethod.imul(a, b);
```

#### Method invm

Calculates the modular multiplicative inverse of a number in the Montgomery domain.

```ts
invm(a: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

The modular multiplicative inverse of 'a'.

Argument Details

+ **a**
  + The number to compute the modular multiplicative inverse of.

Example

```ts
const montMethod = new MontgomoryMethod(m);
const inverse = montMethod.invm(a);
```

#### Method mul

Performs the multiplication of two numbers in the Montgomery domain.

```ts
mul(a: BigNumber, b: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

The result of the multiplication.

Argument Details

+ **a**
  + The first number to multiply.
+ **b**
  + The second number to multiply.

Example

```ts
const montMethod = new MontgomoryMethod(m);
const product = montMethod.mul(a, b);
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: Point

`Point` class is a representation of an elliptic curve point with affine coordinates.
It extends the functionality of BasePoint and carries x, y coordinates of point on the curve.
It also introduces new methods for handling Point operations in elliptic curve.

```ts
export default class Point extends BasePoint {
    x: BigNumber | null;
    y: BigNumber | null;
    inf: boolean;
    static fromDER(bytes: number[]): Point 
    static fromString(str: string): Point 
    static fromX(x: BigNumber | number | number[] | string, odd: boolean): Point 
    static fromJSON(obj: string | any[], isRed: boolean): Point 
    constructor(x: BigNumber | number | number[] | string | null, y: BigNumber | number | number[] | string | null, isRed: boolean = true) 
    validate(): boolean 
    encode(compact: boolean = true, enc?: "hex"): number[] | string 
    toString(): string 
    toJSON(): [
        BigNumber | null,
        BigNumber | null,
        {
            doubles: {
                step: any;
                points: any[];
            } | undefined;
            naf: {
                wnd: any;
                points: any[];
            } | undefined;
        }?
    ] 
    inspect(): string 
    isInfinity(): boolean 
    add(p: Point): Point 
    dbl(): Point 
    getX(): BigNumber 
    getY(): BigNumber 
    mul(k: BigNumber | number | number[] | string): Point 
    mulAdd(k1: BigNumber, p2: Point, k2: BigNumber): Point 
    jmulAdd(k1: BigNumber, p2: Point, k2: BigNumber): JPoint 
    eq(p: Point): boolean 
    neg(_precompute?: boolean): Point 
    dblp(k: number): Point 
    toJ(): JPoint 
}
```

See also: [BasePoint](./primitives.md#class-basepoint), [BigNumber](./primitives.md#class-bignumber), [encode](./primitives.md#variable-encode)

#### Constructor

```ts
constructor(x: BigNumber | number | number[] | string | null, y: BigNumber | number | number[] | string | null, isRed: boolean = true) 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Argument Details

+ **x**
  + The x-coordinate of the point. May be a number, a BigNumber, a string (which will be interpreted as hex), a number array, or null. If null, an "Infinity" point is constructed.
+ **y**
  + The y-coordinate of the point, similar to x.
+ **isRed**
  + A boolean indicating if the point is a member of the field of integers modulo the k256 prime. Default is true.

Example

```ts
new Point('abc123', 'def456');
new Point(null, null); // Generates Infinity point.
```

#### Property inf

Flag to record if the point is at infinity in the Elliptic Curve.

```ts
inf: boolean
```

#### Property x

The x-coordinate of the point.

```ts
x: BigNumber | null
```
See also: [BigNumber](./primitives.md#class-bignumber)

#### Property y

The y-coordinate of the point.

```ts
y: BigNumber | null
```
See also: [BigNumber](./primitives.md#class-bignumber)

#### Method add

Adds another Point to this Point, returning a new Point.

```ts
add(p: Point): Point 
```
See also: [Point](./primitives.md#class-point)

Returns

A new Point that results from the addition.

Argument Details

+ **p**
  + The Point to add to this one.

Example

```ts
const p1 = new Point(1, 2);
const p2 = new Point(2, 3);
const result = p1.add(p2);
```

#### Method dbl

Doubles the current point.

```ts
dbl(): Point 
```
See also: [Point](./primitives.md#class-point)

Example

```ts
const P = new Point('123', '456');
const result = P.dbl();
```

#### Method dblp

Performs the "doubling" operation on the Point a given number of times.
This is used in elliptic curve operations to perform multiplication by 2, multiple times.
If the point is at infinity, it simply returns the point because doubling
a point at infinity is still infinity.

```ts
dblp(k: number): Point 
```
See also: [Point](./primitives.md#class-point)

Returns

The Point after 'k' "doubling" operations have been performed.

Argument Details

+ **k**
  + The number of times the "doubling" operation is to be performed on the Point.

Example

```ts
const p = new Point(5, 20);
const doubledPoint = p.dblp(10); // returns the point after "doubled" 10 times
```

#### Method encode

Encodes the coordinates of a point into an array or a hexadecimal string.
The details of encoding are determined by the optional compact and enc parameters.

```ts
encode(compact: boolean = true, enc?: "hex"): number[] | string 
```

Returns

If enc is undefined, a byte array representation of the point will be returned. if enc is 'hex', a hexadecimal string representation of the point will be returned.

Argument Details

+ **compact**
  + If true, an additional prefix byte 0x02 or 0x03 based on the 'y' coordinate being even or odd respectively is used. If false, byte 0x04 is used.
+ **enc**
  + Expects the string 'hex' if hexadecimal string encoding is required instead of an array of numbers.

Throws

Will throw an error if the specified encoding method is not recognized. Expects 'hex'.

Example

```ts
const aPoint = new Point(x, y);
const encodedPointArray = aPoint.encode();
const encodedPointHex = aPoint.encode(true, 'hex');
```

#### Method eq

Checks if the Point instance is equal to another given Point.

```ts
eq(p: Point): boolean 
```
See also: [Point](./primitives.md#class-point)

Returns

Whether the two Point instances are equal. Both the 'x' and 'y' coordinates have to match, and both points have to either be valid or at infinity for equality. If both conditions are true, it returns true, else it returns false.

Argument Details

+ **p**
  + The Point to be checked if equal to the current instance.

Example

```ts
const p1 = new Point(5, 20);
const p2 = new Point(5, 20);
const areEqual = p1.eq(p2); // returns true
```

#### Method fromDER

Creates a point object from a given Array. These numbers can represent coordinates in hex format, or points
in multiple established formats.
The function verifies the integrity of the provided data and throws errors if inconsistencies are found.

```ts
static fromDER(bytes: number[]): Point 
```
See also: [Point](./primitives.md#class-point)

Returns

Returns a new point representing the given string.

Argument Details

+ **bytes**
  + The point representation number array.

Throws

`Error` If the point number[] value has a wrong length.

`Error` If the point format is unknown.

Example

```ts
const derPoint = [ 2, 18, 123, 108, 125, 83, 1, 251, 164, 214, 16, 119, 200, 216, 210, 193, 251, 193, 129, 67, 97, 146, 210, 216, 77, 254, 18, 6, 150, 190, 99, 198, 128 ];
const point = Point.fromDER(derPoint);
```

#### Method fromJSON

Generates a point from a serialized JSON object. The function accounts for different options in the JSON object,
including precomputed values for optimization of EC operations, and calls another helper function to turn nested
JSON points into proper Point objects.

```ts
static fromJSON(obj: string | any[], isRed: boolean): Point 
```
See also: [Point](./primitives.md#class-point)

Returns

Returns a new point based on the deserialized JSON object.

Argument Details

+ **obj**
  + An object or array that holds the data for the point.
+ **isRed**
  + A boolean to direct how the Point is constructed from the JSON object.

Example

```ts
const serializedPoint = '{"x":52,"y":15}';
const point = Point.fromJSON(serializedPoint, true);
```

#### Method fromString

Creates a point object from a given string. This string can represent coordinates in hex format, or points
in multiple established formats.
The function verifies the integrity of the provided data and throws errors if inconsistencies are found.

```ts
static fromString(str: string): Point 
```
See also: [Point](./primitives.md#class-point)

Returns

Returns a new point representing the given string.

Argument Details

+ **str**
  + The point representation string.

Throws

`Error` If the point string value has a wrong length.

`Error` If the point format is unknown.

Example

```ts
const pointStr = 'abcdef';
const point = Point.fromString(pointStr);
```

#### Method fromX

Generates a point from an x coordinate and a boolean indicating whether the corresponding
y coordinate is odd.

```ts
static fromX(x: BigNumber | number | number[] | string, odd: boolean): Point 
```
See also: [BigNumber](./primitives.md#class-bignumber), [Point](./primitives.md#class-point)

Returns

Returns the new point.

Argument Details

+ **x**
  + The x coordinate of the point.
+ **odd**
  + Boolean indicating whether the corresponding y coordinate is odd or not.

Throws

`Error` If the point is invalid.

Example

```ts
const xCoordinate = new BigNumber('10');
const point = Point.fromX(xCoordinate, true);
```

#### Method getX

Returns X coordinate of point

```ts
getX(): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Example

```ts
const P = new Point('123', '456');
const x = P.getX();
```

#### Method getY

Returns X coordinate of point

```ts
getY(): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Example

```ts
const P = new Point('123', '456');
const x = P.getX();
```

#### Method inspect

Provides the point coordinates in a human-readable string format for debugging purposes.

```ts
inspect(): string 
```

Returns

String of the format '<EC Point x: x-coordinate y: y-coordinate>', or '<EC Point Infinity>' if the point is at infinity.

Example

```ts
const aPoint = new Point(x, y);
console.log(aPoint.inspect());
```

#### Method isInfinity

Checks if the point is at infinity.

```ts
isInfinity(): boolean 
```

Returns

Returns whether or not the point is at infinity.

Example

```ts
const p = new Point(null, null);
console.log(p.isInfinity()); // outputs: true
```

#### Method jmulAdd

Performs the Jacobian multiplication and addition operation in a single
step. Instead of returning a regular Point, the result is a JacobianPoint.

```ts
jmulAdd(k1: BigNumber, p2: Point, k2: BigNumber): JPoint 
```
See also: [BigNumber](./primitives.md#class-bignumber), [Point](./primitives.md#class-point)

Returns

A JacobianPoint that results from the combined multiplication and addition operation.

Argument Details

+ **k1**
  + The scalar value to multiply this Point by.
+ **p2**
  + The other Point to be involved in the operation
+ **k2**
  + The scalar value to multiply the Point p2 by.

Example

```ts
const p1 = new Point(1, 2);
const p2 = new Point(2, 3);
const result = p1.jmulAdd(2, p2, 3);
```

#### Method mul

Multiplies this Point by a scalar value, returning a new Point.

```ts
mul(k: BigNumber | number | number[] | string): Point 
```
See also: [BigNumber](./primitives.md#class-bignumber), [Point](./primitives.md#class-point)

Returns

A new Point that results from the multiplication.

Argument Details

+ **k**
  + The scalar value to multiply this Point by.

Example

```ts
const p = new Point(1, 2);
const result = p.mul(2); // this doubles the Point
```

#### Method mulAdd

Performs a multiplication and addition operation in a single step.
Multiplies this Point by k1, adds the resulting Point to the result of p2 multiplied by k2.

```ts
mulAdd(k1: BigNumber, p2: Point, k2: BigNumber): Point 
```
See also: [BigNumber](./primitives.md#class-bignumber), [Point](./primitives.md#class-point)

Returns

A Point that results from the combined multiplication and addition operations.

Argument Details

+ **k1**
  + The scalar value to multiply this Point by.
+ **p2**
  + The other Point to be involved in the operation.
+ **k2**
  + The scalar value to multiply the Point p2 by.

Example

```ts
const p1 = new Point(1, 2);
const p2 = new Point(2, 3);
const result = p1.mulAdd(2, p2, 3);
```

#### Method neg

Negate a point. The negation of a point P is the mirror of P about x-axis.

```ts
neg(_precompute?: boolean): Point 
```
See also: [Point](./primitives.md#class-point)

Example

```ts
const P = new Point('123', '456');
const result = P.neg();
```

#### Method toJ

Converts the point to a Jacobian point. If the point is at infinity, the corresponding Jacobian point
will also be at infinity.

```ts
toJ(): JPoint 
```

Returns

Returns a new Jacobian point based on the current point.

Example

```ts
const point = new Point(xCoordinate, yCoordinate);
const jacobianPoint = point.toJ();
```

#### Method toJSON

Exports the x and y coordinates of the point, and the precomputed doubles and non-adjacent form (NAF) for optimization. The output is an array.

```ts
toJSON(): [
    BigNumber | null,
    BigNumber | null,
    {
        doubles: {
            step: any;
            points: any[];
        } | undefined;
        naf: {
            wnd: any;
            points: any[];
        } | undefined;
    }?
] 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

An Array where first two elements are the coordinates of the point and optional third element is an object with doubles and NAF points.

Example

```ts
const aPoint = new Point(x, y);
const jsonPoint = aPoint.toJSON();
```

#### Method toString

function toString() { [native code] }

Converts the point coordinates to a hexadecimal string. A wrapper method
for encode. Byte 0x02 or 0x03 is used as prefix based on the 'y' coordinate being even or odd respectively.

```ts
toString(): string 
```

Returns

A hexadecimal string representation of the point coordinates.

Example

```ts
const aPoint = new Point(x, y);
const stringPoint = aPoint.toString();
```

#### Method validate

Validates if a point belongs to the curve. Follows the short Weierstrass
equation for elliptic curves: y^2 = x^3 + ax + b.

```ts
validate(): boolean 
```

Returns

true if the point is on the curve, false otherwise.

Example

```ts
const aPoint = new Point(x, y);
const isValid = aPoint.validate();
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: PointInFiniteField

```ts
export class PointInFiniteField {
    x: BigNumber;
    y: BigNumber;
    constructor(x: BigNumber, y: BigNumber) 
    toString(): string 
    static fromString(str: string): PointInFiniteField 
}
```

See also: [BigNumber](./primitives.md#class-bignumber)

#### Method toString

function toString() { [native code] }

```ts
toString(): string 
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: Polynomial

Polynomial class

This class is used to create a polynomial with a given threshold and a private key.
The polynomial is used to create shares of the private key.

Example

```ts
const key = new PrivateKey()
const threshold = 2
const polynomial = new Polynomial(key, threshold)
```

```ts
export default class Polynomial {
    readonly points: PointInFiniteField[];
    readonly threshold: number;
    constructor(points: PointInFiniteField[], threshold?: number) 
    static fromPrivateKey(key: PrivateKey, threshold: number): Polynomial 
    valueAt(x: BigNumber): BigNumber 
}
```

See also: [BigNumber](./primitives.md#class-bignumber), [PointInFiniteField](./primitives.md#class-pointinfinitefield), [PrivateKey](./primitives.md#class-privatekey)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: PrivateKey

Represents a Private Key, which is a secret that can be used to generate signatures in a cryptographic system.

The `PrivateKey` class extends from the `BigNumber` class. It offers methods to create signatures, verify them,
create a corresponding public key and derive a shared secret from a public key.

```ts
export default class PrivateKey extends BigNumber {
    static fromRandom(): PrivateKey 
    static fromString(str: string, base: number | "hex" = "hex"): PrivateKey 
    static fromHex(str: string): PrivateKey 
    static fromWif(wif: string, prefixLength: number = 1): PrivateKey 
    constructor(number: BigNumber | number | string | number[] = 0, base: number | "be" | "le" | "hex" = 10, endian: "be" | "le" = "be", modN: "apply" | "nocheck" | "error" = "apply") 
    checkInField(): {
        inField: boolean;
        modN: BigNumber;
    } 
    isValid(): boolean 
    sign(msg: number[] | string, enc?: "hex" | "utf8", forceLowS: boolean = true, customK?: ((iter: number) => BigNumber) | BigNumber): Signature 
    verify(msg: number[] | string, sig: Signature, enc?: "hex"): boolean 
    toPublicKey(): PublicKey 
    toWif(prefix: number[] = [128]): string 
    toAddress(prefix: number[] | string = [0]): string 
    toHex(): string 
    toString(base: number | "hex" = "hex", padding: number = 64): string 
    deriveSharedSecret(key: PublicKey): Point 
    deriveChild(publicKey: PublicKey, invoiceNumber: string, cacheSharedSecret?: ((priv: PrivateKey, pub: Point, point: Point) => void), retrieveCachedSharedSecret?: ((priv: PrivateKey, pub: Point) => (Point | undefined))): PrivateKey 
    toKeyShares(threshold: number, totalShares: number): KeyShares 
    toBackupShares(threshold: number, totalShares: number): string[] 
    static fromBackupShares(shares: string[]): PrivateKey 
    static fromKeyShares(keyShares: KeyShares): PrivateKey 
}
```

See also: [BigNumber](./primitives.md#class-bignumber), [KeyShares](./primitives.md#class-keyshares), [Point](./primitives.md#class-point), [PublicKey](./primitives.md#class-publickey), [Signature](./primitives.md#class-signature), [modN](./primitives.md#variable-modn), [sign](./compat.md#variable-sign), [toHex](./primitives.md#variable-tohex), [verify](./compat.md#variable-verify)

#### Constructor

```ts
constructor(number: BigNumber | number | string | number[] = 0, base: number | "be" | "le" | "hex" = 10, endian: "be" | "le" = "be", modN: "apply" | "nocheck" | "error" = "apply") 
```
See also: [BigNumber](./primitives.md#class-bignumber), [modN](./primitives.md#variable-modn)

Argument Details

+ **number**
  + The number (various types accepted) to construct a BigNumber from. Default is 0.
+ **base**
  + The base of number provided. By default is 10. Ignored if number is BigNumber.
+ **endian**
  + The endianness provided. By default is 'big endian'. Ignored if number is BigNumber.
+ **modN**
  + Optional. Default 'apply. If 'apply', apply modN to input to guarantee a valid PrivateKey. If 'error', if input is out of field throw new Error('Input is out of field'). If 'nocheck', assumes input is in field.

Example

```ts
import PrivateKey from './PrivateKey';
import BigNumber from './BigNumber';
const privKey = new PrivateKey(new BigNumber('123456', 10, 'be'));
```

#### Method checkInField

A utility function to check that the value of this PrivateKey lies in the field limited by curve.n

```ts
checkInField(): {
    inField: boolean;
    modN: BigNumber;
} 
```
See also: [BigNumber](./primitives.md#class-bignumber), [modN](./primitives.md#variable-modn)

Returns

, modN } where modN is this PrivateKey's current BigNumber value mod curve.n, and inField is true only if modN equals current BigNumber value.

#### Method deriveChild

Derives a child key with BRC-42.

```ts
deriveChild(publicKey: PublicKey, invoiceNumber: string, cacheSharedSecret?: ((priv: PrivateKey, pub: Point, point: Point) => void), retrieveCachedSharedSecret?: ((priv: PrivateKey, pub: Point) => (Point | undefined))): PrivateKey 
```
See also: [Point](./primitives.md#class-point), [PrivateKey](./primitives.md#class-privatekey), [PublicKey](./primitives.md#class-publickey)

Returns

The derived child key.

Argument Details

+ **publicKey**
  + The public key of the other party
+ **invoiceNumber**
  + The invoice number used to derive the child key
+ **cacheSharedSecret**
  + Optional function to cache shared secrets
+ **retrieveCachedSharedSecret**
  + Optional function to retrieve shared secrets from the cache

#### Method deriveSharedSecret

Derives a shared secret from the public key.

```ts
deriveSharedSecret(key: PublicKey): Point 
```
See also: [Point](./primitives.md#class-point), [PublicKey](./primitives.md#class-publickey)

Returns

The derived shared secret (a point on the curve).

Argument Details

+ **key**
  + The public key to derive the shared secret from.

Throws

Will throw an error if the public key is not valid.

Example

```ts
const privateKey = PrivateKey.fromRandom();
const publicKey = privateKey.toPublicKey();
const sharedSecret = privateKey.deriveSharedSecret(publicKey);
```

#### Method fromBackupShares

```ts
static fromBackupShares(shares: string[]): PrivateKey 
```
See also: [PrivateKey](./primitives.md#class-privatekey)

Returns

PrivateKey

Example

```ts
const share1 = '3znuzt7DZp8HzZTfTh5MF9YQKNX3oSxTbSYmSRGrH2ev.2Nm17qoocmoAhBTCs8TEBxNXCskV9N41rB2PckcgYeqV.2.35449bb9'
const share2 = 'Cm5fuUc39X5xgdedao8Pr1kvCSm8Gk7Cfenc7xUKcfLX.2juyK9BxCWn2DiY5JUAgj9NsQ77cc9bWksFyW45haXZm.2.35449bb9'

const recoveredKey = PrivateKey.fromBackupShares([share1, share2])
```

#### Method fromHex

Generates a private key from a hexadecimal string.

```ts
static fromHex(str: string): PrivateKey 
```
See also: [PrivateKey](./primitives.md#class-privatekey)

Returns

The generated Private Key instance.

Argument Details

+ **str**
  + The hexadecimal string representing the private key. The string must represent a valid private key in big-endian format.

Throws

If the string is not a valid hexadecimal or represents an invalid private key.

#### Method fromKeyShares

Combines shares to reconstruct the private key.

```ts
static fromKeyShares(keyShares: KeyShares): PrivateKey 
```
See also: [KeyShares](./primitives.md#class-keyshares), [PrivateKey](./primitives.md#class-privatekey)

Returns

The reconstructed private key.

Argument Details

+ **shares**
  + An array of points (shares) to be used to reconstruct the private key.
+ **threshold**
  + The minimum number of shares required to reconstruct the private key.

#### Method fromRandom

Generates a private key randomly.

```ts
static fromRandom(): PrivateKey 
```
See also: [PrivateKey](./primitives.md#class-privatekey)

Returns

The newly generated Private Key.

Example

```ts
const privateKey = PrivateKey.fromRandom();
```

#### Method fromString

Generates a private key from a string.

```ts
static fromString(str: string, base: number | "hex" = "hex"): PrivateKey 
```
See also: [PrivateKey](./primitives.md#class-privatekey)

Returns

The generated Private Key.

Argument Details

+ **str**
  + The string to generate the private key from.
+ **base**
  + The base of the string.

Throws

Will throw an error if the string is not valid.

#### Method fromWif

Generates a private key from a WIF (Wallet Import Format) string.

```ts
static fromWif(wif: string, prefixLength: number = 1): PrivateKey 
```
See also: [PrivateKey](./primitives.md#class-privatekey)

Returns

The generated Private Key.

Argument Details

+ **wif**
  + The WIF string to generate the private key from.
+ **base**
  + The base of the string.

Throws

Will throw an error if the string is not a valid WIF.

#### Method isValid

```ts
isValid(): boolean 
```

Returns

true if the PrivateKey's current BigNumber value lies in the field limited by curve.n

#### Method sign

Signs a message using the private key.

```ts
sign(msg: number[] | string, enc?: "hex" | "utf8", forceLowS: boolean = true, customK?: ((iter: number) => BigNumber) | BigNumber): Signature 
```
See also: [BigNumber](./primitives.md#class-bignumber), [Signature](./primitives.md#class-signature)

Returns

A digital signature generated from the hash of the message and the private key.

Argument Details

+ **msg**
  + The message (array of numbers or string) to be signed.
+ **enc**
  + If 'hex' the string will be treated as hex, utf8 otherwise.
+ **forceLowS**
  + If true (the default), the signature will be forced to have a low S value.
+ **customK**
  + — If provided, uses a custom K-value for the signature. Provie a function that returns a BigNumber, or the BigNumber itself.

Example

```ts
const privateKey = PrivateKey.fromRandom();
const signature = privateKey.sign('Hello, World!');
```

#### Method toAddress

Base58Check encodes the hash of the public key associated with this private key with a prefix to indicate locking script type.
Defaults to P2PKH for mainnet, otherwise known as a "Bitcoin Address".

```ts
toAddress(prefix: number[] | string = [0]): string 
```

Returns

Returns the address encoding associated with the hash of the public key associated with this private key.

Argument Details

+ **prefix**
  + defaults to [0x00] for mainnet, set to [0x6f] for testnet or use the strings 'testnet' or 'mainnet'

Example

```ts
const address = privkey.toAddress()
const address = privkey.toAddress('mainnet')
const testnetAddress = privkey.toAddress([0x6f])
const testnetAddress = privkey.toAddress('testnet')
```

#### Method toBackupShares

```ts
toBackupShares(threshold: number, totalShares: number): string[] 
```

Argument Details

+ **threshold**
  + The number of shares which will be required to reconstruct the private key.
+ **totalShares**
  + The number of shares to generate for distribution.

#### Method toHex

Converts this PrivateKey to a hexadecimal string.

```ts
toHex(): string 
```

Returns

Returns a string representing the hexadecimal value of this BigNumber.

Argument Details

+ **length**
  + The minimum length of the hex string

Example

```ts
const bigNumber = new BigNumber(255);
const hex = bigNumber.toHex();
```

#### Method toKeyShares

Splits the private key into shares using Shamir's Secret Sharing Scheme.

```ts
toKeyShares(threshold: number, totalShares: number): KeyShares 
```
See also: [KeyShares](./primitives.md#class-keyshares)

Returns

An array of shares.

Argument Details

+ **threshold**
  + The minimum number of shares required to reconstruct the private key.
+ **totalShares**
  + The total number of shares to generate.
+ **prime**
  + The prime number to be used in Shamir's Secret Sharing Scheme.

Example

```ts
const key = PrivateKey.fromRandom()
const shares = key.toKeyShares(2, 5)
```

#### Method toPublicKey

Converts the private key to its corresponding public key.

The public key is generated by multiplying the base point G of the curve and the private key.

```ts
toPublicKey(): PublicKey 
```
See also: [PublicKey](./primitives.md#class-publickey)

Returns

The generated PublicKey.

Example

```ts
const privateKey = PrivateKey.fromRandom();
const publicKey = privateKey.toPublicKey();
```

#### Method toString

function toString() { [native code] }

Converts this PrivateKey to a string representation.

```ts
toString(base: number | "hex" = "hex", padding: number = 64): string 
```

Returns

A string representation of the PrivateKey in the specified base, padded to the specified length.

Argument Details

+ **base**
  + The base for representing the number. Default is hexadecimal ('hex').
+ **padding**
  + The minimum number of digits for the output string. Default is 64, ensuring a 256-bit representation in hexadecimal.

#### Method toWif

Converts the private key to a Wallet Import Format (WIF) string.

Base58Check encoding is used for encoding the private key.
The prefix

```ts
toWif(prefix: number[] = [128]): string 
```

Returns

The WIF string.

Argument Details

+ **prefix**
  + defaults to [0x80] for mainnet, set it to [0xef] for testnet.

Throws

Error('Value is out of field') if current BigNumber value is out of field limited by curve.n

Example

```ts
const privateKey = PrivateKey.fromRandom();
const wif = privateKey.toWif();
const testnetWif = privateKey.toWif([0xef]);
```

#### Method verify

Verifies a message's signature using the public key associated with this private key.

```ts
verify(msg: number[] | string, sig: Signature, enc?: "hex"): boolean 
```
See also: [Signature](./primitives.md#class-signature)

Returns

Whether or not the signature is valid.

Argument Details

+ **msg**
  + The original message which has been signed.
+ **sig**
  + The signature to be verified.
+ **enc**
  + The data encoding method.

Example

```ts
const privateKey = PrivateKey.fromRandom();
const signature = privateKey.sign('Hello, World!');
const isSignatureValid = privateKey.verify('Hello, World!', signature);
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: PublicKey

The PublicKey class extends the Point class. It is used in public-key cryptography to derive shared secret, verify message signatures, and encode the public key in the DER format.
The class comes with static methods to generate PublicKey instances from private keys or from strings.

```ts
export default class PublicKey extends Point {
    static fromPrivateKey(key: PrivateKey): PublicKey 
    static fromString(str: string): PublicKey 
    static fromDER(bytes: number[]): PublicKey 
    constructor(x: Point | BigNumber | number | number[] | string | null, y: BigNumber | number | number[] | string | null = null, isRed: boolean = true) 
    deriveSharedSecret(priv: PrivateKey): Point 
    verify(msg: number[] | string, sig: Signature, enc?: "hex" | "utf8"): boolean 
    toDER(enc?: "hex" | undefined): number[] | string 
    toHash(enc?: "hex"): number[] | string 
    toAddress(prefix: number[] | string = [0]): string 
    deriveChild(privateKey: PrivateKey, invoiceNumber: string, cacheSharedSecret?: ((priv: PrivateKey, pub: Point, point: Point) => void), retrieveCachedSharedSecret?: ((priv: PrivateKey, pub: Point) => (Point | undefined))): PublicKey 
    static fromMsgHashAndCompactSignature(msgHash: BigNumber, signature: number[] | string, enc?: "hex" | "base64"): PublicKey 
}
```

See also: [BigNumber](./primitives.md#class-bignumber), [Point](./primitives.md#class-point), [PrivateKey](./primitives.md#class-privatekey), [Signature](./primitives.md#class-signature), [verify](./compat.md#variable-verify)

#### Constructor

```ts
constructor(x: Point | BigNumber | number | number[] | string | null, y: BigNumber | number | number[] | string | null = null, isRed: boolean = true) 
```
See also: [BigNumber](./primitives.md#class-bignumber), [Point](./primitives.md#class-point)

Argument Details

+ **x**
  + A point or the x-coordinate of the point. May be a number, a BigNumber, a string (which will be interpreted as hex), a number array, or null. If null, an "Infinity" point is constructed.
+ **y**
  + If x is not a point, the y-coordinate of the point, similar to x.
+ **isRed**
  + A boolean indicating if the point is a member of the field of integers modulo the k256 prime. Default is true.

Example

```ts
new PublicKey(point1);
new PublicKey('abc123', 'def456');
```

#### Method deriveChild

Derives a child key with BRC-42.

```ts
deriveChild(privateKey: PrivateKey, invoiceNumber: string, cacheSharedSecret?: ((priv: PrivateKey, pub: Point, point: Point) => void), retrieveCachedSharedSecret?: ((priv: PrivateKey, pub: Point) => (Point | undefined))): PublicKey 
```
See also: [Point](./primitives.md#class-point), [PrivateKey](./primitives.md#class-privatekey), [PublicKey](./primitives.md#class-publickey)

Returns

The derived child key.

Argument Details

+ **privateKey**
  + The private key of the other party
+ **invoiceNumber**
  + The invoice number used to derive the child key
+ **cacheSharedSecret**
  + Optional function to cache shared secrets
+ **retrieveCachedSharedSecret**
  + Optional function to retrieve shared secrets from the cache

#### Method deriveSharedSecret

Derive a shared secret from a public key and a private key for use in symmetric encryption.
This method multiplies the public key (an instance of Point) with a private key.

```ts
deriveSharedSecret(priv: PrivateKey): Point 
```
See also: [Point](./primitives.md#class-point), [PrivateKey](./primitives.md#class-privatekey)

Returns

Returns the Point representing the shared secret.

Argument Details

+ **priv**
  + The private key to use in deriving the shared secret.

Throws

Will throw an error if the public key is not valid for ECDH secret derivation.

Example

```ts
const myPrivKey = new PrivateKey(...)
const sharedSecret = myPubKey.deriveSharedSecret(myPrivKey)
```

#### Method fromDER

Static factory method to create a PublicKey instance from a number array.

```ts
static fromDER(bytes: number[]): PublicKey 
```
See also: [PublicKey](./primitives.md#class-publickey)

Returns

Returns the PublicKey created from the number array.

Argument Details

+ **bytes**
  + A number array representing a public key.

Example

```ts
const myPubKey = PublicKey.fromString("03....")
```

#### Method fromMsgHashAndCompactSignature

Takes an array of numbers or a string and returns a new PublicKey instance.
This method will throw an error if the Compact encoding is invalid.
If a string is provided, it is assumed to represent a hexadecimal sequence.
compactByte value 27-30 means uncompressed public key.
31-34 means compressed public key.
The range represents the recovery param which can be 0,1,2,3.

```ts
static fromMsgHashAndCompactSignature(msgHash: BigNumber, signature: number[] | string, enc?: "hex" | "base64"): PublicKey 
```
See also: [BigNumber](./primitives.md#class-bignumber), [PublicKey](./primitives.md#class-publickey)

Returns

A PublicKey instance derived from the message hash and compact signature.

Argument Details

+ **msgHash**
  + The message hash which was signed.
+ **signature**
  + The signature in compact format.
+ **enc**
  + The encoding of the signature string.

Example

```ts
const publicKey = Signature.fromMsgHashAndCompactSignature(msgHash, 'IMOl2mVKfDgsSsHT4uIYBNN4e...', 'base64');
```

#### Method fromPrivateKey

Static factory method to derive a public key from a private key.
It multiplies the generator point 'g' on the elliptic curve by the private key.

```ts
static fromPrivateKey(key: PrivateKey): PublicKey 
```
See also: [PrivateKey](./primitives.md#class-privatekey), [PublicKey](./primitives.md#class-publickey)

Returns

Returns the PublicKey derived from the given PrivateKey.

Argument Details

+ **key**
  + The private key from which to derive the public key.

Example

```ts
const myPrivKey = new PrivateKey(...)
const myPubKey = PublicKey.fromPrivateKey(myPrivKey)
```

#### Method fromString

Static factory method to create a PublicKey instance from a string.

```ts
static fromString(str: string): PublicKey 
```
See also: [PublicKey](./primitives.md#class-publickey)

Returns

Returns the PublicKey created from the string.

Argument Details

+ **str**
  + A string representing a public key.

Example

```ts
const myPubKey = PublicKey.fromString("03....")
```

#### Method toAddress

Base58Check encodes the hash of the public key with a prefix to indicate locking script type.
Defaults to P2PKH for mainnet, otherwise known as a "Bitcoin Address".

```ts
toAddress(prefix: number[] | string = [0]): string 
```

Returns

Returns the address encoding associated with the hash of the public key.

Argument Details

+ **prefix**
  + defaults to [0x00] for mainnet, set to [0x6f] for testnet or use the strings 'mainnet' or 'testnet'

Example

```ts
const address = pubkey.toAddress()
const address = pubkey.toAddress('mainnet')
const testnetAddress = pubkey.toAddress([0x6f])
const testnetAddress = pubkey.toAddress('testnet')
```

#### Method toDER

Encode the public key to DER (Distinguished Encoding Rules) format.

```ts
toDER(enc?: "hex" | undefined): number[] | string 
```

Returns

Returns the DER-encoded public key in number array or string.

Argument Details

+ **enc**
  + The encoding of the DER string. undefined = number array, 'hex' = hex string.

Example

```ts
const derPublicKey = myPubKey.toDER()
```

#### Method toHash

Hash sha256 and ripemd160 of the public key.

```ts
toHash(enc?: "hex"): number[] | string 
```

Returns

Returns the hash of the public key.

Example

```ts
const publicKeyHash = pubkey.toHash()
```

#### Method verify

Verify a signature of a message using this public key.

```ts
verify(msg: number[] | string, sig: Signature, enc?: "hex" | "utf8"): boolean 
```
See also: [Signature](./primitives.md#class-signature)

Returns

Returns true if the signature is verified successfully, otherwise false.

Argument Details

+ **msg**
  + The message to verify. It can be a string or an array of numbers.
+ **sig**
  + The Signature of the message that needs verification.
+ **enc**
  + The encoding of the message. It defaults to 'utf8'.

Example

```ts
const myMessage = "Hello, world!"
const mySignature = new Signature(...)
const isVerified = myPubKey.verify(myMessage, mySignature)
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: RIPEMD160

An implementation of RIPEMD160 cryptographic hash function. Extends the BaseHash class.
It provides a way to compute a 'digest' for any kind of input data; transforming the data
into a unique output of fixed size. The output is deterministic; it will always be
the same for the same input.

Example

```ts
const ripemd160 = new RIPEMD160();
```

```ts
export class RIPEMD160 extends BaseHash {
    h: number[];
    constructor() 
    _update(msg: number[], start: number): void 
    _digest(): number[] 
    _digestHex(): string 
}
```

#### Property h

Array that is updated iteratively as part of hashing computation.

```ts
h: number[]
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: Reader

```ts
export class Reader {
    public bin: number[];
    public pos: number;
    constructor(bin: number[] = [], pos: number = 0) 
    public eof(): boolean 
    public read(len = this.length): number[] 
    public readReverse(len = this.length): number[] 
    public readUInt8(): number 
    public readInt8(): number 
    public readUInt16BE(): number 
    public readInt16BE(): number 
    public readUInt16LE(): number 
    public readInt16LE(): number 
    public readUInt32BE(): number 
    public readInt32BE(): number 
    public readUInt32LE(): number 
    public readInt32LE(): number 
    public readUInt64BEBn(): BigNumber 
    public readUInt64LEBn(): BigNumber 
    public readInt64LEBn(): BigNumber 
    public readVarIntNum(signed: boolean = true): number 
    public readVarInt(): number[] 
    public readVarIntBn(): BigNumber 
}
```

See also: [BigNumber](./primitives.md#class-bignumber)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: ReductionContext

A base reduction engine that provides several arithmetic operations over
big numbers under a modulus context. It's particularly suitable for
calculations required in cryptography algorithms and encoding schemas.

```ts
export default class ReductionContext {
    prime: Mersenne | null;
    m: BigNumber;
    constructor(m: BigNumber | "k256") 
    verify1(a: BigNumber): void 
    verify2(a: BigNumber, b: BigNumber): void 
    imod(a: BigNumber): BigNumber 
    neg(a: BigNumber): BigNumber 
    add(a: BigNumber, b: BigNumber): BigNumber 
    iadd(a: BigNumber, b: BigNumber): BigNumber 
    sub(a: BigNumber, b: BigNumber): BigNumber 
    isub(a: BigNumber, b: BigNumber): BigNumber 
    shl(a: BigNumber, num: number): BigNumber 
    imul(a: BigNumber, b: BigNumber): BigNumber 
    mul(a: BigNumber, b: BigNumber): BigNumber 
    isqr(a: BigNumber): BigNumber 
    sqr(a: BigNumber): BigNumber 
    sqrt(a: BigNumber): BigNumber 
    invm(a: BigNumber): BigNumber 
    pow(a: BigNumber, num: BigNumber): BigNumber 
    convertTo(num: BigNumber): BigNumber 
    convertFrom(num: BigNumber): BigNumber 
}
```

See also: [BigNumber](./primitives.md#class-bignumber), [Mersenne](./primitives.md#class-mersenne)

#### Constructor

Constructs a new ReductionContext.

```ts
constructor(m: BigNumber | "k256") 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Argument Details

+ **m**
  + A BigNumber representing the modulus, or 'k256' to create a context for Koblitz curve.

Example

```ts
new ReductionContext(new BigNumber(11));
new ReductionContext('k256');
```

#### Property m

The modulus used for reduction operations.

```ts
m: BigNumber
```
See also: [BigNumber](./primitives.md#class-bignumber)

#### Property prime

The prime number utilised in the reduction context, typically an instance of Mersenne class.

```ts
prime: Mersenne | null
```
See also: [Mersenne](./primitives.md#class-mersenne)

#### Method add

Performs the addition operation on two BigNumbers in the reduction context.

```ts
add(a: BigNumber, b: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns the result of 'a + b' in the reduction context.

Argument Details

+ **a**
  + First BigNumber to add.
+ **b**
  + Second BigNumber to add.

Example

```ts
const context = new ReductionContext(new BigNumber(5));
context.add(new BigNumber(2), new BigNumber(4)); // Returns 1
```

#### Method convertFrom

Converts a BigNumber from reduction context to its regular form.

```ts
convertFrom(num: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns the converted BigNumber in its regular form.

Argument Details

+ **num**
  + The BigNumber to convert from the reduction context.

Example

```ts
const context = new ReductionContext(new BigNumber(7));
const a = context.convertTo(new BigNumber(8)); // 'a' is now 1 in the reduction context
context.convertFrom(a); // Returns 1
```

#### Method convertTo

Converts a BigNumber to its equivalent in the reduction context.

```ts
convertTo(num: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns the converted BigNumber compatible with the reduction context.

Argument Details

+ **num**
  + The BigNumber to convert to the reduction context.

Example

```ts
const context = new ReductionContext(new BigNumber(7));
context.convertTo(new BigNumber(8)); // Returns 1 (8 % 7)
```

#### Method iadd

Performs an in-place addition operation on two BigNumbers in the reduction context
in order to avoid creating a new BigNumber, it modifies the first one with the result.

```ts
iadd(a: BigNumber, b: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns the modified 'a' after addition with 'b' in the reduction context.

Argument Details

+ **a**
  + First BigNumber to add.
+ **b**
  + Second BigNumber to add.

Example

```ts
const context = new ReductionContext(new BigNumber(5));
const a = new BigNumber(2);
context.iadd(a, new BigNumber(4)); // Modifies 'a' to be 1
```

#### Method imod

Performs an in-place reduction of the given BigNumber by the modulus of the reduction context, 'm'.

```ts
imod(a: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns the reduced result.

Argument Details

+ **a**
  + BigNumber to be reduced.

Example

```ts
const context = new ReductionContext(new BigNumber(7));
context.imod(new BigNumber(19)); // Returns 5
```

#### Method imul

Performs in-place multiplication of two BigNumbers in the reduction context,
modifying the first BigNumber with the result.

```ts
imul(a: BigNumber, b: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns the modified 'a' after multiplication with 'b' in the reduction context.

Argument Details

+ **a**
  + First BigNumber to multiply.
+ **b**
  + Second BigNumber to multiply.

Example

```ts
const context = new ReductionContext(new BigNumber(7));
const a = new BigNumber(3);
context.imul(a, new BigNumber(2)); // Modifies 'a' to be 6
```

#### Method invm

Calculates the multiplicative inverse of a BigNumber in the reduction context.

```ts
invm(a: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns the multiplicative inverse of 'a' in the reduction context.

Argument Details

+ **a**
  + The BigNumber to find the multiplicative inverse of.

Example

```ts
const context = new ReductionContext(new BigNumber(11));
context.invm(new BigNumber(3)); // Returns 4 (3*4 mod 11 = 1)
```

#### Method isqr

Calculates the square of a BigNumber in the reduction context,
modifying the original BigNumber with the result.

```ts
isqr(a: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns the squared 'a' in the reduction context.

Argument Details

+ **a**
  + BigNumber to be squared.

Example

```ts
const context = new ReductionContext(new BigNumber(7));
const a = new BigNumber(3);
context.isqr(a); // Modifies 'a' to be 2 (9 % 7 = 2)
```

#### Method isub

Performs in-place subtraction of one BigNumber from another in the reduction context,
it modifies the first BigNumber with the result.

```ts
isub(a: BigNumber, b: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns the modified 'a' after subtraction of 'b' in the reduction context.

Argument Details

+ **a**
  + BigNumber to be subtracted from.
+ **b**
  + BigNumber to subtract.

Example

```ts
const context = new ReductionContext(new BigNumber(5));
const a = new BigNumber(4);
context.isub(a, new BigNumber(2)); // Modifies 'a' to be 2
```

#### Method mul

Multiplies two BigNumbers in the reduction context.

```ts
mul(a: BigNumber, b: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns the result of 'a * b' in the reduction context.

Argument Details

+ **a**
  + First BigNumber to multiply.
+ **b**
  + Second BigNumber to multiply.

Example

```ts
const context = new ReductionContext(new BigNumber(7));
context.mul(new BigNumber(3), new BigNumber(2)); // Returns 6
```

#### Method neg

Negates a BigNumber in the context of the modulus.

```ts
neg(a: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns the negation of 'a' in the reduction context.

Argument Details

+ **a**
  + BigNumber to negate.

Example

```ts
const context = new ReductionContext(new BigNumber(7));
context.neg(new BigNumber(3)); // Returns 4
```

#### Method pow

Raises a BigNumber to a power in the reduction context.

```ts
pow(a: BigNumber, num: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns the result of 'a' raised to the power of 'num' in the reduction context.

Argument Details

+ **a**
  + The BigNumber to be raised to a power.
+ **num**
  + The power to raise the BigNumber to.

Example

```ts
const context = new ReductionContext(new BigNumber(7));
context.pow(new BigNumber(3), new BigNumber(2)); // Returns 2 (3^2 % 7)
```

#### Method shl

Performs bitwise shift left operation on a BigNumber in the reduction context.

```ts
shl(a: BigNumber, num: number): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns the result of shifting 'a' left by 'num' positions in the reduction context.

Argument Details

+ **a**
  + BigNumber to perform shift on.
+ **num**
  + The number of positions to shift.

Example

```ts
const context = new ReductionContext(new BigNumber(32));
context.shl(new BigNumber(4), 2); // Returns 16
```

#### Method sqr

Calculates the square of a BigNumber in the reduction context.

```ts
sqr(a: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns the result of 'a^2' in the reduction context.

Argument Details

+ **a**
  + BigNumber to be squared.

Example

```ts
const context = new ReductionContext(new BigNumber(7));
context.sqr(new BigNumber(3)); // Returns 2 (9 % 7 = 2)
```

#### Method sqrt

Calculates the square root of a BigNumber in the reduction context.

```ts
sqrt(a: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns the square root of 'a' in the reduction context.

Argument Details

+ **a**
  + The BigNumber to calculate the square root of.

Example

```ts
const context = new ReductionContext(new BigNumber(9));
context.sqrt(new BigNumber(4)); // Returns 2
```

#### Method sub

Subtracts one BigNumber from another BigNumber in the reduction context.

```ts
sub(a: BigNumber, b: BigNumber): BigNumber 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Returns

Returns the result of 'a - b' in the reduction context.

Argument Details

+ **a**
  + BigNumber to be subtracted from.
+ **b**
  + BigNumber to subtract.

Example

```ts
const context = new ReductionContext(new BigNumber(7));
context.sub(new BigNumber(3), new BigNumber(2)); // Returns 1
```

#### Method verify1

Verifies that a BigNumber is positive and red. Throws an error if these
conditions are not met.

```ts
verify1(a: BigNumber): void 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Argument Details

+ **a**
  + The BigNumber to be verified.

Example

```ts
this.verify1(new BigNumber(10).toRed());
this.verify1(new BigNumber(-10).toRed()); //throws an Error
this.verify1(new BigNumber(10)); //throws an Error
```

#### Method verify2

Verifies that two BigNumbers are both positive and red. Also checks
that they have the same reduction context. Throws an error if these
conditions are not met.

```ts
verify2(a: BigNumber, b: BigNumber): void 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Argument Details

+ **a**
  + The first BigNumber to be verified.
+ **b**
  + The second BigNumber to be verified.

Example

```ts
this.verify2(new BigNumber(10).toRed(this), new BigNumber(20).toRed(this));
this.verify2(new BigNumber(-10).toRed(this), new BigNumber(20).toRed(this)); //throws an Error
this.verify2(new BigNumber(10).toRed(this), new BigNumber(20)); //throws an Error
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: SHA1

An implementation of SHA1 cryptographic hash function. Extends the BaseHash class.
It provides a way to compute a 'digest' for any kind of input data; transforming the data
into a unique output of fixed size. The output is deterministic; it will always be
the same for the same input.

Example

```ts
const sha1 = new SHA1();
```

```ts
export class SHA1 extends BaseHash {
    h: number[];
    W: number[];
    k: number[];
    constructor() 
    _update(msg: number[], start?: number): void 
    _digest(): number[] 
    _digestHex(): string 
}
```

#### Property W

Provides a way to recycle usage of the array memory.

```ts
W: number[]
```

#### Property h

The initial hash constants.

```ts
h: number[]
```

#### Property k

The round constants used for each round of SHA-1.

```ts
k: number[]
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: SHA1HMAC

```ts
export class SHA1HMAC {
    inner: SHA1;
    outer: SHA1;
    blockSize = 64;
    constructor(key: number[] | string) 
    update(msg: number[] | string, enc?: "hex"): SHA1HMAC 
    digest(): number[] 
    digestHex(): string 
}
```

See also: [SHA1](./primitives.md#class-sha1)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: SHA256

An implementation of SHA256 cryptographic hash function. Extends the BaseHash class.
It provides a way to compute a 'digest' for any kind of input data; transforming the data
into a unique output of fixed size. The output is deterministic; it will always be
the same for the same input.

Example

```ts
const sha256 = new SHA256();
```

```ts
export class SHA256 {
    constructor() 
    update(msg: number[] | string, enc?: "hex" | "utf8"): this 
    digest(): number[] 
    digestHex(): string 
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: SHA256HMAC

The `SHA256HMAC` class is used to create Hash-based Message Authentication Code (HMAC) using the SHA-256 cryptographic hash function.

HMAC is a specific type of MAC involving a cryptographic hash function and a secret cryptographic key. It may be used to simultaneously verify both the data integrity and the authenticity of a message.

This class also uses the SHA-256 cryptographic hash algorithm that produces a 256-bit (32-byte) hash value.

```ts
export class SHA256HMAC {
    blockSize = 64;
    outSize = 32;
    constructor(key: number[] | string) 
    update(msg: number[] | string, enc?: "hex"): SHA256HMAC 
    digest(): number[] 
    digestHex(): string 
}
```

#### Constructor

The constructor for the `SHA256HMAC` class.

It initializes the `SHA256HMAC` object and sets up the inner and outer padded keys.
If the key size is larger than the blockSize, it is digested using SHA-256.
If the key size is less than the blockSize, it is padded with zeroes.

```ts
constructor(key: number[] | string) 
```

Argument Details

+ **key**
  + The key to use to create the HMAC. Can be a number array or a string in hexadecimal format.

Example

```ts
const myHMAC = new SHA256HMAC('deadbeef');
```

#### Property blockSize

The block size for the SHA-256 hash function, in bytes. It's set to 64 bytes.

```ts
blockSize = 64
```

#### Property outSize

The output size of the SHA-256 hash function, in bytes. It's set to 32 bytes.

```ts
outSize = 32
```

#### Method digest

Finalizes the HMAC computation and returns the resultant hash.

```ts
digest(): number[] 
```

Returns

Returns the digest of the hashed data. Can be a number array or a string.

Example

```ts
let hashedMessage = myHMAC.digest();
```

#### Method digestHex

Finalizes the HMAC computation and returns the resultant hash as a hex string.

```ts
digestHex(): string 
```

Returns

Returns the digest of the hashed data as a hex string

Example

```ts
let hashedMessage = myHMAC.digestHex();
```

#### Method update

Updates the `SHA256HMAC` object with part of the message to be hashed.

```ts
update(msg: number[] | string, enc?: "hex"): SHA256HMAC 
```
See also: [SHA256HMAC](./primitives.md#class-sha256hmac)

Returns

Returns the instance of `SHA256HMAC` for chaining calls.

Argument Details

+ **msg**
  + Part of the message to hash. Can be a number array or a string.
+ **enc**
  + If 'hex', then the input is encoded as hexadecimal. If undefined or not 'hex', then no encoding is performed.

Example

```ts
myHMAC.update('deadbeef', 'hex');
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: SHA512

An implementation of SHA512 cryptographic hash function. Extends the BaseHash class.
It provides a way to compute a 'digest' for any kind of input data; transforming the data
into a unique output of fixed size. The output is deterministic; it will always be
the same for the same input.

Example

```ts
const sha512 = new SHA512();
```

```ts
export class SHA512 {
    constructor() 
    update(msg: number[] | string, enc?: "hex" | "utf8"): this 
    digest(): number[] 
    digestHex(): string 
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: SHA512HMAC

The `SHA512HMAC` class is used to create Hash-based Message Authentication Code (HMAC) using the SHA-512 cryptographic hash function.

HMAC is a specific type of MAC involving a cryptographic hash function and a secret cryptographic key. It may be used to simultaneously verify both the data integrity and the authenticity of a message.

This class also uses the SHA-512 cryptographic hash algorithm that produces a 512-bit (64-byte) hash value.

```ts
export class SHA512HMAC {
    blockSize = 128;
    outSize = 32;
    constructor(key: number[] | string) 
    update(msg: number[] | string, enc?: "hex" | "utf8"): SHA512HMAC 
    digest(): number[] 
    digestHex(): string 
}
```

#### Constructor

The constructor for the `SHA512HMAC` class.

It initializes the `SHA512HMAC` object and sets up the inner and outer padded keys.
If the key size is larger than the blockSize, it is digested using SHA-512.
If the key size is less than the blockSize, it is padded with zeroes.

```ts
constructor(key: number[] | string) 
```

Argument Details

+ **key**
  + The key to use to create the HMAC. Can be a number array or a string in hexadecimal format.

Example

```ts
const myHMAC = new SHA512HMAC('deadbeef');
```

#### Property blockSize

The block size for the SHA-512 hash function, in bytes. It's set to 128 bytes.

```ts
blockSize = 128
```

#### Property outSize

The output size of the SHA-512 hash function, in bytes. It's set to 64 bytes.

```ts
outSize = 32
```

#### Method digest

Finalizes the HMAC computation and returns the resultant hash.

```ts
digest(): number[] 
```

Returns

Returns the digest of the hashed data as a number array.

Example

```ts
let hashedMessage = myHMAC.digest();
```

#### Method digestHex

Finalizes the HMAC computation and returns the resultant hash as a hex string.

```ts
digestHex(): string 
```

Returns

Returns the digest of the hashed data as a hex string

Example

```ts
let hashedMessage = myHMAC.digestHex();
```

#### Method update

Updates the `SHA512HMAC` object with part of the message to be hashed.

```ts
update(msg: number[] | string, enc?: "hex" | "utf8"): SHA512HMAC 
```
See also: [SHA512HMAC](./primitives.md#class-sha512hmac)

Returns

Returns the instance of `SHA512HMAC` for chaining calls.

Argument Details

+ **msg**
  + Part of the message to hash. Can be a number array or a string.
+ **enc**
  + If 'hex', then the input is encoded as hexadecimal. If undefined or not 'hex', then no encoding is performed.

Example

```ts
myHMAC.update('deadbeef', 'hex');
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: Schnorr

Class representing the Schnorr Zero-Knowledge Proof (ZKP) protocol.

This class provides methods to generate and verify proofs that demonstrate knowledge of a secret without revealing it.
Specifically, it allows one party to prove to another that they know the private key corresponding to a public key
and have correctly computed a shared secret, without disclosing the private key itself.

The protocol involves two main methods:
- `generateProof`: Generates a proof linking a public key `A` and a shared secret `S`, proving knowledge of the corresponding private key `a`.
- `verifyProof`: Verifies the provided proof, ensuring its validity without revealing any secret information.

The class utilizes elliptic curve cryptography (ECC) and the SHA-256 hash function to compute challenges within the proof.

Example

```typescript
const schnorr = new Schnorr();
const a = PrivateKey.fromRandom(); // Prover's private key
const A = a.toPublicKey();         // Prover's public key
const b = PrivateKey.fromRandom(); // Other party's private key
const B = b.toPublicKey();         // Other party's public key
const S = B.mul(a);                // Shared secret

// Prover generates the proof
const proof = schnorr.generateProof(a, A, B, S);

// Verifier verifies the proof
const isValid = schnorr.verifyProof(A.point, B.point, S.point, proof);
console.log(`Proof is valid: ${isValid}`);
```
```ts
export default class Schnorr {
    constructor() 
    generateProof(aArg: PrivateKey, AArg: PublicKey, BArg: PublicKey, S: Point): {
        R: Point;
        SPrime: Point;
        z: BigNumber;
    } 
    verifyProof(A: Point, B: Point, S: Point, proof: {
        R: Point;
        SPrime: Point;
        z: BigNumber;
    }): boolean 
}
```

See also: [BigNumber](./primitives.md#class-bignumber), [Point](./primitives.md#class-point), [PrivateKey](./primitives.md#class-privatekey), [PublicKey](./primitives.md#class-publickey)

#### Method generateProof

Generates a proof that demonstrates the link between public key A and shared secret S

```ts
generateProof(aArg: PrivateKey, AArg: PublicKey, BArg: PublicKey, S: Point): {
    R: Point;
    SPrime: Point;
    z: BigNumber;
} 
```
See also: [BigNumber](./primitives.md#class-bignumber), [Point](./primitives.md#class-point), [PrivateKey](./primitives.md#class-privatekey), [PublicKey](./primitives.md#class-publickey)

Returns

Proof (R, S', z)

Argument Details

+ **a**
  + Private key corresponding to public key A
+ **A**
  + Public key
+ **B**
  + Other party's public key
+ **S**
  + Shared secret

#### Method verifyProof

Verifies the proof of the link between public key A and shared secret S

```ts
verifyProof(A: Point, B: Point, S: Point, proof: {
    R: Point;
    SPrime: Point;
    z: BigNumber;
}): boolean 
```
See also: [BigNumber](./primitives.md#class-bignumber), [Point](./primitives.md#class-point)

Returns

True if the proof is valid, false otherwise

Argument Details

+ **A**
  + Public key
+ **B**
  + Other party's public key
+ **S**
  + Shared secret
+ **proof**
  + Proof (R, S', z)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: Signature

Represents a digital signature.

A digital signature is a mathematical scheme for verifying the authenticity of
digital messages or documents. In many scenarios, it is equivalent to a handwritten signature or stamped seal.
The signature pair (R, S) corresponds to the raw ECDSA ([Elliptic Curve Digital Signature Algorithm](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)) signature.
Signatures are often serialized into a format known as '[DER encoding](https://en.wikipedia.org/wiki/X.690#DER_encoding)' for transmission.

```ts
export default class Signature {
    r: BigNumber;
    s: BigNumber;
    static fromDER(data: number[] | string, enc?: "hex" | "base64"): Signature 
    static fromCompact(data: number[] | string, enc?: "hex" | "base64"): Signature 
    constructor(r: BigNumber, s: BigNumber) 
    verify(msg: number[] | string, key: PublicKey, enc?: "hex"): boolean 
    toString(enc?: "hex" | "base64"): number[] | string 
    toDER(enc?: "hex" | "base64"): number[] | string 
    toCompact(recovery: number, compressed: boolean, enc?: "hex" | "base64"): number[] | string 
    RecoverPublicKey(recovery: number, e: BigNumber): PublicKey 
    CalculateRecoveryFactor(pubkey: PublicKey, msgHash: BigNumber): number 
}
```

See also: [BigNumber](./primitives.md#class-bignumber), [PublicKey](./primitives.md#class-publickey), [verify](./compat.md#variable-verify)

#### Constructor

Creates an instance of the Signature class.

```ts
constructor(r: BigNumber, s: BigNumber) 
```
See also: [BigNumber](./primitives.md#class-bignumber)

Argument Details

+ **r**
  + The R component of the signature.
+ **s**
  + The S component of the signature.

Example

```ts
const r = new BigNumber('208755674028...');
const s = new BigNumber('564745627577...');
const signature = new Signature(r, s);
```

#### Method CalculateRecoveryFactor

Calculates the recovery factor which will work for a particular public key and message hash.
This method will return the recovery factor if it finds a valid recovery factor.
If it does not find a valid recovery factor, it will throw an error.
The recovery factor is a number between 0 and 3.

```ts
CalculateRecoveryFactor(pubkey: PublicKey, msgHash: BigNumber): number 
```
See also: [BigNumber](./primitives.md#class-bignumber), [PublicKey](./primitives.md#class-publickey)

Returns

the recovery factor: number
/

Argument Details

+ **msgHash**
  + The message hash.

Example

```ts
const recovery = signature.CalculateRecoveryFactor(publicKey, msgHash);
```

#### Method RecoverPublicKey

Recovers the public key from a signature.
This method will return the public key if it finds a valid public key.
If it does not find a valid public key, it will throw an error.
The recovery factor is a number between 0 and 3.

```ts
RecoverPublicKey(recovery: number, e: BigNumber): PublicKey 
```
See also: [BigNumber](./primitives.md#class-bignumber), [PublicKey](./primitives.md#class-publickey)

Returns

The public key associated with the signature.

Argument Details

+ **recovery**
  + The recovery factor.
+ **e**
  + The message hash.

Example

```ts
const publicKey = signature.RecoverPublicKey(0, msgHash);
```

#### Method fromCompact

Takes an array of numbers or a string and returns a new Signature instance.
This method will throw an error if the Compact encoding is invalid.
If a string is provided, it is assumed to represent a hexadecimal sequence.
compactByte value 27-30 means uncompressed public key.
31-34 means compressed public key.
The range represents the recovery param which can be 0,1,2,3.
We could support recovery functions in future if there's demand.

```ts
static fromCompact(data: number[] | string, enc?: "hex" | "base64"): Signature 
```
See also: [Signature](./primitives.md#class-signature)

Returns

The decoded data in the form of Signature instance.

Argument Details

+ **data**
  + The sequence to decode from Compact encoding.
+ **enc**
  + The encoding of the data string.

Example

```ts
const signature = Signature.fromCompact('1b18c1f5502f8...', 'hex');
```

#### Method fromDER

Takes an array of numbers or a string and returns a new Signature instance.
This method will throw an error if the DER encoding is invalid.
If a string is provided, it is assumed to represent a hexadecimal sequence.

```ts
static fromDER(data: number[] | string, enc?: "hex" | "base64"): Signature 
```
See also: [Signature](./primitives.md#class-signature)

Returns

The decoded data in the form of Signature instance.

Argument Details

+ **data**
  + The sequence to decode from DER encoding.
+ **enc**
  + The encoding of the data string.

Example

```ts
const signature = Signature.fromDER('30440220018c1f5502f8...', 'hex');
```

#### Method toCompact

Converts an instance of Signature into Compact encoding.

If the encoding parameter is set to 'hex', the function will return a hex string.
If 'base64', it will return a base64 string.
Otherwise, it will return an array of numbers.

```ts
toCompact(recovery: number, compressed: boolean, enc?: "hex" | "base64"): number[] | string 
```

Returns

The current instance in DER encoding.

Argument Details

+ **enc**
  + The encoding to use for the output.

Example

```ts
const compact = signature.toCompact(3, true, 'base64');
```

#### Method toDER

Converts an instance of Signature into DER encoding.

If the encoding parameter is set to 'hex', the function will return a hex string.
If 'base64', it will return a base64 string.
Otherwise, it will return an array of numbers.

```ts
toDER(enc?: "hex" | "base64"): number[] | string 
```

Returns

The current instance in DER encoding.

Argument Details

+ **enc**
  + The encoding to use for the output.

Example

```ts
const der = signature.toDER('hex');
```

#### Method toString

function toString() { [native code] }

Converts an instance of Signature into DER encoding.
An alias for the toDER method.

If the encoding parameter is set to 'hex', the function will return a hex string.
If 'base64', it will return a base64 string.
Otherwise, it will return an array of numbers.

```ts
toString(enc?: "hex" | "base64"): number[] | string 
```

Returns

The current instance in DER encoding.

Argument Details

+ **enc**
  + The encoding to use for the output.

Example

```ts
const der = signature.toString('base64');
```

#### Method verify

Verifies a digital signature.

This method will return true if the signature, key, and message hash match.
If the data or key do not match the signature, the function returns false.

```ts
verify(msg: number[] | string, key: PublicKey, enc?: "hex"): boolean 
```
See also: [PublicKey](./primitives.md#class-publickey)

Returns

A boolean representing whether the signature is valid.

Argument Details

+ **msg**
  + The message to verify.
+ **key**
  + The public key used to sign the original message.
+ **enc**
  + The encoding of the msg string.

Example

```ts
const msg = 'The quick brown fox jumps over the lazy dog';
const publicKey = PublicKey.fromString('04188ca1050...');
const isVerified = signature.verify(msg, publicKey);
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: SymmetricKey

`SymmetricKey` is a class that extends the `BigNumber` class and implements symmetric encryption and decryption methods.
Symmetric-Key encryption is a form of encryption where the same key is used to encrypt and decrypt the message.
It leverages the Advanced Encryption Standard Galois/Counter Mode (AES-GCM) for encryption and decryption of messages.

```ts
export default class SymmetricKey extends BigNumber {
    static fromRandom(): SymmetricKey 
    encrypt(msg: number[] | string, enc?: "hex"): string | number[] 
    decrypt(msg: number[] | string, enc?: "hex" | "utf8"): string | number[] 
}
```

See also: [BigNumber](./primitives.md#class-bignumber), [decrypt](./messages.md#variable-decrypt), [encrypt](./messages.md#variable-encrypt)

#### Method decrypt

Decrypts a given AES-GCM encrypted message using the same key that was used for encryption.
The method extracts the IV and the authentication tag from the encrypted message, then attempts to decrypt it.
If the decryption fails (e.g., due to message tampering), an error is thrown.

```ts
decrypt(msg: number[] | string, enc?: "hex" | "utf8"): string | number[] 
```

Returns

Returns the decrypted message as a string or an array of numbers, depending on `enc` argument. If absent, an array of numbers is returned.

Argument Details

+ **msg**
  + The encrypted message to be decrypted. It can be a string or an array of numbers.
+ **enc**
  + optional. The encoding of the message (if no encoding is provided, uses utf8 for strings, unless specified as hex).

Throws

Will throw an error if the decryption fails, likely due to message tampering or incorrect decryption key.

Example

```ts
const key = new SymmetricKey(1234);
const decryptedMessage = key.decrypt(encryptedMessage, 'utf8');
```

#### Method encrypt

Encrypts a given message using AES-GCM encryption.
The generated Initialization Vector (IV) is attached to the encrypted message for decryption purposes.
The OpenSSL format of |IV|encryptedContent|authTag| is used.

```ts
encrypt(msg: number[] | string, enc?: "hex"): string | number[] 
```

Returns

Returns the encrypted message as a string or an array of numbers, depending on `enc` argument.

Argument Details

+ **msg**
  + The message to be encrypted. It can be a string or an array of numbers.
+ **enc**
  + optional. The encoding of the message. If hex, the string is assumed to be hex, UTF-8 otherwise.

Example

```ts
const key = new SymmetricKey(1234);
const encryptedMessage = key.encrypt('plainText', 'utf8');
```

#### Method fromRandom

Generates a symmetric key randomly.

```ts
static fromRandom(): SymmetricKey 
```
See also: [SymmetricKey](./primitives.md#class-symmetrickey)

Returns

The newly generated Symmetric Key.

Example

```ts
const symmetricKey = SymmetricKey.fromRandom();
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: TransactionSignature

```ts
export default class TransactionSignature extends Signature {
    public static readonly SIGHASH_ALL = 1;
    public static readonly SIGHASH_NONE = 2;
    public static readonly SIGHASH_SINGLE = 3;
    public static readonly SIGHASH_FORKID = 64;
    public static readonly SIGHASH_ANYONECANPAY = 128;
    scope: number;
    static format(params: {
        sourceTXID: string;
        sourceOutputIndex: number;
        sourceSatoshis: number;
        transactionVersion: number;
        otherInputs: TransactionInput[];
        outputs: TransactionOutput[];
        inputIndex: number;
        subscript: Script;
        inputSequence: number;
        lockTime: number;
        scope: number;
    }): number[] 
    static fromChecksigFormat(buf: number[]): TransactionSignature 
    constructor(r: BigNumber, s: BigNumber, scope: number) 
    public hasLowS(): boolean 
    toChecksigFormat(): number[] 
}
```

See also: [BigNumber](./primitives.md#class-bignumber), [Script](./script.md#class-script), [Signature](./primitives.md#class-signature), [TransactionInput](./transaction.md#interface-transactioninput), [TransactionOutput](./transaction.md#interface-transactionoutput)

#### Method hasLowS

Compares to bitcoind's IsLowDERSignature
See also Ecdsa signature algorithm which enforces this.
See also Bip 62, "low S values in signatures"

```ts
public hasLowS(): boolean 
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: Writer

```ts
export class Writer {
    public bufs: number[][];
    constructor(bufs?: number[][]) 
    getLength(): number 
    toArray(): number[] 
    write(buf: number[]): this 
    writeReverse(buf: number[]): this 
    writeUInt8(n: number): this 
    writeInt8(n: number): this 
    writeUInt16BE(n: number): this 
    writeInt16BE(n: number): this 
    writeUInt16LE(n: number): this 
    writeInt16LE(n: number): this 
    writeUInt32BE(n: number): this 
    writeInt32BE(n: number): this 
    writeUInt32LE(n: number): this 
    writeInt32LE(n: number): this 
    writeUInt64BEBn(bn: BigNumber): this 
    writeUInt64LEBn(bn: BigNumber): this 
    writeUInt64LE(n: number): this 
    writeVarIntNum(n: number): this 
    writeVarIntBn(bn: BigNumber): this 
    static varIntNum(n: number): number[] 
    static varIntBn(bn: BigNumber): number[] 
}
```

See also: [BigNumber](./primitives.md#class-bignumber), [toArray](./primitives.md#variable-toarray)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Functions

| |
| --- |
| [AES](#function-aes) |
| [AESGCM](#function-aesgcm) |
| [AESGCMDecrypt](#function-aesgcmdecrypt) |
| [ghash](#function-ghash) |
| [pbkdf2](#function-pbkdf2) |
| [red](#function-red) |
| [toArray](#function-toarray) |
| [toBase64](#function-tobase64) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Function: AES

```ts
export function AES(input: number[], key: number[]): number[] 
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: AESGCM

```ts
export function AESGCM(plainText: number[], additionalAuthenticatedData: number[], initializationVector: number[], key: number[]): {
    result: number[];
    authenticationTag: number[];
} 
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: AESGCMDecrypt

```ts
export function AESGCMDecrypt(cipherText: number[], additionalAuthenticatedData: number[], initializationVector: number[], authenticationTag: number[], key: number[]): number[] | null 
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: ghash

```ts
export function ghash(input: number[], hashSubKey: number[]): number[] 
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: pbkdf2

Limited SHA-512-only PBKDF2 function for use in deprecated BIP39 code.

```ts
export function pbkdf2(password: number[], salt: number[], iterations: number, keylen: number, digest = "sha512"): number[] 
```

Returns

The computed key

Argument Details

+ **password**
  + The PBKDF2 password
+ **salt**
  + The PBKDF2 salt
+ **iterations**
  + The number of of iterations to run
+ **keylen**
  + The length of the key
+ **digest**
  + The digest (must be sha512 for this implementation)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: red

```ts
export function red(x: bigint): bigint 
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: toArray

```ts
export function toArray(msg: number[] | string, enc?: "hex" | "utf8"): number[] 
```

Returns

array of byte values from msg. If msg is an array, a copy is returned.

Argument Details

+ **enc**
  + Optional. Encoding to use if msg is string. Default is 'utf8'.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: toBase64

Converts an array of bytes (each between 0 and 255) into a base64 encoded string.

Example

```ts
const bytes = [72, 101, 108, 108, 111]; // Represents the string "Hello"
console.log(toBase64(bytes)); // Outputs: SGVsbG8=
```

```ts
export function toBase64(byteArray: number[]): string 
```

Returns

The base64 encoded string.

Argument Details

+ **byteArray**
  + An array of numbers where each number is a byte (0-255).

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Types

## Enums

## Variables

| | | |
| --- | --- | --- |
| [BI_EIGHT](#variable-bi_eight) | [biModSqrt](#variable-bimodsqrt) | [multiply](#variable-multiply) |
| [BI_FOUR](#variable-bi_four) | [biModSub](#variable-bimodsub) | [rightShift](#variable-rightshift) |
| [BI_ONE](#variable-bi_one) | [checkBit](#variable-checkbit) | [ripemd160](#variable-ripemd160) |
| [BI_THREE](#variable-bi_three) | [encode](#variable-encode) | [scalarMultiplyWNAF](#variable-scalarmultiplywnaf) |
| [BI_TWO](#variable-bi_two) | [exclusiveOR](#variable-exclusiveor) | [sha1](#variable-sha1) |
| [BI_ZERO](#variable-bi_zero) | [fromBase58](#variable-frombase58) | [sha256](#variable-sha256) |
| [GX_BIGINT](#variable-gx_bigint) | [fromBase58Check](#variable-frombase58check) | [sha256hmac](#variable-sha256hmac) |
| [GY_BIGINT](#variable-gy_bigint) | [getBytes](#variable-getbytes) | [sha512](#variable-sha512) |
| [MASK_256](#variable-mask_256) | [hash160](#variable-hash160) | [sha512hmac](#variable-sha512hmac) |
| [N_BIGINT](#variable-n_bigint) | [hash256](#variable-hash256) | [sign](#variable-sign) |
| [P_BIGINT](#variable-p_bigint) | [incrementLeastSignificantThirtyTwoBits](#variable-incrementleastsignificantthirtytwobits) | [toArray](#variable-toarray) |
| [P_PLUS1_DIV4](#variable-p_plus1_div4) | [jpAdd](#variable-jpadd) | [toBase58](#variable-tobase58) |
| [biMod](#variable-bimod) | [jpDouble](#variable-jpdouble) | [toBase58Check](#variable-tobase58check) |
| [biModAdd](#variable-bimodadd) | [jpNeg](#variable-jpneg) | [toHex](#variable-tohex) |
| [biModInv](#variable-bimodinv) | [minimallyEncode](#variable-minimallyencode) | [toUTF8](#variable-toutf8) |
| [biModMul](#variable-bimodmul) | [modInvN](#variable-modinvn) | [verify](#variable-verify) |
| [biModPow](#variable-bimodpow) | [modMulN](#variable-modmuln) | [zero2](#variable-zero2) |
| [biModSqr](#variable-bimodsqr) | [modN](#variable-modn) |  |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Variable: BI_EIGHT

```ts
BI_EIGHT = 8n
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: BI_FOUR

```ts
BI_FOUR = 4n
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: BI_ONE

```ts
BI_ONE = 1n
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: BI_THREE

```ts
BI_THREE = 3n
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: BI_TWO

```ts
BI_TWO = 2n
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: BI_ZERO

```ts
BI_ZERO = 0n
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: GX_BIGINT

```ts
GX_BIGINT = BigInt("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: GY_BIGINT

```ts
GY_BIGINT = BigInt("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: MASK_256

```ts
MASK_256 = (1n << 256n) - 1n
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: N_BIGINT

```ts
N_BIGINT = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: P_BIGINT

```ts
P_BIGINT = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: P_PLUS1_DIV4

```ts
P_PLUS1_DIV4 = (P_BIGINT + 1n) >> 2n
```

See also: [P_BIGINT](./primitives.md#variable-p_bigint)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: biMod

```ts
biMod = (a: bigint): bigint => red((a % P_BIGINT + P_BIGINT) % P_BIGINT)
```

See also: [P_BIGINT](./primitives.md#variable-p_bigint), [red](./primitives.md#function-red)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: biModAdd

```ts
biModAdd = (a: bigint, b: bigint): bigint => red(a + b)
```

See also: [red](./primitives.md#function-red)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: biModInv

```ts
biModInv = (a: bigint): bigint => {
    let lm = BI_ONE;
    let hm = BI_ZERO;
    let low = biMod(a);
    let high = P_BIGINT;
    while (low > BI_ONE) {
        const r = high / low;
        [lm, hm] = [hm - lm * r, lm];
        [low, high] = [high - low * r, low];
    }
    return biMod(lm);
}
```

See also: [BI_ONE](./primitives.md#variable-bi_one), [BI_ZERO](./primitives.md#variable-bi_zero), [P_BIGINT](./primitives.md#variable-p_bigint), [biMod](./primitives.md#variable-bimod)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: biModMul

```ts
biModMul = (a: bigint, b: bigint): bigint => red(a * b)
```

See also: [red](./primitives.md#function-red)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: biModPow

```ts
biModPow = (base: bigint, exp: bigint): bigint => {
    let result = BI_ONE;
    base = biMod(base);
    let e = exp;
    while (e > BI_ZERO) {
        if ((e & BI_ONE) === BI_ONE)
            result = biModMul(result, base);
        base = biModMul(base, base);
        e >>= BI_ONE;
    }
    return result;
}
```

See also: [BI_ONE](./primitives.md#variable-bi_one), [BI_ZERO](./primitives.md#variable-bi_zero), [biMod](./primitives.md#variable-bimod), [biModMul](./primitives.md#variable-bimodmul)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: biModSqr

```ts
biModSqr = (a: bigint): bigint => biModMul(a, a)
```

See also: [biModMul](./primitives.md#variable-bimodmul)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: biModSqrt

```ts
biModSqrt = (a: bigint): bigint | null => {
    const r = biModPow(a, P_PLUS1_DIV4);
    return biModMul(r, r) === biMod(a) ? r : null;
}
```

See also: [P_PLUS1_DIV4](./primitives.md#variable-p_plus1_div4), [biMod](./primitives.md#variable-bimod), [biModMul](./primitives.md#variable-bimodmul), [biModPow](./primitives.md#variable-bimodpow)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: biModSub

```ts
biModSub = (a: bigint, b: bigint): bigint => (a >= b ? a - b : P_BIGINT - (b - a))
```

See also: [P_BIGINT](./primitives.md#variable-p_bigint)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: checkBit

```ts
checkBit = function (byteArray: number[], byteIndex: number, bitIndex: number): 1 | 0 {
    return (byteArray[byteIndex] & (1 << bitIndex)) !== 0 ? 1 : 0;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: encode

```ts
encode = (arr: number[], enc?: "hex" | "utf8"): string | number[] => {
    switch (enc) {
        case "hex":
            return toHex(arr);
        case "utf8":
            return toUTF8(arr);
        default:
            return arr;
    }
}
```

See also: [toHex](./primitives.md#variable-tohex), [toUTF8](./primitives.md#variable-toutf8)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: exclusiveOR

```ts
exclusiveOR = function (block0: number[], block1: number[]): number[] {
    const len = block0.length;
    const result = new Array(len);
    for (let i = 0; i < len; i++) {
        result[i] = block0[i] ^ block1[i];
    }
    return result;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: fromBase58

```ts
fromBase58 = (str: string): number[] => {
    if (str === "" || typeof str !== "string") {
        throw new Error(`Expected base58 string but got “${str}”`);
    }
    const match: string[] | null = str.match(/[IOl0]/gmu);
    if (match !== null) {
        throw new Error(`Invalid base58 character “${match.join("")}”`);
    }
    const lz = str.match(/^1+/gmu);
    const psz: number = (lz !== null) ? lz[0].length : 0;
    const size = ((str.length - psz) * (Math.log(58) / Math.log(256)) + 1) >>> 0;
    const uint8 = new Uint8Array([
        ...new Uint8Array(psz),
        ...(str.match(/./gmu) ?? [])
            .map((i) => base58chars.indexOf(i))
            .reduce((acc, i) => {
            acc = acc.map((j) => {
                const x = j * 58 + i;
                i = x >> 8;
                return x;
            });
            return acc;
        }, new Uint8Array(size))
            .reverse()
            .filter(((lastValue) => (value) => (lastValue = lastValue || value))(false))
    ]);
    return [...uint8];
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: fromBase58Check

```ts
fromBase58Check = (str: string, enc?: "hex", prefixLength: number = 1): {
    data: number[] | string;
    prefix: number[] | string;
} => {
    const bin = fromBase58(str);
    let prefix: string | number[] = bin.slice(0, prefixLength);
    let data: string | number[] = bin.slice(prefixLength, -4);
    let hash = [...prefix, ...data];
    hash = hash256(hash);
    bin.slice(-4).forEach((check, index) => {
        if (check !== hash[index]) {
            throw new Error("Invalid checksum");
        }
    });
    if (enc === "hex") {
        prefix = toHex(prefix);
        data = toHex(data);
    }
    return { prefix, data };
}
```

See also: [fromBase58](./primitives.md#variable-frombase58), [hash256](./primitives.md#variable-hash256), [toHex](./primitives.md#variable-tohex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: getBytes

```ts
getBytes = function (numericValue: number): number[] {
    return [
        (numericValue & 4278190080) >>> 24,
        (numericValue & 16711680) >> 16,
        (numericValue & 65280) >> 8,
        numericValue & 255
    ];
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: hash160

```ts
hash160 = (msg: number[] | string, enc?: "hex" | "utf8"): number[] => {
    const first = new SHA256().update(msg, enc).digest();
    return new RIPEMD160().update(first).digest();
}
```

See also: [RIPEMD160](./primitives.md#class-ripemd160), [SHA256](./primitives.md#class-sha256)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: hash256

```ts
hash256 = (msg: number[] | string, enc?: "hex" | "utf8"): number[] => {
    const first = new SHA256().update(msg, enc).digest();
    return new SHA256().update(first).digest();
}
```

See also: [SHA256](./primitives.md#class-sha256)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: incrementLeastSignificantThirtyTwoBits

```ts
incrementLeastSignificantThirtyTwoBits = function (block: number[]): number[] {
    let i;
    const result = block.slice();
    for (i = 15; i !== 11; i--) {
        result[i] = result[i] + 1;
        if (result[i] === 256) {
            result[i] = 0;
        }
        else {
            break;
        }
    }
    return result;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: jpAdd

```ts
jpAdd = (P: JacobianPointBI, Q: JacobianPointBI): JacobianPointBI => {
    if (P.Z === BI_ZERO)
        return Q;
    if (Q.Z === BI_ZERO)
        return P;
    const Z1Z1 = biModMul(P.Z, P.Z);
    const Z2Z2 = biModMul(Q.Z, Q.Z);
    const U1 = biModMul(P.X, Z2Z2);
    const U2 = biModMul(Q.X, Z1Z1);
    const S1 = biModMul(P.Y, biModMul(Z2Z2, Q.Z));
    const S2 = biModMul(Q.Y, biModMul(Z1Z1, P.Z));
    const H = biModSub(U2, U1);
    const r = biModSub(S2, S1);
    if (H === BI_ZERO) {
        if (r === BI_ZERO)
            return jpDouble(P);
        return { X: BI_ZERO, Y: BI_ONE, Z: BI_ZERO };
    }
    const HH = biModMul(H, H);
    const HHH = biModMul(H, HH);
    const V = biModMul(U1, HH);
    const X3 = biModSub(biModSub(biModMul(r, r), HHH), biModMul(BI_TWO, V));
    const Y3 = biModSub(biModMul(r, biModSub(V, X3)), biModMul(S1, HHH));
    const Z3 = biModMul(H, biModMul(P.Z, Q.Z));
    return { X: X3, Y: Y3, Z: Z3 };
}
```

See also: [BI_ONE](./primitives.md#variable-bi_one), [BI_TWO](./primitives.md#variable-bi_two), [BI_ZERO](./primitives.md#variable-bi_zero), [JacobianPointBI](./primitives.md#interface-jacobianpointbi), [biModMul](./primitives.md#variable-bimodmul), [biModSub](./primitives.md#variable-bimodsub), [jpDouble](./primitives.md#variable-jpdouble)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: jpDouble

```ts
jpDouble = (P: JacobianPointBI): JacobianPointBI => {
    const { X: X1, Y: Y1, Z: Z1 } = P;
    if (Y1 === BI_ZERO)
        return { X: BI_ZERO, Y: BI_ONE, Z: BI_ZERO };
    const Y1sq = biModMul(Y1, Y1);
    const S = biModMul(BI_FOUR, biModMul(X1, Y1sq));
    const M = biModMul(BI_THREE, biModMul(X1, X1));
    const X3 = biModSub(biModMul(M, M), biModMul(BI_TWO, S));
    const Y3 = biModSub(biModMul(M, biModSub(S, X3)), biModMul(BI_EIGHT, biModMul(Y1sq, Y1sq)));
    const Z3 = biModMul(BI_TWO, biModMul(Y1, Z1));
    return { X: X3, Y: Y3, Z: Z3 };
}
```

See also: [BI_EIGHT](./primitives.md#variable-bi_eight), [BI_FOUR](./primitives.md#variable-bi_four), [BI_ONE](./primitives.md#variable-bi_one), [BI_THREE](./primitives.md#variable-bi_three), [BI_TWO](./primitives.md#variable-bi_two), [BI_ZERO](./primitives.md#variable-bi_zero), [JacobianPointBI](./primitives.md#interface-jacobianpointbi), [biModMul](./primitives.md#variable-bimodmul), [biModSub](./primitives.md#variable-bimodsub)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: jpNeg

```ts
jpNeg = (P: JacobianPointBI): JacobianPointBI => {
    if (P.Z === BI_ZERO)
        return P;
    return { X: P.X, Y: P_BIGINT - P.Y, Z: P.Z };
}
```

See also: [BI_ZERO](./primitives.md#variable-bi_zero), [JacobianPointBI](./primitives.md#interface-jacobianpointbi), [P_BIGINT](./primitives.md#variable-p_bigint)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: minimallyEncode

```ts
minimallyEncode = (buf: number[]): number[] => {
    if (buf.length === 0) {
        return buf;
    }
    const last = buf[buf.length - 1];
    if ((last & 127) !== 0) {
        return buf;
    }
    if (buf.length === 1) {
        return [];
    }
    if ((buf[buf.length - 2] & 128) !== 0) {
        return buf;
    }
    for (let i = buf.length - 1; i > 0; i--) {
        if (buf[i - 1] !== 0) {
            if ((buf[i - 1] & 128) !== 0) {
                buf[i] = last;
                return buf.slice(0, i + 1);
            }
            else {
                buf[i - 1] |= last;
                return buf.slice(0, i);
            }
        }
    }
    return [];
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: modInvN

```ts
modInvN = (a: bigint): bigint => {
    let lm = 1n;
    let hm = 0n;
    let low = modN(a);
    let high = N_BIGINT;
    while (low > 1n) {
        const q = high / low;
        [lm, hm] = [hm - lm * q, lm];
        [low, high] = [high - low * q, low];
    }
    return modN(lm);
}
```

See also: [N_BIGINT](./primitives.md#variable-n_bigint), [modN](./primitives.md#variable-modn)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: modMulN

```ts
modMulN = (a: bigint, b: bigint): bigint => modN(a * b)
```

See also: [modN](./primitives.md#variable-modn)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: modN

```ts
modN = (a: bigint): bigint => {
    let r = a % N_BIGINT;
    if (r < 0n)
        r += N_BIGINT;
    return r;
}
```

See also: [N_BIGINT](./primitives.md#variable-n_bigint)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: multiply

```ts
multiply = function (block0: number[], block1: number[]): number[] {
    const v = block1.slice();
    const z = createZeroBlock(16);
    for (let i = 0; i < 16; i++) {
        for (let j = 7; j >= 0; j--) {
            if ((block0[i] & (1 << j)) !== 0) {
                xorInto(z, v);
            }
            if ((v[15] & 1) !== 0) {
                rightShift(v);
                xorInto(v, R);
            }
            else {
                rightShift(v);
            }
        }
    }
    return z;
}
```

See also: [rightShift](./primitives.md#variable-rightshift)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: rightShift

```ts
rightShift = function (block: number[]): number[] {
    let i: number;
    let carry = 0;
    let oldCarry = 0;
    for (i = 0; i < block.length; i++) {
        oldCarry = carry;
        carry = block[i] & 1;
        block[i] = block[i] >> 1;
        if (oldCarry !== 0) {
            block[i] = block[i] | 128;
        }
    }
    return block;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: ripemd160

```ts
ripemd160 = (msg: number[] | string, enc?: "hex" | "utf8"): number[] => {
    return new RIPEMD160().update(msg, enc).digest();
}
```

See also: [RIPEMD160](./primitives.md#class-ripemd160)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: scalarMultiplyWNAF

```ts
scalarMultiplyWNAF = (k: bigint, P0: {
    x: bigint;
    y: bigint;
}, window: number = 5): JacobianPointBI => {
    const key = `${window}:${P0.x.toString(16)}:${P0.y.toString(16)}`;
    let tbl = WNAF_TABLE_CACHE.get(key);
    let P: JacobianPointBI;
    if (tbl === undefined) {
        const tblSize = 1 << (window - 1);
        tbl = new Array(tblSize);
        P = { X: P0.x, Y: P0.y, Z: BI_ONE };
        tbl[0] = P;
        const twoP = jpDouble(P);
        for (let i = 1; i < tblSize; i++) {
            tbl[i] = jpAdd(tbl[i - 1], twoP);
        }
        WNAF_TABLE_CACHE.set(key, tbl);
    }
    else {
        P = tbl[0];
    }
    const wnaf: number[] = [];
    const wBig = 1n << BigInt(window);
    const wHalf = wBig >> 1n;
    let kTmp = k;
    while (kTmp > 0n) {
        if ((kTmp & BI_ONE) === BI_ZERO) {
            wnaf.push(0);
            kTmp >>= BI_ONE;
        }
        else {
            let z = kTmp & (wBig - 1n);
            if (z > wHalf)
                z -= wBig;
            wnaf.push(Number(z));
            kTmp -= z;
            kTmp >>= BI_ONE;
        }
    }
    let Q: JacobianPointBI = { X: BI_ZERO, Y: BI_ONE, Z: BI_ZERO };
    for (let i = wnaf.length - 1; i >= 0; i--) {
        Q = jpDouble(Q);
        const di = wnaf[i];
        if (di !== 0) {
            const idx = Math.abs(di) >> 1;
            const addend = di > 0 ? tbl[idx] : jpNeg(tbl[idx]);
            Q = jpAdd(Q, addend);
        }
    }
    return Q;
}
```

See also: [BI_ONE](./primitives.md#variable-bi_one), [BI_ZERO](./primitives.md#variable-bi_zero), [JacobianPointBI](./primitives.md#interface-jacobianpointbi), [jpAdd](./primitives.md#variable-jpadd), [jpDouble](./primitives.md#variable-jpdouble), [jpNeg](./primitives.md#variable-jpneg)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: sha1

```ts
sha1 = (msg: number[] | string, enc?: "hex" | "utf8"): number[] => {
    return new SHA1().update(msg, enc).digest();
}
```

See also: [SHA1](./primitives.md#class-sha1)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: sha256

```ts
sha256 = (msg: number[] | string, enc?: "hex" | "utf8"): number[] => {
    return new SHA256().update(msg, enc).digest();
}
```

See also: [SHA256](./primitives.md#class-sha256)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: sha256hmac

```ts
sha256hmac = (key: number[] | string, msg: number[] | string, enc?: "hex"): number[] => {
    return new SHA256HMAC(key).update(msg, enc).digest();
}
```

See also: [SHA256HMAC](./primitives.md#class-sha256hmac)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: sha512

```ts
sha512 = (msg: number[] | string, enc?: "hex" | "utf8"): number[] => {
    return new SHA512().update(msg, enc).digest();
}
```

See also: [SHA512](./primitives.md#class-sha512)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: sha512hmac

```ts
sha512hmac = (key: number[] | string, msg: number[] | string, enc?: "hex"): number[] => {
    return new SHA512HMAC(key).update(msg, enc).digest();
}
```

See also: [SHA512HMAC](./primitives.md#class-sha512hmac)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: sign

```ts
sign = (msg: BigNumber, key: BigNumber, forceLowS: boolean = false, customK?: BigNumber | ((iter: number) => BigNumber)): Signature => {
    msg = truncateToN(msg);
    const msgBig = BigInt("0x" + msg.toString(16));
    const keyBig = BigInt("0x" + key.toString(16));
    const bkey = key.toArray("be", bytes);
    const nonce = msg.toArray("be", bytes);
    const drbg = new DRBG(bkey, nonce);
    for (let iter = 0;; iter++) {
        let kBN = typeof customK === "function"
            ? customK(iter)
            : BigNumber.isBN(customK)
                ? customK
                : new BigNumber(drbg.generate(bytes), 16);
        if (kBN == null)
            throw new Error("k is undefined");
        kBN = truncateToN(kBN, true);
        if (kBN.cmpn(1) <= 0 || kBN.cmp(ns1) >= 0) {
            if (BigNumber.isBN(customK)) {
                throw new Error("Invalid fixed custom K value (must be >1 and <N\u20111)");
            }
            continue;
        }
        const kBig = BigInt("0x" + kBN.toString(16));
        const R = scalarMultiplyWNAF(kBig, { x: GX_BIGINT, y: GY_BIGINT });
        if (R.Z === 0n) {
            if (BigNumber.isBN(customK)) {
                throw new Error("Invalid fixed custom K value (k\u00B7G at infinity)");
            }
            continue;
        }
        const zInv = biModInv(R.Z);
        const zInv2 = biModMul(zInv, zInv);
        const xAff = biModMul(R.X, zInv2);
        const rBig = modN(xAff);
        if (rBig === 0n) {
            if (BigNumber.isBN(customK)) {
                throw new Error("Invalid fixed custom K value (r == 0)");
            }
            continue;
        }
        const kInv = modInvN(kBig);
        const rTimesKey = modMulN(rBig, keyBig);
        const sum = modN(msgBig + rTimesKey);
        let sBig = modMulN(kInv, sum);
        if (sBig === 0n) {
            if (BigNumber.isBN(customK)) {
                throw new Error("Invalid fixed custom K value (s == 0)");
            }
            continue;
        }
        if (forceLowS && sBig > halfN) {
            sBig = N_BIGINT - sBig;
        }
        const r = new BigNumber(rBig.toString(16), 16);
        const s = new BigNumber(sBig.toString(16), 16);
        return new Signature(r, s);
    }
}
```

See also: [BigNumber](./primitives.md#class-bignumber), [DRBG](./primitives.md#class-drbg), [GX_BIGINT](./primitives.md#variable-gx_bigint), [GY_BIGINT](./primitives.md#variable-gy_bigint), [N_BIGINT](./primitives.md#variable-n_bigint), [Signature](./primitives.md#class-signature), [biModInv](./primitives.md#variable-bimodinv), [biModMul](./primitives.md#variable-bimodmul), [modInvN](./primitives.md#variable-modinvn), [modMulN](./primitives.md#variable-modmuln), [modN](./primitives.md#variable-modn), [scalarMultiplyWNAF](./primitives.md#variable-scalarmultiplywnaf), [toArray](./primitives.md#variable-toarray)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: toArray

```ts
toArray = (msg: any, enc?: "hex" | "utf8" | "base64"): any[] => {
    if (Array.isArray(msg))
        return msg.slice();
    if (msg === undefined)
        return [];
    if (typeof msg !== "string") {
        return Array.from(msg, (item: any) => item | 0);
    }
    switch (enc) {
        case "hex":
            return hexToArray(msg);
        case "base64":
            return base64ToArray(msg);
        default:
            return utf8ToArray(msg);
    }
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: toBase58

```ts
toBase58 = (bin: number[]): string => {
    const base58Map = Array(256).fill(-1);
    for (let i = 0; i < base58chars.length; ++i) {
        base58Map[base58chars.charCodeAt(i)] = i;
    }
    const result: number[] = [];
    for (const byte of bin) {
        let carry = byte;
        for (let j = 0; j < result.length; ++j) {
            const x = (base58Map[result[j]] << 8) + carry;
            result[j] = base58chars.charCodeAt(x % 58);
            carry = (x / 58) | 0;
        }
        while (carry !== 0) {
            result.push(base58chars.charCodeAt(carry % 58));
            carry = (carry / 58) | 0;
        }
    }
    for (const byte of bin) {
        if (byte !== 0)
            break;
        else
            result.push("1".charCodeAt(0));
    }
    result.reverse();
    return String.fromCharCode(...result);
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: toBase58Check

```ts
toBase58Check = (bin: number[], prefix: number[] = [0]): string => {
    let hash = hash256([...prefix, ...bin]);
    hash = [...prefix, ...bin, ...hash.slice(0, 4)];
    return toBase58(hash);
}
```

See also: [hash256](./primitives.md#variable-hash256), [toBase58](./primitives.md#variable-tobase58)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: toHex

```ts
toHex = (msg: number[]): string => {
    let res = "";
    for (const num of msg) {
        res += zero2(num.toString(16));
    }
    return res;
}
```

See also: [zero2](./primitives.md#variable-zero2)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: toUTF8

```ts
toUTF8 = (arr: number[]): string => {
    let result = "";
    let skip = 0;
    for (let i = 0; i < arr.length; i++) {
        const byte = arr[i];
        if (skip > 0) {
            skip--;
            continue;
        }
        if (byte <= 127) {
            result += String.fromCharCode(byte);
        }
        else if (byte >= 192 && byte <= 223) {
            const byte2 = arr[i + 1];
            skip = 1;
            const codePoint = ((byte & 31) << 6) | (byte2 & 63);
            result += String.fromCharCode(codePoint);
        }
        else if (byte >= 224 && byte <= 239) {
            const byte2 = arr[i + 1];
            const byte3 = arr[i + 2];
            skip = 2;
            const codePoint = ((byte & 15) << 12) | ((byte2 & 63) << 6) | (byte3 & 63);
            result += String.fromCharCode(codePoint);
        }
        else if (byte >= 240 && byte <= 247) {
            const byte2 = arr[i + 1];
            const byte3 = arr[i + 2];
            const byte4 = arr[i + 3];
            skip = 3;
            const codePoint = ((byte & 7) << 18) |
                ((byte2 & 63) << 12) |
                ((byte3 & 63) << 6) |
                (byte4 & 63);
            const surrogate1 = 55296 + ((codePoint - 65536) >> 10);
            const surrogate2 = 56320 + ((codePoint - 65536) & 1023);
            result += String.fromCharCode(surrogate1, surrogate2);
        }
    }
    return result;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: verify

```ts
verify = (msg: BigNumber, sig: Signature, key: Point): boolean => {
    const hash = BigInt("0x" + msg.toString(16));
    if ((key.x == null) || (key.y == null)) {
        throw new Error("Invalid public key: missing coordinates.");
    }
    const publicKey = {
        x: BigInt("0x" + key.x.toString(16)),
        y: BigInt("0x" + key.y.toString(16))
    };
    const signature = {
        r: BigInt("0x" + sig.r.toString(16)),
        s: BigInt("0x" + sig.s.toString(16))
    };
    const { r, s } = signature;
    const z = hash;
    if (r <= BI_ZERO || r >= N_BIGINT || s <= BI_ZERO || s >= N_BIGINT) {
        return false;
    }
    const w = modInvN(s);
    if (w === 0n)
        return false;
    const u1 = modMulN(z, w);
    const u2 = modMulN(r, w);
    const RG = scalarMultiplyWNAF(u1, { x: GX_BIGINT, y: GY_BIGINT });
    const RQ = scalarMultiplyWNAF(u2, publicKey);
    const R = jpAdd(RG, RQ);
    if (R.Z === 0n)
        return false;
    const zInv = biModInv(R.Z);
    const zInv2 = biModMul(zInv, zInv);
    const xAff = biModMul(R.X, zInv2);
    const v = modN(xAff);
    return v === r;
}
```

See also: [BI_ZERO](./primitives.md#variable-bi_zero), [BigNumber](./primitives.md#class-bignumber), [GX_BIGINT](./primitives.md#variable-gx_bigint), [GY_BIGINT](./primitives.md#variable-gy_bigint), [N_BIGINT](./primitives.md#variable-n_bigint), [Point](./primitives.md#class-point), [Signature](./primitives.md#class-signature), [biModInv](./primitives.md#variable-bimodinv), [biModMul](./primitives.md#variable-bimodmul), [jpAdd](./primitives.md#variable-jpadd), [modInvN](./primitives.md#variable-modinvn), [modMulN](./primitives.md#variable-modmuln), [modN](./primitives.md#variable-modn), [scalarMultiplyWNAF](./primitives.md#variable-scalarmultiplywnaf)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: zero2

```ts
zero2 = (word: string): string => {
    if (word.length % 2 === 1) {
        return "0" + word;
    }
    else {
        return word;
    }
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
