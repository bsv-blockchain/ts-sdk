import {
  METHOD2_VM_LAYOUT,
  Method2VmBuilder
} from './Method2Vm.js'
import {
  METHOD2_HMAC_INNER_PAD,
  METHOD2_HMAC_KEY_SIZE,
  METHOD2_HMAC_OUTER_PAD,
  METHOD2_SHA256_DIGEST_SIZE,
  Method2HmacWitnessPlan,
  method2HmacWitnessPlan
} from './Method2Hmac.js'

export interface Method2VmHmacInputWitness extends Method2HmacWitnessPlan {
  shared: number[]
  invoice: number[]
  sharedBytesLinked: number
  invoiceBytesBound: number
  linkageBytesBound: number
}

export class Method2VmHmacInputBuilder {
  private readonly shared: number[] = []

  constructor (
    private readonly builder: Method2VmBuilder,
    private readonly invoice: number[],
    private readonly linkage: number[]
  ) {
    assertBytes(invoice, undefined, 'invoice')
    assertBytes(linkage, METHOD2_SHA256_DIGEST_SIZE, 'linkage')
  }

  consumeSharedByte (
    byteIndex: number,
    value: number
  ): void {
    if (byteIndex !== this.shared.length) {
      throw new Error('Method 2 VM HMAC shared byte order mismatch')
    }
    assertBytes([value], undefined, 'shared byte')
    const inner = value ^ METHOD2_HMAC_INNER_PAD
    const outer = value ^ METHOD2_HMAC_OUTER_PAD
    this.builder.assertXorConstByteLinked(
      value,
      METHOD2_HMAC_INNER_PAD,
      inner,
      'a'
    )
    this.builder.assertEq(inner, inner)
    this.builder.assertEqLinked(value, value, 'a')
    this.builder.assertXorConstByteLinked(
      value,
      METHOD2_HMAC_OUTER_PAD,
      outer,
      'a'
    )
    this.builder.assertEq(outer, outer)
    this.shared.push(value)
  }

  finish (
    options: { validateLinkage?: boolean } = {}
  ): Method2VmHmacInputWitness {
    if (this.shared.length !== METHOD2_HMAC_KEY_SIZE) {
      throw new Error('Method 2 VM HMAC shared key is incomplete')
    }
    const validateLinkage = options.validateLinkage !== false
    const plan = validateLinkage
      ? method2HmacWitnessPlan(
        this.shared,
        this.invoice,
        this.linkage
      )
      : {
          innerMessage: [],
          innerDigest: [],
          outerMessage: [],
          linkage: this.linkage.slice()
        }
    for (const byte of this.invoice) {
      appendPublicByte(this.builder, byte)
    }
    for (const byte of this.linkage) {
      appendPublicByte(this.builder, byte)
    }
    return {
      ...plan,
      shared: this.shared.slice(),
      invoice: this.invoice.slice(),
      sharedBytesLinked: this.shared.length,
      invoiceBytesBound: this.invoice.length,
      linkageBytesBound: this.linkage.length
    }
  }
}

export function appendMethod2VmLinkedHmacInput (
  builder: Method2VmBuilder,
  shared: number[],
  invoice: number[],
  linkage: number[]
): Method2VmHmacInputWitness {
  const hmac = new Method2VmHmacInputBuilder(builder, invoice, linkage)
  for (let i = 0; i < shared.length; i++) {
    builder.assertEqLinked(shared[i], shared[i], 'a')
    hmac.consumeSharedByte(i, shared[i])
  }
  return hmac.finish()
}

function appendPublicByte (
  builder: Method2VmBuilder,
  byte: number
): void {
  const row = builder.rowCount()
  builder.assertByte(byte)
  builder.fixCell(row, METHOD2_VM_LAYOUT.a, byte)
}

function assertBytes (
  bytes: number[],
  length: number | undefined,
  label: string
): void {
  if (length !== undefined && bytes.length !== length) {
    throw new Error(`Invalid ${label} length`)
  }
  for (const byte of bytes) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`Invalid ${label} byte`)
    }
  }
}
