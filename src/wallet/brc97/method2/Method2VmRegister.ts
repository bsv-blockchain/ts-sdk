import {
  Method2VmBuilder,
  Method2VmProgram
} from './Method2Vm.js'

export class Method2VmRegisterProgramBuilder {
  private current?: bigint

  constructor (
    private readonly builder: Method2VmBuilder = new Method2VmBuilder()
  ) {}

  seed (value: bigint | number): this {
    const normalized = BigInt(value)
    this.builder.assertEqLinked(normalized, normalized, 'a')
    this.current = normalized
    return this
  }

  add (value: bigint | number): this {
    const current = this.requireCurrent()
    const right = BigInt(value)
    const result = current + right
    this.builder.assertAddLinked(current, right, result, 'a')
    this.current = result
    return this
  }

  mul (value: bigint | number): this {
    const current = this.requireCurrent()
    const right = BigInt(value)
    const result = current * right
    this.builder.assertMulLinked(current, right, result, 'a')
    this.current = result
    return this
  }

  select (valueIfOne: bigint | number, selector: 0 | 1): this {
    const current = this.requireCurrent()
    const right = BigInt(valueIfOne)
    const result = selector === 1 ? right : current
    this.builder.assertSelectLinked(current, right, selector, result, 'a')
    this.current = result
    return this
  }

  assertEq (value: bigint | number): this {
    this.builder.assertEq(this.requireCurrent(), BigInt(value))
    return this
  }

  assertBool (): this {
    const current = this.requireCurrent()
    if (current !== 0n && current !== 1n) {
      throw new Error('Method 2 VM register value is not boolean')
    }
    this.builder.assertBoolLinked(Number(current) as 0 | 1, 'a')
    return this
  }

  value (): bigint {
    return this.requireCurrent()
  }

  build (publicInputDigest?: number[]): Method2VmProgram {
    if (this.current === undefined) {
      throw new Error('Method 2 VM register program has no seeded register')
    }
    return this.builder.build(publicInputDigest)
  }

  private requireCurrent (): bigint {
    if (this.current === undefined) {
      throw new Error('Method 2 VM register program has no current register')
    }
    return this.current
  }
}
