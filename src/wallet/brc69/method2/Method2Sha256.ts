import {
  F,
  FieldElement,
  AirDefinition
} from '../stark/index.js'
import {
  Sha256State,
  sha256CompressBlock,
  sha256Schedule,
  toBitsLE
} from '../circuit/index.js'

export const METHOD2_SHA256_INITIAL_STATE = [
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19
]

export const METHOD2_SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

const WORD_BITS = 32
const STATE_WORDS = 8
const SCHEDULE_WINDOW = 16
const ROUND_COUNT = 64
const RESULT_ROW = 64
const TRACE_LENGTH = 128

export interface Method2Sha256BlockLayout {
  active: number
  scheduleActive: number
  last: number
  state: number
  chain: number
  schedule: number
  k: number
  t1: number
  t2: number
  roundA: number
  roundE: number
  t1Carry: number
  t2Carry: number
  nextACarry: number
  nextECarry: number
  scheduleCarry: number
  finalCarry: number
  width: number
}

export interface Method2Sha256BlockTrace {
  traceRows: FieldElement[][]
  outputState: number[]
  layout: Method2Sha256BlockLayout
}

export const METHOD2_SHA256_BLOCK_LAYOUT: Method2Sha256BlockLayout = {
  active: 0,
  scheduleActive: 1,
  last: 2,
  state: 3,
  chain: 3 + STATE_WORDS * WORD_BITS,
  schedule: 3 + STATE_WORDS * WORD_BITS * 2,
  k: 3 + STATE_WORDS * WORD_BITS * 2 + SCHEDULE_WINDOW * WORD_BITS,
  t1: 3 + STATE_WORDS * WORD_BITS * 2 + SCHEDULE_WINDOW * WORD_BITS + WORD_BITS,
  t2: 3 + STATE_WORDS * WORD_BITS * 2 + SCHEDULE_WINDOW * WORD_BITS + WORD_BITS * 2,
  roundA: 3 + STATE_WORDS * WORD_BITS * 2 + SCHEDULE_WINDOW * WORD_BITS + WORD_BITS * 3,
  roundE: 3 + STATE_WORDS * WORD_BITS * 2 + SCHEDULE_WINDOW * WORD_BITS + WORD_BITS * 4,
  t1Carry: 3 + STATE_WORDS * WORD_BITS * 2 + SCHEDULE_WINDOW * WORD_BITS + WORD_BITS * 5,
  t2Carry: 3 + STATE_WORDS * WORD_BITS * 2 + SCHEDULE_WINDOW * WORD_BITS + WORD_BITS * 5 + WORD_BITS + 1,
  nextACarry: 3 + STATE_WORDS * WORD_BITS * 2 + SCHEDULE_WINDOW * WORD_BITS + WORD_BITS * 5 + (WORD_BITS + 1) * 2,
  nextECarry: 3 + STATE_WORDS * WORD_BITS * 2 + SCHEDULE_WINDOW * WORD_BITS + WORD_BITS * 5 + (WORD_BITS + 1) * 3,
  scheduleCarry: 3 + STATE_WORDS * WORD_BITS * 2 + SCHEDULE_WINDOW * WORD_BITS + WORD_BITS * 5 + (WORD_BITS + 1) * 4,
  finalCarry: 3 + STATE_WORDS * WORD_BITS * 2 + SCHEDULE_WINDOW * WORD_BITS + WORD_BITS * 5 + (WORD_BITS + 1) * 5,
  width: 3 + STATE_WORDS * WORD_BITS * 2 + SCHEDULE_WINDOW * WORD_BITS + WORD_BITS * 5 + (WORD_BITS + 1) * 5 + STATE_WORDS * (WORD_BITS + 1)
}

export function method2Sha256BlockLayoutAt (
  offset: number
): Method2Sha256BlockLayout {
  if (!Number.isSafeInteger(offset) || offset < 0) {
    throw new Error('SHA-256 block layout offset is invalid')
  }
  return {
    active: offset + METHOD2_SHA256_BLOCK_LAYOUT.active,
    scheduleActive: offset + METHOD2_SHA256_BLOCK_LAYOUT.scheduleActive,
    last: offset + METHOD2_SHA256_BLOCK_LAYOUT.last,
    state: offset + METHOD2_SHA256_BLOCK_LAYOUT.state,
    chain: offset + METHOD2_SHA256_BLOCK_LAYOUT.chain,
    schedule: offset + METHOD2_SHA256_BLOCK_LAYOUT.schedule,
    k: offset + METHOD2_SHA256_BLOCK_LAYOUT.k,
    t1: offset + METHOD2_SHA256_BLOCK_LAYOUT.t1,
    t2: offset + METHOD2_SHA256_BLOCK_LAYOUT.t2,
    roundA: offset + METHOD2_SHA256_BLOCK_LAYOUT.roundA,
    roundE: offset + METHOD2_SHA256_BLOCK_LAYOUT.roundE,
    t1Carry: offset + METHOD2_SHA256_BLOCK_LAYOUT.t1Carry,
    t2Carry: offset + METHOD2_SHA256_BLOCK_LAYOUT.t2Carry,
    nextACarry: offset + METHOD2_SHA256_BLOCK_LAYOUT.nextACarry,
    nextECarry: offset + METHOD2_SHA256_BLOCK_LAYOUT.nextECarry,
    scheduleCarry: offset + METHOD2_SHA256_BLOCK_LAYOUT.scheduleCarry,
    finalCarry: offset + METHOD2_SHA256_BLOCK_LAYOUT.finalCarry,
    width: METHOD2_SHA256_BLOCK_LAYOUT.width
  }
}

export function buildMethod2Sha256BlockTrace (
  initialState: number[],
  block: number[]
): Method2Sha256BlockTrace {
  validateState(initialState)
  validateBlock(block)
  const layout = METHOD2_SHA256_BLOCK_LAYOUT
  const traceRows = new Array<FieldElement[]>(TRACE_LENGTH)
    .fill([])
    .map(() => new Array<FieldElement>(layout.width).fill(0n))
  const schedule = sha256Schedule(block)
  let working = initialState.slice()

  for (let round = 0; round < ROUND_COUNT; round++) {
    const row = traceRows[round]
    const scheduleWindow = new Array<number>(SCHEDULE_WINDOW).fill(0)
    for (let i = 0; i < SCHEDULE_WINDOW; i++) {
      scheduleWindow[i] = schedule[round + i] ?? 0
    }
    writeRoundWitness(
      row,
      initialState,
      working,
      scheduleWindow,
      METHOD2_SHA256_K[round],
      round
    )
    working = nextWorkingState(working, schedule[round], METHOD2_SHA256_K[round])
  }

  const outputState = addStateWords(initialState, working)
  writeWordBits(traceRows[RESULT_ROW], layout.state, outputState)
  writeWordBits(traceRows[RESULT_ROW], layout.chain, outputState)

  return {
    traceRows,
    outputState,
    layout
  }
}

export function buildMethod2Sha256BlockAir (
  initialState: number[],
  block: number[],
  expectedOutputState?: number[]
): AirDefinition {
  validateState(initialState)
  validateBlock(block)
  if (expectedOutputState !== undefined) validateState(expectedOutputState)
  const layout = METHOD2_SHA256_BLOCK_LAYOUT
  const schedule = sha256Schedule(block)
  const boundaryConstraints = []

  for (let row = 0; row < TRACE_LENGTH; row++) {
    boundaryConstraints.push({
      column: layout.active,
      row,
      value: row < ROUND_COUNT ? 1n : 0n
    })
    boundaryConstraints.push({
      column: layout.scheduleActive,
      row,
      value: row < ROUND_COUNT - SCHEDULE_WINDOW ? 1n : 0n
    })
    boundaryConstraints.push({
      column: layout.last,
      row,
      value: row === ROUND_COUNT - 1 ? 1n : 0n
    })
  }

  boundaryConstraints.push(...wordBoundaryConstraints(
    0,
    layout.state,
    initialState
  ))
  boundaryConstraints.push(...wordBoundaryConstraints(
    0,
    layout.chain,
    initialState
  ))
  boundaryConstraints.push(...wordBoundaryConstraints(
    0,
    layout.schedule,
    schedule.slice(0, SCHEDULE_WINDOW)
  ))
  for (let row = 0; row < ROUND_COUNT; row++) {
    boundaryConstraints.push(...wordBoundaryConstraints(
      row,
      layout.k,
      [METHOD2_SHA256_K[row]]
    ))
  }
  if (expectedOutputState !== undefined) {
    boundaryConstraints.push(...wordBoundaryConstraints(
      RESULT_ROW,
      layout.state,
      expectedOutputState
    ))
  }

  return {
    traceWidth: layout.width,
    boundaryConstraints,
    transitionDegree: 7,
    evaluateTransition: (current, next) =>
      evaluateMethod2Sha256BlockTransition(current, next, layout)
  }
}

export function evaluateMethod2Sha256BlockTransition (
  current: FieldElement[],
  next: FieldElement[],
  layout: Method2Sha256BlockLayout = METHOD2_SHA256_BLOCK_LAYOUT
): FieldElement[] {
  const active = current[layout.active]
  const scheduleActive = current[layout.scheduleActive]
  const last = current[layout.last]
  const notLast = F.mul(active, F.sub(1n, last))
  const isLast = F.mul(active, last)
  const constraints: FieldElement[] = [
    booleanConstraint(active),
    booleanConstraint(scheduleActive),
    booleanConstraint(last),
    F.mul(scheduleActive, F.sub(scheduleActive, active)),
    F.mul(last, F.sub(last, active))
  ]

  const state = readWordBits(current, layout.state, STATE_WORDS)
  const chain = readWordBits(current, layout.chain, STATE_WORDS)
  const nextState = readWordBits(next, layout.state, STATE_WORDS)
  const nextChain = readWordBits(next, layout.chain, STATE_WORDS)
  const schedule = readWordBits(current, layout.schedule, SCHEDULE_WINDOW)
  const nextSchedule = readWordBits(next, layout.schedule, SCHEDULE_WINDOW)
  const k = wordBits(current, layout.k)
  const t1 = wordBits(current, layout.t1)
  const t2 = wordBits(current, layout.t2)
  const roundA = wordBits(current, layout.roundA)
  const roundE = wordBits(current, layout.roundE)

  constraints.push(...gateConstraints(bitBooleanConstraints([
    ...flatten(state),
    ...flatten(chain),
    ...flatten(schedule),
    ...k,
    ...t1,
    ...t2,
    ...roundA,
    ...roundE
  ]), active))

  const sigma1 = xor3Bits(rotrBits(state[4], 6), rotrBits(state[4], 11), rotrBits(state[4], 25))
  const ch = chBits(state[4], state[5], state[6])
  const sigma0 = xor3Bits(rotrBits(state[0], 2), rotrBits(state[0], 13), rotrBits(state[0], 22))
  const maj = majBits(state[0], state[1], state[2])

  constraints.push(...gateConstraints(addBitsConstraints(
    [state[7], sigma1, ch, k, schedule[0]],
    t1,
    current,
    layout.t1Carry
  ), active))
  constraints.push(...gateConstraints(addBitsConstraints(
    [sigma0, maj],
    t2,
    current,
    layout.t2Carry
  ), active))

  constraints.push(...gateConstraints(addBitsConstraints(
    [t1, t2],
    roundA,
    current,
    layout.nextACarry
  ), active))
  constraints.push(...gateConstraints(addBitsConstraints(
    [state[3], t1],
    roundE,
    current,
    layout.nextECarry
  ), active))
  constraints.push(...gateConstraints(wordEqualityConstraints(nextState[0], roundA), notLast))
  constraints.push(...gateConstraints(wordEqualityConstraints(nextState[4], roundE), notLast))
  constraints.push(...gateConstraints(wordEqualityConstraints(nextState[1], state[0]), notLast))
  constraints.push(...gateConstraints(wordEqualityConstraints(nextState[2], state[1]), notLast))
  constraints.push(...gateConstraints(wordEqualityConstraints(nextState[3], state[2]), notLast))
  constraints.push(...gateConstraints(wordEqualityConstraints(nextState[5], state[4]), notLast))
  constraints.push(...gateConstraints(wordEqualityConstraints(nextState[6], state[5]), notLast))
  constraints.push(...gateConstraints(wordEqualityConstraints(nextState[7], state[6]), notLast))
  for (let word = 0; word < STATE_WORDS; word++) {
    constraints.push(...gateConstraints(wordEqualityConstraints(nextChain[word], chain[word]), notLast))
  }

  for (let word = 0; word < SCHEDULE_WINDOW - 1; word++) {
    constraints.push(...gateConstraints(wordEqualityConstraints(nextSchedule[word], schedule[word + 1]), notLast))
  }
  constraints.push(...gateConstraints(addBitsConstraints(
    [smallSigma1Bits(schedule[14]), schedule[9], smallSigma0Bits(schedule[1]), schedule[0]],
    nextSchedule[15],
    current,
    layout.scheduleCarry
  ), F.mul(notLast, scheduleActive)))
  constraints.push(...gateConstraints(
    wordEqualityConstraints(nextSchedule[15], zeroBits()),
    F.mul(notLast, F.sub(1n, scheduleActive))
  ))

  const finalWords = [
    roundA,
    state[0],
    state[1],
    state[2],
    roundE,
    state[4],
    state[5],
    state[6]
  ]
  for (let word = 0; word < STATE_WORDS; word++) {
    constraints.push(...gateConstraints(addBitsConstraints(
      [chain[word], finalWords[word]],
      nextState[word],
      current,
      layout.finalCarry + word * (WORD_BITS + 1)
    ), isLast))
    constraints.push(...gateConstraints(
      wordEqualityConstraints(nextChain[word], nextState[word]),
      isLast
    ))
  }

  return constraints
}

function writeRoundWitness (
  row: FieldElement[],
  chain: number[],
  working: number[],
  scheduleWindow: number[],
  k: number,
  round: number
): void {
  const layout = METHOD2_SHA256_BLOCK_LAYOUT
  row[layout.active] = 1n
  row[layout.scheduleActive] = round < ROUND_COUNT - SCHEDULE_WINDOW ? 1n : 0n
  row[layout.last] = round === ROUND_COUNT - 1 ? 1n : 0n
  writeWordBits(row, layout.state, working)
  writeWordBits(row, layout.chain, chain)
  writeWordBits(row, layout.schedule, scheduleWindow)
  writeWordBits(row, layout.k, [k])

  const t1 = add32(
    working[7],
    bigSigma1(working[4]),
    ch(working[4], working[5], working[6]),
    k,
    scheduleWindow[0]
  )
  const t2 = add32(bigSigma0(working[0]), maj(working[0], working[1], working[2]))
  writeWordBits(row, layout.t1, [t1])
  writeWordBits(row, layout.t2, [t2])
  writeWordBits(row, layout.roundA, [add32(t1, t2)])
  writeWordBits(row, layout.roundE, [add32(working[3], t1)])
  writeCarries(row, layout.t1Carry, [
    working[7],
    bigSigma1(working[4]),
    ch(working[4], working[5], working[6]),
    k,
    scheduleWindow[0]
  ], t1)
  writeCarries(row, layout.t2Carry, [
    bigSigma0(working[0]),
    maj(working[0], working[1], working[2])
  ], t2)
  writeCarries(row, layout.nextACarry, [t1, t2], add32(t1, t2))
  writeCarries(row, layout.nextECarry, [working[3], t1], add32(working[3], t1))
  writeCarries(row, layout.scheduleCarry, [
    smallSigma1(scheduleWindow[14]),
    scheduleWindow[9],
    smallSigma0(scheduleWindow[1]),
    scheduleWindow[0]
  ], add32(
    smallSigma1(scheduleWindow[14]),
    scheduleWindow[9],
    smallSigma0(scheduleWindow[1]),
    scheduleWindow[0]
  ))

  const roundOutput = [
    add32(t1, t2),
    working[0],
    working[1],
    working[2],
    add32(working[3], t1),
    working[4],
    working[5],
    working[6]
  ]
  for (let word = 0; word < STATE_WORDS; word++) {
    writeCarries(
      row,
      layout.finalCarry + word * (WORD_BITS + 1),
      [chain[word], roundOutput[word]],
      add32(chain[word], roundOutput[word])
    )
  }
}

function nextWorkingState (
  working: number[],
  w: number,
  k: number
): number[] {
  const t1 = add32(
    working[7],
    bigSigma1(working[4]),
    ch(working[4], working[5], working[6]),
    k,
    w
  )
  const t2 = add32(bigSigma0(working[0]), maj(working[0], working[1], working[2]))
  return [
    add32(t1, t2),
    working[0],
    working[1],
    working[2],
    add32(working[3], t1),
    working[4],
    working[5],
    working[6]
  ]
}

function addStateWords (left: number[], right: number[]): number[] {
  return left.map((word, index) => add32(word, right[index]))
}

function writeWordBits (
  row: FieldElement[],
  offset: number,
  words: number[]
): void {
  for (let word = 0; word < words.length; word++) {
    const bits = toBitsLE(BigInt(words[word] >>> 0), WORD_BITS)
    for (let bit = 0; bit < WORD_BITS; bit++) {
      row[offset + word * WORD_BITS + bit] = BigInt(bits[bit])
    }
  }
}

function writeCarries (
  row: FieldElement[],
  offset: number,
  operands: number[],
  output: number
): void {
  let carry = 0
  row[offset] = 0n
  for (let bit = 0; bit < WORD_BITS; bit++) {
    let sum = carry
    for (const operand of operands) sum += (operand >>> bit) & 1
    const outputBit = (output >>> bit) & 1
    const nextCarry = (sum - outputBit) / 2
    if (!Number.isInteger(nextCarry) || nextCarry < 0) {
      throw new Error('Invalid SHA-256 carry witness')
    }
    row[offset + bit + 1] = BigInt(nextCarry)
    carry = nextCarry
  }
}

function addBitsConstraints (
  operands: FieldElement[][],
  output: FieldElement[],
  row: FieldElement[],
  carryOffset: number
): FieldElement[] {
  const constraints: FieldElement[] = [
    row[carryOffset],
    smallRangeConstraint(row[carryOffset], operands.length)
  ]
  for (let bit = 0; bit < WORD_BITS; bit++) {
    let sum = row[carryOffset + bit]
    for (const operand of operands) sum = F.add(sum, operand[bit])
    constraints.push(booleanConstraint(output[bit]))
    constraints.push(F.sub(
      sum,
      F.add(output[bit], F.mul(2n, row[carryOffset + bit + 1]))
    ))
    constraints.push(smallRangeConstraint(
      row[carryOffset + bit + 1],
      operands.length
    ))
  }
  return constraints
}

function readWordBits (
  row: FieldElement[],
  offset: number,
  words: number
): FieldElement[][] {
  const out: FieldElement[][] = []
  for (let word = 0; word < words; word++) {
    out.push(wordBits(row, offset + word * WORD_BITS))
  }
  return out
}

function wordBits (
  row: FieldElement[],
  offset: number
): FieldElement[] {
  return row.slice(offset, offset + WORD_BITS)
}

function wordBoundaryConstraints (
  row: number,
  offset: number,
  words: number[]
): Array<{ column: number, row: number, value: FieldElement }> {
  const constraints: Array<{ column: number, row: number, value: FieldElement }> = []
  for (let word = 0; word < words.length; word++) {
    const bits = toBitsLE(BigInt(words[word] >>> 0), WORD_BITS)
    for (let bit = 0; bit < WORD_BITS; bit++) {
      constraints.push({
        column: offset + word * WORD_BITS + bit,
        row,
        value: BigInt(bits[bit])
      })
    }
  }
  return constraints
}

function rotrBits (bits: FieldElement[], amount: number): FieldElement[] {
  return bits.map((_, bit) => bits[(bit + amount) % WORD_BITS])
}

function shrBits (bits: FieldElement[], amount: number): FieldElement[] {
  return bits.map((_, bit) => bit + amount < WORD_BITS ? bits[bit + amount] : 0n)
}

function xor3Bits (
  left: FieldElement[],
  middle: FieldElement[],
  right: FieldElement[]
): FieldElement[] {
  return left.map((value, bit) => xor3(value, middle[bit], right[bit]))
}

function chBits (
  x: FieldElement[],
  y: FieldElement[],
  z: FieldElement[]
): FieldElement[] {
  return x.map((value, bit) => F.add(
    F.mul(value, y[bit]),
    F.mul(F.sub(1n, value), z[bit])
  ))
}

function majBits (
  x: FieldElement[],
  y: FieldElement[],
  z: FieldElement[]
): FieldElement[] {
  return x.map((value, bit) => F.sub(
    F.add(F.add(
      F.mul(value, y[bit]),
      F.mul(value, z[bit])
    ), F.mul(y[bit], z[bit])),
    F.mul(2n, F.mul(F.mul(value, y[bit]), z[bit]))
  ))
}

function smallSigma0Bits (bits: FieldElement[]): FieldElement[] {
  return xor3Bits(rotrBits(bits, 7), rotrBits(bits, 18), shrBits(bits, 3))
}

function smallSigma1Bits (bits: FieldElement[]): FieldElement[] {
  return xor3Bits(rotrBits(bits, 17), rotrBits(bits, 19), shrBits(bits, 10))
}

function zeroBits (): FieldElement[] {
  return new Array<FieldElement>(WORD_BITS).fill(0n)
}

function bitBooleanConstraints (bits: FieldElement[]): FieldElement[] {
  return bits.map(booleanConstraint)
}

function wordEqualityConstraints (
  left: FieldElement[],
  right: FieldElement[]
): FieldElement[] {
  return left.map((value, bit) => F.sub(value, right[bit]))
}

function gateConstraints (
  constraints: FieldElement[],
  selector: FieldElement
): FieldElement[] {
  return constraints.map(constraint => F.mul(selector, constraint))
}

function flatten (values: FieldElement[][]): FieldElement[] {
  return ([] as FieldElement[]).concat(...values)
}

function booleanConstraint (value: FieldElement): FieldElement {
  return F.mul(value, F.sub(value, 1n))
}

function smallRangeConstraint (
  value: FieldElement,
  max: number
): FieldElement {
  let result = 1n
  for (let i = 0; i <= max; i++) {
    result = F.mul(result, F.sub(value, BigInt(i)))
  }
  return result
}

function xor3 (
  x: FieldElement,
  y: FieldElement,
  z: FieldElement
): FieldElement {
  return F.add(
    F.sub(
      F.sub(
        F.sub(F.add(F.add(x, y), z), F.mul(2n, F.mul(x, y))),
        F.mul(2n, F.mul(x, z))
      ),
      F.mul(2n, F.mul(y, z))
    ),
    F.mul(4n, F.mul(F.mul(x, y), z))
  )
}

function ch (x: number, y: number, z: number): number {
  return ((x & y) ^ (~x & z)) >>> 0
}

function maj (x: number, y: number, z: number): number {
  return ((x & z) ^ (x & y) ^ (y & z)) >>> 0
}

function bigSigma0 (x: number): number {
  return (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)) >>> 0
}

function bigSigma1 (x: number): number {
  return (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)) >>> 0
}

function smallSigma0 (x: number): number {
  return (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) >>> 0
}

function smallSigma1 (x: number): number {
  return (rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10)) >>> 0
}

function rotr (x: number, n: number): number {
  return ((x >>> n) | (x << (WORD_BITS - n))) >>> 0
}

function add32 (...values: number[]): number {
  let sum = 0
  for (const value of values) sum = (sum + (value >>> 0)) >>> 0
  return sum
}

function validateState (state: number[]): void {
  if (state.length !== STATE_WORDS) {
    throw new Error('SHA-256 state must contain 8 words')
  }
  for (const word of state) validateU32(word)
}

function validateBlock (block: number[]): void {
  if (block.length !== 64) throw new Error('SHA-256 block must be 64 bytes')
  for (const byte of block) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error('Invalid SHA-256 block byte')
    }
  }
}

function validateU32 (word: number): void {
  if (!Number.isInteger(word) || word < 0 || word > 0xffffffff) {
    throw new Error('SHA-256 word must be uint32')
  }
}

export function method2Sha256CompressBlockReference (
  initialState: number[],
  block: number[]
): number[] {
  const state: Sha256State = { words: initialState.slice() }
  return sha256CompressBlock(state, block).words
}
