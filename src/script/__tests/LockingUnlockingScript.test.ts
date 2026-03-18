import LockingScript from '../../script/LockingScript'
import UnlockingScript from '../../script/UnlockingScript'
import Script from '../../script/Script'

describe('LockingScript', () => {
  it('isLockingScript() returns true', () => {
    const script = new LockingScript()
    expect(script.isLockingScript()).toBe(true)
  })

  it('isUnlockingScript() returns false', () => {
    const script = new LockingScript()
    expect(script.isUnlockingScript()).toBe(false)
  })

  it('extends Script', () => {
    const script = new LockingScript()
    expect(script).toBeInstanceOf(Script)
  })

  it('can be constructed from hex via inherited fromHex', () => {
    const hex = '76a914' + '00'.repeat(20) + '88ac'
    const script = Script.fromHex(hex)
    const locking = new LockingScript()
    locking.chunks = script.chunks
    expect(locking.toHex()).toBe(hex)
    expect(locking.isLockingScript()).toBe(true)
  })

  it('fromHex returns a Script instance that can be used to populate a LockingScript', () => {
    const hex = '51' // OP_1
    const base = Script.fromHex(hex)
    expect(base.toHex()).toBe(hex)
  })
})

describe('UnlockingScript', () => {
  it('isLockingScript() returns false', () => {
    const script = new UnlockingScript()
    expect(script.isLockingScript()).toBe(false)
  })

  it('isUnlockingScript() returns true', () => {
    const script = new UnlockingScript()
    expect(script.isUnlockingScript()).toBe(true)
  })

  it('extends Script', () => {
    const script = new UnlockingScript()
    expect(script).toBeInstanceOf(Script)
  })

  it('can be constructed from hex via inherited fromHex', () => {
    const hex = '4830450221'
    const script = Script.fromHex(hex)
    const unlocking = new UnlockingScript()
    unlocking.chunks = script.chunks
    expect(unlocking.isUnlockingScript()).toBe(true)
  })
})

describe('LockingScript vs UnlockingScript', () => {
  it('LockingScript and UnlockingScript return opposite values for isLockingScript', () => {
    const locking = new LockingScript()
    const unlocking = new UnlockingScript()
    expect(locking.isLockingScript()).not.toBe(unlocking.isLockingScript())
  })

  it('LockingScript and UnlockingScript return opposite values for isUnlockingScript', () => {
    const locking = new LockingScript()
    const unlocking = new UnlockingScript()
    expect(locking.isUnlockingScript()).not.toBe(unlocking.isUnlockingScript())
  })

  it('both are instances of Script', () => {
    expect(new LockingScript()).toBeInstanceOf(Script)
    expect(new UnlockingScript()).toBeInstanceOf(Script)
  })
})
