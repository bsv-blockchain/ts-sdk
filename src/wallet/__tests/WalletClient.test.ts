import { CreateActionArgs } from '../Wallet.interfaces'
import WalletClient from '../WalletClient'
describe('WalletClient', () => {
  it('0 createAction', async () => {
    const wallet = new WalletClient('auto', '0.WalletClient.test')

    async function testArgs(args: CreateActionArgs, parameter: string) {
      try {
        const r = await wallet.createAction(args)
        expect(true).toBe(false)
      } catch (e: any) {
        expect(e.name).toBe('WERR_INVALID_PARAMETER')
        expect(e.parameter).toBe(parameter)
      }
    }

    const args: CreateActionArgs = {
      description: 't' // too short to be valid
    }
    testArgs(args, 'description')
    args.description = '12345'
    args.outputs = [{
      lockingScript: '',
      satoshis: 0,
      outputDescription: ''
    }]
    testArgs(args, 'lockingScript')
    args.outputs[0].lockingScript = '1234'
    testArgs(args, 'outputDescription')
  })

  it('1 validates optional createAction reference', async () => {
    const wallet = new WalletClient('auto', '0.WalletClient.test')
    await expect(
      wallet.createAction({
        description: '12345',
        reference: 'not-base64'
      })
    ).rejects.toMatchObject({
      name: 'WERR_INVALID_PARAMETER',
      parameter: 'reference'
    })
  })

  it('2 validates optional listActions reference', async () => {
    const wallet = new WalletClient('auto', '0.WalletClient.test')
    await expect(
      wallet.listActions({
        labels: [],
        reference: 'not-base64'
      })
    ).rejects.toMatchObject({
      name: 'WERR_INVALID_PARAMETER',
      parameter: 'reference'
    })
  })

  it('3 validates optional internalizeAction reference', async () => {
    const wallet = new WalletClient('auto', '0.WalletClient.test')
    await expect(
      wallet.internalizeAction({
        tx: [],
        outputs: [],
        description: '12345',
        reference: 'not-base64'
      })
    ).rejects.toMatchObject({
      name: 'WERR_INVALID_PARAMETER',
      parameter: 'reference'
    })
  })
})
