import { CreateActionArgs } from '../Wallet.interfaces'
import WalletClient from '../WalletClient'
import WERR_INVALID_PARAMETER from '../WERR_INVALID_PARAMETER'

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
})