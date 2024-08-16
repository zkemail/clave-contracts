import { assert, expect } from 'chai';
import type { ec } from 'elliptic';
import {
    AbiCoder,
    WeiPerEther,
    ZeroAddress,
    concat,
    ethers,
    parseEther,
    randomBytes,
    solidityPackedKeccak256,
} from 'ethers';
import * as hre from 'hardhat';
import { Contract, Provider, Wallet, utils } from 'zksync-ethers';

import { LOCAL_RICH_WALLETS, deployContract, getWallet } from '../deploy/utils';
import type { CallStruct } from '../typechain-types/contracts/batch/BatchCaller';
import { encodePublicKey, genKey } from './utils/p256';
import { getGaslessPaymasterInput } from './utils/paymaster';
import { ethTransfer, prepareBatchTx, prepareTeeTx } from './utils/transaction';

let provider: Provider;
let richWallet: Wallet;
let keyPair: ec.KeyPair;

let batchCaller: Contract;
let mockValidator: Contract;
let implementation: Contract;
let factory: Contract;
let account: Contract;
let create2Address: Contract;

beforeEach(async () => {
    provider = new Provider(hre.network.config.url, undefined, {
        cacheTimeout: -1,
    });
    richWallet = getWallet(hre, LOCAL_RICH_WALLETS[0].privateKey);
    keyPair = genKey();
    const publicKey = encodePublicKey(keyPair);
    create2Address = await deployContract(hre, 'Create2Address', undefined, {
        wallet: richWallet,
        silent: true,
    });
})

describe('Create2Address', function () {
    it('should create a create2 address', async () => {

        const recoveredAccount = "0x0000000000000000000000000000000000000001";
        const accountSalt = ethers.ZeroHash;

        const chainId = await create2Address.chainId();
        console.log("chainId", chainId);

        const emailAuthAddress = await create2Address.emailAuthImplementation();
        console.log("emailAuthAddress", emailAuthAddress);
  
        const computeAddress = await create2Address.computeEmailAuthAddress(recoveredAccount, accountSalt);
        console.log("computeAddress", computeAddress);

/**
 * 09:42:43  INFO Unable to estimate gas for the request with our suggested gas limit of 80010000. The transaction is most likely unexecutable. Breakdown of estimation:
09:42:43  INFO  Estimated transaction body gas cost: 80000000
09:42:43  INFO  Gas for pubdata: 0
09:42:43  INFO  Overhead: 10000
09:42:43  INFO execution reverted: Error function_selector = 0x, data = 0x
 */
        const deployedProxyAddress = await create2Address.deployProxy(recoveredAccount, accountSalt, {
            gasLimit: 90000000.
        });
        console.log("deployedProxyAddress", deployedProxyAddress);
    })
})