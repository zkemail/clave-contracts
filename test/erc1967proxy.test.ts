import type { Contract } from '@ethersproject/contracts';
import { assert, expect } from 'chai';
import type { ec } from 'elliptic';
import {
    AbiCoder,
    WeiPerEther,
    ZeroAddress,
    concat,
    type ethers,
    parseEther,
    parseUnits,
    randomBytes,
    solidityPackedKeccak256,
    zeroPadBytes,
    ZeroHash,
} from 'ethers';
import {
    deployAccount,
    deployBatchCaller,
    deployEOAValidator,
    deployERC20PaymasterMock,
    deployFactory,
    deployGaslessPaymaster,
    deployImplementation,
    deployMockExecutionHook,
    deployMockImplementation,
    deployMockModule,
    deployMockStable,
    deployMockValidationHook,
    deployRegistry,
    deploySubsidizerPaymasterMock,
    deployTeeValidator,
    deployVerifier,
} from './utils/deploy';

import { Provider, Wallet, utils } from 'zksync-ethers';

import type {
    ERC1967Proxy
} from '../typechain-types';
import { Deployer } from '@matterlabs/hardhat-zksync-deploy';

let provider: Provider;
let wallet: Wallet;

import * as hre from 'hardhat';
import { richWallets } from './utils/rich-wallets';

describe('Check the bytecode hash of ERC1967Proxy', function () {

    it('Have correct bytecode hash', async function () {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        provider = new Provider(hre.network.config.url, undefined, {
            cacheTimeout: -1,
        });
        const richPk = richWallets[0].privateKey;
        wallet = new Wallet(richPk, provider);
    
        const deployer: Deployer = new Deployer(hre, wallet);

        const emailAuthartifact = await deployer.loadArtifact(
            'EmailAuth',
        );
        const emailAuth = await deployer.deploy(emailAuthartifact, []);

        const emailAuthContract = await hre.ethers.getContractFactory("EmailAuth");
        const inputData = emailAuthContract.interface.encodeFunctionData(
            "initialize", 
            [
                "0x25D06343b3a5738594e59703Cf61B2Adec968B60",
                "0x1162ebff40918afe5305e68396f0283eb675901d0387f97d21928d423aaa0b54"
            ])
        console.dir(inputData);

        const artifact = await deployer.loadArtifact(
            'ERC1967Proxy',
        );
        console.log(await emailAuth.getAddress())
        const estimatesGas = await deployer.estimateDeployGas(
            artifact,
            [await emailAuth.getAddress(), inputData],
        );
        console.log(estimatesGas);
        const proxy = await deployer.deploy(
            artifact, 
            [await emailAuth.getAddress(), inputData], 
        );
        const contract = await hre.ethers.getContractAt(
            'ERC1967Proxy',
            await proxy.getAddress(),
            wallet,
        );
        
        const contractAddress = await contract.getAddress();
        const bytecode = await provider.getCode(contractAddress);
        console.log(bytecode);
        const bytecodeHash = hre.ethers.hexlify(utils.hashBytecode(bytecode));
        console.log(bytecodeHash);

    })
})

