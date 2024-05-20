/**
 * Copyright Clave - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
import '@matterlabs/hardhat-zksync-toolbox';
import '@nomicfoundation/hardhat-ethers';
import '@typechain/hardhat';
import dotenv from 'dotenv';
import type { HardhatUserConfig } from 'hardhat/config';
import type { NetworkUserConfig } from 'hardhat/types';

dotenv.config();

const zkSyncMainnet: NetworkUserConfig = {
    url: 'https://mainnet.era.zksync.io',
    ethNetwork: 'mainnet',
    zksync: true,
    verifyURL:
        'https://zksync2-mainnet-explorer.zksync.io/contract_verification',
    chainId: 324,
};

const zkSyncSepolia: NetworkUserConfig = {
    url: 'https://sepolia.era.zksync.dev',
    ethNetwork: 'sepolia',
    zksync: true,
    verifyURL: 'https://explorer.sepolia.era.zksync.dev/contract_verification',
    chainId: 300,
};

const inMemoryNode: NetworkUserConfig = {
    url: 'http://127.0.0.1:8011',
    ethNetwork: '', // in-memory node doesn't support eth node; removing this line will cause an error
    zksync: true,
    chainId: 260,
};

const dockerizedNode: NetworkUserConfig = {
    url: 'http://localhost:3050',
    ethNetwork: 'http://localhost:8545',
    zksync: true,
    chainId: 270,
};

const config: HardhatUserConfig = {
    zksolc: {
        version: 'latest',
        settings: {
            isSystem: true,
            optimizer: {
                fallbackToOptimizingForSize: false,
            },
            libraries: {
                  "contracts/email-auth/libraries/DecimalUtils.sol": {
                    "DecimalUtils": "0xf120b2943F2B04C22317E61495b82d8FE0D7dD68"
                  },
                  "contracts/email-auth/libraries/SubjectUtils.sol": {
                    "SubjectUtils": "0x1a6218e620Eb3599984ACCf62Dc92676A4569F8B"
                  }
                }
        },
    },
    defaultNetwork: 'zkSyncSepolia',
    networks: {
        hardhat: {
            zksync: true,
        },
        zkSyncSepolia,
        zkSyncMainnet,
        inMemoryNode,
        dockerizedNode,
    },
    solidity: {
        version: '0.8.20',
    },
};

export default config;
