import type { HardhatUserConfig } from 'hardhat/config';
import hardhatToolboxViemPlugin from '@nomicfoundation/hardhat-toolbox-viem';
import * as dotenv from 'dotenv';

dotenv.config();

const config: HardhatUserConfig = {
  plugins: [hardhatToolboxViemPlugin],
  paths: {
    sources: {
      solidity: ['contracts', 'examples'],
    },
  },
  solidity: {
    profiles: {
      default: {
        version: '0.8.35',
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
      production: {
        version: '0.8.35',
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
    },
  },
  networks: {
    hardhatMainnet: {
      type: 'edr-simulated',
      chainType: 'l1',
    },
    ...(process.env.SEPOLIA_RPC_URL
      ? {
          sepolia: {
            type: 'http' as const,
            chainType: 'l1' as const,
            url: process.env.SEPOLIA_RPC_URL,
            accounts: process.env.SEPOLIA_PRIVATE_KEY
              ? [process.env.SEPOLIA_PRIVATE_KEY]
              : [],
          },
        }
      : {}),
  },
};

export default config;
