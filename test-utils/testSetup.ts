/**
 * Shared deployment helper for tests — the EVM analog of the Solana repo's
 * testSetup. Instead of spinning up the fakenet-signer server, the mock MPC
 * lives in-process (see signingUtils.ts): tests derive the same child keys
 * the network would and deliver responses through the respond* functions.
 */
import { network } from 'hardhat';
import { parseGwei } from 'viem';

export const SIGNATURE_DEPOSIT = parseGwei('50000');

export async function connectAndDeploy() {
  const { viem } = await network.getOrCreate();
  const publicClient = await viem.getPublicClient();
  const [admin, requester, responder] = await viem.getWalletClients();

  const chainSignatures = await viem.deployContract('ChainSignatures', [
    admin.account.address,
    SIGNATURE_DEPOSIT,
  ]);
  const proxyTestCaller = await viem.deployContract('ProxyTestCaller', [
    chainSignatures.address,
  ]);

  const chainId = BigInt(await publicClient.getChainId());

  return {
    viem,
    publicClient,
    admin,
    requester,
    responder,
    chainSignatures,
    proxyTestCaller,
    chainId,
  };
}
