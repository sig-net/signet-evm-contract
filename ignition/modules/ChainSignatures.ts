import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';

/**
 * Deploys the ChainSignatures contract. The admin defaults to the deployer;
 * production deployments should pass the MPC network's admin address via the
 * `admin` parameter and the required deposit via `signatureDeposit` (wei).
 */
const ChainSignaturesModule = buildModule('ChainSignaturesModule', (m) => {
  const admin = m.getParameter('admin', m.getAccount(0));
  const signatureDeposit = m.getParameter(
    'signatureDeposit',
    50_000_000_000_000n // 50000 gwei
  );

  const chainSignatures = m.contract('ChainSignatures', [
    admin,
    signatureDeposit,
  ]);

  return { chainSignatures };
});

export default ChainSignaturesModule;
