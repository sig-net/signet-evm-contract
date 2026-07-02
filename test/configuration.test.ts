import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { parseGwei, zeroAddress } from 'viem';
import {
  connectAndDeploy,
  SIGNATURE_DEPOSIT,
} from '../test-utils/testSetup.js';
import { createSignArgs } from '../test-utils/signingUtils.js';

void describe('Configuration Functions', () => {
  void it('Is initialized', async () => {
    const { chainSignatures, admin } = await connectAndDeploy();

    assert.equal(
      await chainSignatures.read.getSignatureDeposit(),
      SIGNATURE_DEPOSIT
    );
    const adminRole = await chainSignatures.read.DEFAULT_ADMIN_ROLE();
    assert.equal(
      await chainSignatures.read.hasRole([adminRole, admin.account.address]),
      true
    );
  });

  void describe('setSignatureDeposit', () => {
    void it('Should successfully update deposit when called by admin', async () => {
      const { viem, chainSignatures } = await connectAndDeploy();
      const newDeposit = parseGwei('100000');

      await viem.assertions.emitWithArgs(
        chainSignatures.write.setSignatureDeposit([newDeposit]),
        chainSignatures,
        'DepositUpdated',
        [SIGNATURE_DEPOSIT, newDeposit]
      );

      assert.equal(
        await chainSignatures.read.getSignatureDeposit(),
        newDeposit
      );
    });

    void it('Should fail when called by non-admin', async () => {
      const { viem, chainSignatures, requester } = await connectAndDeploy();

      await viem.assertions.revertWithCustomError(
        chainSignatures.write.setSignatureDeposit([parseGwei('300000')], {
          account: requester.account,
        }),
        chainSignatures,
        'AccessControlUnauthorizedAccount'
      );
    });
  });

  void describe('withdraw', () => {
    async function fundedDeployment() {
      const deployment = await connectAndDeploy();
      const { chainSignatures, requester } = deployment;

      const signArgs = createSignArgs('CONFIG_TEST', 'deposit', 1);
      await chainSignatures.write.sign([signArgs], {
        value: SIGNATURE_DEPOSIT,
        account: requester.account,
      });

      return deployment;
    }

    void it('Should successfully withdraw funds when called by admin', async () => {
      const { viem, publicClient, chainSignatures, responder } =
        await fundedDeployment();
      const withdrawAmount = parseGwei('30000');

      await viem.assertions.emitWithArgs(
        chainSignatures.write.withdraw([
          withdrawAmount,
          responder.account.address,
        ]),
        chainSignatures,
        'FundsWithdrawn',
        [withdrawAmount, responder.account.address]
      );

      assert.equal(
        await publicClient.getBalance({ address: chainSignatures.address }),
        SIGNATURE_DEPOSIT - withdrawAmount
      );
    });

    void it('Should fail when called by non-admin', async () => {
      const { viem, chainSignatures, requester } = await fundedDeployment();

      await viem.assertions.revertWithCustomError(
        chainSignatures.write.withdraw(
          [parseGwei('30000'), requester.account.address],
          { account: requester.account }
        ),
        chainSignatures,
        'AccessControlUnauthorizedAccount'
      );
    });

    void it('Should fail when trying to withdraw more than available', async () => {
      const { viem, chainSignatures, responder } = await fundedDeployment();

      await viem.assertions.revertWithCustomError(
        chainSignatures.write.withdraw([
          SIGNATURE_DEPOSIT + 1n,
          responder.account.address,
        ]),
        chainSignatures,
        'InsufficientFunds'
      );
    });

    void it('Should fail when recipient is zero address', async () => {
      const { viem, chainSignatures } = await fundedDeployment();

      await viem.assertions.revertWithCustomError(
        chainSignatures.write.withdraw([parseGwei('30000'), zeroAddress]),
        chainSignatures,
        'InvalidRecipient'
      );
    });
  });
});
