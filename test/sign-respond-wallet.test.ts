import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { getAddress, parseEventLogs, recoverAddress } from 'viem';
import {
  connectAndDeploy,
  SIGNATURE_DEPOSIT,
} from '../test-utils/testSetup.js';
import {
  createSignArgs,
  generateSignRequestId,
  deriveChildAddress,
  mpcSignDigest,
  signatureStructToRsv,
} from '../test-utils/signingUtils.js';

void describe('Sign/Respond wallet tests', () => {
  void it('Can request a signature', async () => {
    const { viem, chainSignatures, requester, chainId } =
      await connectAndDeploy();
    const signArgs = createSignArgs('WALLET_TEST', 'wallet');

    await viem.assertions.emitWithArgs(
      chainSignatures.write.sign([signArgs], {
        value: SIGNATURE_DEPOSIT,
        account: requester.account,
      }),
      chainSignatures,
      'SignatureRequested',
      [
        getAddress(requester.account.address),
        signArgs.payload,
        signArgs.keyVersion,
        SIGNATURE_DEPOSIT,
        chainId,
        signArgs.path,
        signArgs.algo,
        signArgs.dest,
        signArgs.params,
      ]
    );
  });

  void it('Should fail with insufficient deposit', async () => {
    const { viem, chainSignatures, requester } = await connectAndDeploy();
    const signArgs = createSignArgs('WALLET_TEST', 'deposit');

    await viem.assertions.revertWithCustomError(
      chainSignatures.write.sign([signArgs], {
        value: SIGNATURE_DEPOSIT - 1n,
        account: requester.account,
      }),
      chainSignatures,
      'InsufficientDeposit'
    );
  });

  void it('Can respond with a signature verifiable against the derived MPC key', async () => {
    const { publicClient, chainSignatures, requester, responder, chainId } =
      await connectAndDeploy();
    const signArgs = createSignArgs('WALLET_TEST', 'respond');

    await chainSignatures.write.sign([signArgs], {
      value: SIGNATURE_DEPOSIT,
      account: requester.account,
    });

    // The mock MPC derives the request ID and signs with the child key for
    // (requester, path) — exactly what the network does for this event.
    const requestId = generateSignRequestId(
      requester.account.address,
      signArgs,
      chainId
    );
    const signature = mpcSignDigest(
      requester.account.address,
      signArgs.path,
      signArgs.payload
    );

    const txHash = await chainSignatures.write.respond(
      [[{ requestId, signature }]],
      { account: responder.account }
    );
    const receipt = await publicClient.waitForTransactionReceipt({
      hash: txHash,
    });

    // Parse the SignatureResponded event (struct args) from the receipt.
    const events = parseEventLogs({
      abi: chainSignatures.abi,
      logs: receipt.logs,
      eventName: 'SignatureResponded',
    });
    assert.equal(events.length, 1);
    assert.equal(events[0].args.requestId, requestId);
    assert.equal(
      getAddress(events[0].args.responder),
      getAddress(responder.account.address)
    );
    assert.deepEqual(events[0].args.signature, {
      bigR: { x: signature.bigR.x, y: signature.bigR.y },
      s: signature.s,
      recoveryId: signature.recoveryId,
    });

    // Client-side verification: recover the signer address from the event's
    // signature and compare against the signet.js-derived child address.
    const recovered = await recoverAddress({
      hash: signArgs.payload,
      signature: signatureStructToRsv(events[0].args.signature),
    });
    assert.equal(
      recovered,
      deriveChildAddress(requester.account.address, signArgs.path)
    );
  });
});
