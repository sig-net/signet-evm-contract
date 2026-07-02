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

/**
 * The EVM analog of the Solana `proxy-test-cpi` tests: a consumer contract
 * forwards requests to the signet contract via an external call. Unlike
 * Solana CPI (where the wallet stays the signer), the proxy contract becomes
 * the event's `sender` — so the request ID and the MPC key-derivation
 * predecessor belong to the proxy contract.
 */
void describe('Sign/Respond proxy tests', () => {
  void it('Can call signet contract via proxy and receive signature response', async () => {
    const {
      viem,
      chainSignatures,
      proxyTestCaller,
      requester,
      responder,
      chainId,
    } = await connectAndDeploy();
    const signArgs = createSignArgs('PROXY_TEST', 'single');

    // The proxy contract is the sender of the forwarded call.
    await viem.assertions.emitWithArgs(
      proxyTestCaller.write.callSign([signArgs], {
        value: SIGNATURE_DEPOSIT,
        account: requester.account,
      }),
      chainSignatures,
      'SignatureRequested',
      [
        getAddress(proxyTestCaller.address),
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

    // The mock MPC responds using the PROXY address as the predecessor.
    const requestId = generateSignRequestId(
      proxyTestCaller.address,
      signArgs,
      chainId
    );
    const signature = mpcSignDigest(
      proxyTestCaller.address,
      signArgs.path,
      signArgs.payload
    );

    await viem.assertions.emit(
      chainSignatures.write.respond([[{ requestId, signature }]], {
        account: responder.account,
      }),
      chainSignatures,
      'SignatureResponded'
    );

    const recovered = await recoverAddress({
      hash: signArgs.payload,
      signature: signatureStructToRsv(signature),
    });
    assert.equal(
      recovered,
      deriveChildAddress(proxyTestCaller.address, signArgs.path)
    );
  });

  void it('Can handle multiple concurrent proxy calls', async () => {
    const {
      publicClient,
      chainSignatures,
      proxyTestCaller,
      requester,
      responder,
      chainId,
    } = await connectAndDeploy();

    const signArgs1 = createSignArgs('CONCURRENT_TEST', '1', 1);
    const signArgs2 = createSignArgs('CONCURRENT_TEST', '2', 2);

    await proxyTestCaller.write.callSign([signArgs1], {
      value: SIGNATURE_DEPOSIT,
      account: requester.account,
    });
    await proxyTestCaller.write.callSign([signArgs2], {
      value: SIGNATURE_DEPOSIT,
      account: requester.account,
    });

    // The mock MPC answers both requests in a single batched respond call.
    const responses = [signArgs1, signArgs2].map((signArgs) => ({
      requestId: generateSignRequestId(
        proxyTestCaller.address,
        signArgs,
        chainId
      ),
      signature: mpcSignDigest(
        proxyTestCaller.address,
        signArgs.path,
        signArgs.payload
      ),
    }));

    const txHash = await chainSignatures.write.respond([responses], {
      account: responder.account,
    });
    const receipt = await publicClient.waitForTransactionReceipt({
      hash: txHash,
    });

    const events = parseEventLogs({
      abi: chainSignatures.abi,
      logs: receipt.logs,
      eventName: 'SignatureResponded',
    });
    assert.equal(events.length, 2);
    assert.equal(events[0].args.requestId, responses[0].requestId);
    assert.equal(events[1].args.requestId, responses[1].requestId);

    for (const [i, signArgs] of [signArgs1, signArgs2].entries()) {
      const recovered = await recoverAddress({
        hash: signArgs.payload,
        signature: signatureStructToRsv(responses[i].signature),
      });
      assert.equal(
        recovered,
        deriveChildAddress(proxyTestCaller.address, signArgs.path)
      );
    }
  });
});
