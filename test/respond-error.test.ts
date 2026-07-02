import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { getAddress, parseEventLogs, toHex } from 'viem';
import { connectAndDeploy } from '../test-utils/testSetup.js';

void describe('Respond Error tests', () => {
  void it('Can respond with single error', async () => {
    const { viem, chainSignatures, responder } = await connectAndDeploy();
    const requestId = toHex(Uint8Array.from({ length: 32 }, (_, i) => i % 256));

    await viem.assertions.emitWithArgs(
      chainSignatures.write.respondError(
        [[{ requestId, errorMessage: 'Test error message' }]],
        { account: responder.account }
      ),
      chainSignatures,
      'SignatureError',
      [requestId, getAddress(responder.account.address), 'Test error message']
    );
  });

  void it('Can respond with multiple errors', async () => {
    const { publicClient, chainSignatures, responder } =
      await connectAndDeploy();
    const requestId1 = toHex(
      Uint8Array.from({ length: 32 }, (_, i) => (i + 1) % 256)
    );
    const requestId2 = toHex(
      Uint8Array.from({ length: 32 }, (_, i) => (i + 2) % 256)
    );

    const txHash = await chainSignatures.write.respondError(
      [
        [
          { requestId: requestId1, errorMessage: 'First error message' },
          { requestId: requestId2, errorMessage: 'Second error message' },
        ],
      ],
      { account: responder.account }
    );
    const receipt = await publicClient.waitForTransactionReceipt({
      hash: txHash,
    });

    const events = parseEventLogs({
      abi: chainSignatures.abi,
      logs: receipt.logs,
      eventName: 'SignatureError',
    });
    assert.equal(events.length, 2);
    assert.equal(events[0].args.requestId, requestId1);
    assert.equal(events[0].args.errorMessage, 'First error message');
    assert.equal(events[1].args.requestId, requestId2);
    assert.equal(events[1].args.errorMessage, 'Second error message');
  });
});
