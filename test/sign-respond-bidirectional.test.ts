import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  concatHex,
  decodeAbiParameters,
  getAddress,
  keccak256,
  parseEventLogs,
  recoverAddress,
  recoverTransactionAddress,
  serializeTransaction,
  type Hex,
} from 'viem';
import {
  connectAndDeploy,
  SIGNATURE_DEPOSIT,
} from '../test-utils/testSetup.js';
import {
  createBidirectionalArgs,
  buildDestinationTransaction,
  generateBidirectionalRequestId,
  deriveChildAddress,
  mpcSignDigest,
  signatureStructToRsv,
  computeResponseHash,
  hasErrorPrefix,
  ABI_BOOL_TRUE,
  ERROR_PREFIX,
  RESPONSE_KEY_PATH,
} from '../test-utils/signingUtils.js';

const SEPOLIA_CHAIN_ID = 11155111;

void describe('Sign/Respond bidirectional tests', () => {
  void it('Can request a bidirectional cross-chain transaction', async () => {
    const { viem, chainSignatures, requester, chainId } =
      await connectAndDeploy();
    const destinationTx = buildDestinationTransaction(SEPOLIA_CHAIN_ID);
    const args = createBidirectionalArgs(
      serializeTransaction(destinationTx),
      SEPOLIA_CHAIN_ID,
      'request'
    );

    await viem.assertions.emitWithArgs(
      chainSignatures.write.signBidirectional([args], {
        value: SIGNATURE_DEPOSIT,
        account: requester.account,
      }),
      chainSignatures,
      'SignBidirectional',
      [
        getAddress(requester.account.address),
        args.serializedTransaction,
        args.caip2Id,
        args.keyVersion,
        SIGNATURE_DEPOSIT,
        chainId,
        args.path,
        args.algo,
        args.dest,
        args.params,
        args.outputDeserializationSchema,
        args.respondSerializationSchema,
      ]
    );
  });

  void it('Should fail with an empty serialized transaction', async () => {
    const { viem, chainSignatures, requester } = await connectAndDeploy();
    const args = createBidirectionalArgs('0x', SEPOLIA_CHAIN_ID, 'empty');

    await viem.assertions.revertWithCustomError(
      chainSignatures.write.signBidirectional([args], {
        value: SIGNATURE_DEPOSIT,
        account: requester.account,
      }),
      chainSignatures,
      'InvalidTransaction'
    );
  });

  void it('Should fail with insufficient deposit', async () => {
    const { viem, chainSignatures, requester } = await connectAndDeploy();
    const args = createBidirectionalArgs(
      serializeTransaction(buildDestinationTransaction(SEPOLIA_CHAIN_ID)),
      SEPOLIA_CHAIN_ID,
      'deposit'
    );

    await viem.assertions.revertWithCustomError(
      chainSignatures.write.signBidirectional([args], {
        value: SIGNATURE_DEPOSIT - 1n,
        account: requester.account,
      }),
      chainSignatures,
      'InsufficientDeposit'
    );
  });

  void it('Runs the full bidirectional lifecycle with verifiable signatures', async () => {
    const { publicClient, chainSignatures, requester, responder } =
      await connectAndDeploy();

    // 1. The user requests a signature over an unsigned destination-chain tx.
    const destinationTx = buildDestinationTransaction(SEPOLIA_CHAIN_ID);
    const serializedTx = serializeTransaction(destinationTx);
    const args = createBidirectionalArgs(
      serializedTx,
      SEPOLIA_CHAIN_ID,
      'lifecycle'
    );

    await chainSignatures.write.signBidirectional([args], {
      value: SIGNATURE_DEPOSIT,
      account: requester.account,
    });

    // 2. The mock MPC indexes the event, derives the request ID and signs the
    //    destination transaction hash with the child key of (requester, path).
    const requestId = generateBidirectionalRequestId(
      requester.account.address,
      args
    );
    const signingHash = keccak256(serializedTx);
    const txSignature = mpcSignDigest(
      requester.account.address,
      args.path,
      signingHash
    );

    await chainSignatures.write.respond(
      [[{ requestId, signature: txSignature }]],
      { account: responder.account }
    );

    // 3. The user reconstructs the signed destination transaction — it must
    //    broadcast from the derived child address.
    const signedTx = serializeTransaction(
      destinationTx,
      signatureStructToRsv(txSignature)
    );
    const broadcastFrom = await recoverTransactionAddress({
      serializedTransaction: signedTx,
    });
    const derivedAddress = deriveChildAddress(
      requester.account.address,
      args.path
    );
    assert.equal(broadcastFrom, derivedAddress);

    // 4. After observing the destination-chain execution, the MPC publishes
    //    the outcome signed over keccak256(requestId || serializedOutput)
    //    with the response-verification child key.
    const serializedOutput = ABI_BOOL_TRUE;
    const responseHash = computeResponseHash(requestId, serializedOutput);
    const outcomeSignature = mpcSignDigest(
      requester.account.address,
      RESPONSE_KEY_PATH,
      responseHash
    );

    const txHash = await chainSignatures.write.respondBidirectional(
      [requestId, serializedOutput, outcomeSignature],
      { account: responder.account }
    );
    const receipt = await publicClient.waitForTransactionReceipt({
      hash: txHash,
    });

    const events = parseEventLogs({
      abi: chainSignatures.abi,
      logs: receipt.logs,
      eventName: 'RespondBidirectional',
    });
    assert.equal(events.length, 1);
    assert.equal(events[0].args.requestId, requestId);
    assert.equal(
      getAddress(events[0].args.responder),
      getAddress(responder.account.address)
    );
    assert.equal(events[0].args.serializedOutput, serializedOutput);

    // 5. Client-side verification, exactly what a consumer must do: check the
    //    outcome signature against the derived response-verification key,
    //    check the failure prefix, then decode the output.
    const recovered = await recoverAddress({
      hash: computeResponseHash(
        events[0].args.requestId,
        events[0].args.serializedOutput
      ),
      signature: signatureStructToRsv(events[0].args.signature),
    });
    assert.equal(
      recovered,
      deriveChildAddress(requester.account.address, RESPONSE_KEY_PATH)
    );

    assert.equal(hasErrorPrefix(events[0].args.serializedOutput), false);
    const [transferSucceeded] = decodeAbiParameters(
      [{ type: 'bool' }],
      events[0].args.serializedOutput
    );
    assert.equal(transferSucceeded, true);
  });

  void it('Reports failed destination transactions with the error prefix', async () => {
    const { publicClient, chainSignatures, requester, responder } =
      await connectAndDeploy();
    const args = createBidirectionalArgs(
      serializeTransaction(buildDestinationTransaction(SEPOLIA_CHAIN_ID)),
      SEPOLIA_CHAIN_ID,
      'failure'
    );

    await chainSignatures.write.signBidirectional([args], {
      value: SIGNATURE_DEPOSIT,
      account: requester.account,
    });

    const requestId = generateBidirectionalRequestId(
      requester.account.address,
      args
    );

    // Failed transactions are reported as 0xdeadbeef + the serialized failure
    // indicator (mirroring the MPC node's process_failed_tx).
    const serializedOutput: Hex = concatHex([ERROR_PREFIX, ABI_BOOL_TRUE]);
    const responseHash = computeResponseHash(requestId, serializedOutput);
    const outcomeSignature = mpcSignDigest(
      requester.account.address,
      RESPONSE_KEY_PATH,
      responseHash
    );

    const txHash = await chainSignatures.write.respondBidirectional(
      [requestId, serializedOutput, outcomeSignature],
      { account: responder.account }
    );
    const receipt = await publicClient.waitForTransactionReceipt({
      hash: txHash,
    });

    const events = parseEventLogs({
      abi: chainSignatures.abi,
      logs: receipt.logs,
      eventName: 'RespondBidirectional',
    });
    assert.equal(events.length, 1);

    // The signature still verifies; the prefix tells the consumer it failed.
    const recovered = await recoverAddress({
      hash: computeResponseHash(requestId, events[0].args.serializedOutput),
      signature: signatureStructToRsv(events[0].args.signature),
    });
    assert.equal(
      recovered,
      deriveChildAddress(requester.account.address, RESPONSE_KEY_PATH)
    );
    assert.equal(hasErrorPrefix(events[0].args.serializedOutput), true);
  });
});
