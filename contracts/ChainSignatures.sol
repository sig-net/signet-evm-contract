// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title SigNet chain signatures program (EVM)
 * @dev Contract for requesting ECDSA signatures from the SigNet MPC network,
 * supporting both simple signing and bidirectional cross-chain transactions.
 *
 * It mirrors the SigNet Solana program (`signet-solana-program`) and the Canton
 * Signer templates (`signet-signer-v1`): the contract is an event bus plus a
 * deposit sink. It performs no signature verification itself — MPC responses
 * are delivered as events and consumers MUST verify them off-chain (or in
 * their own consumer contracts) against the expected derived MPC key.
 *
 * ## Bidirectional flow
 *
 * The chain-agnostic lifecycle (flow phases, schemas, error convention,
 * key derivation) is documented once at
 * https://docs.sig.network/architecture/sign-bidirectional — the notes
 * below cover only the EVM-specific encoding and verification details.
 *
 * ## Request IDs
 *
 * Request IDs are computed off-chain, never by this contract:
 *
 * - `sign`:
 *   `keccak256(abi.encode(sender, payload, path, keyVersion, block.chainid, algo, dest, params))`
 * - `signBidirectional` (packed, mirroring the Solana program):
 *   `keccak256(abi.encodePacked(sender, serializedTransaction, caip2Id, keyVersion, path, algo, dest, params))`
 *
 * ## Response signature verification (bidirectional)
 *
 * The execution-result signature is made over
 * `keccak256(abi.encodePacked(requestId, serializedOutput))` with the MPC
 * child key derived from the requester using the constant derivation path
 * `"ethereum response key"` (analogous to `"solana response key"` and
 * `"canton response key"` on the other source chains).
 *
 * Failed destination-chain transactions are reported with the magic prefix
 * `0xdeadbeef` at the start of `serializedOutput`.
 */
contract ChainSignatures is AccessControl {
    struct SignRequest {
        bytes32 payload;
        string path;
        uint32 keyVersion;
        string algo;
        string dest;
        string params;
    }

    struct SignBidirectionalRequest {
        bytes serializedTransaction;
        string caip2Id;
        uint32 keyVersion;
        string path;
        string algo;
        string dest;
        string params;
        bytes outputDeserializationSchema;
        bytes respondSerializationSchema;
    }

    struct AffinePoint {
        uint256 x;
        uint256 y;
    }

    struct Signature {
        AffinePoint bigR;
        uint256 s;
        uint8 recoveryId;
    }

    struct Response {
        bytes32 requestId;
        Signature signature;
    }

    struct ErrorResponse {
        bytes32 requestId;
        string errorMessage;
    }

    uint256 signatureDeposit;

    /// @dev Sent value is below the required signature deposit.
    error InsufficientDeposit();
    /// @dev The serialized transaction is empty.
    error InvalidTransaction();
    /// @dev Withdrawal amount exceeds the contract balance.
    error InsufficientFunds();
    /// @dev Withdrawal recipient is the zero address.
    error InvalidRecipient();
    /// @dev Native token transfer failed.
    error TransferFailed();

    /**
     * @dev Emitted when a signature is requested via {sign}.
     * @param sender The address of the sender.
     * @param payload The 32-byte payload to be signed (typically a transaction hash).
     * @param keyVersion The version of the MPC key used for signing.
     * @param deposit The deposit amount paid.
     * @param chainId The EVM chain ID of this contract's chain.
     * @param path The derivation path for the user account.
     * @param algo The algorithm used for signing.
     * @param dest The response destination.
     * @param params Additional parameters.
     */
    event SignatureRequested(
        address sender,
        bytes32 payload,
        uint32 keyVersion,
        uint256 deposit,
        uint256 chainId,
        string path,
        string algo,
        string dest,
        string params
    );

    /**
     * @dev Emitted when a bidirectional cross-chain transaction is requested
     * via {signBidirectional}. The MPC network listens for this event to:
     * 1. Sign the transaction and deliver the signature via {respond}
     * 2. Store the pending transaction for destination-chain observation
     * 3. Monitor the destination chain for confirmation
     * 4. Return the execution result via {respondBidirectional}
     * @param sender The address of the sender.
     * @param serializedTransaction The serialized unsigned transaction for the destination chain.
     * @param caip2Id The CAIP-2 identifier of the destination chain (e.g. "eip155:1").
     * @param keyVersion The version of the MPC key used for signing.
     * @param deposit The deposit amount paid.
     * @param chainId The EVM chain ID of this contract's chain.
     * @param path The derivation path for the user's signing key.
     * @param algo The algorithm used for signing.
     * @param dest The response destination.
     * @param params Additional parameters.
     * @param outputDeserializationSchema Schema for parsing the destination chain output.
     * @param respondSerializationSchema Schema for serializing the response back to this chain.
     */
    event SignBidirectional(
        address sender,
        bytes serializedTransaction,
        string caip2Id,
        uint32 keyVersion,
        uint256 deposit,
        uint256 chainId,
        string path,
        string algo,
        string dest,
        string params,
        bytes outputDeserializationSchema,
        bytes respondSerializationSchema
    );

    /**
     * @dev Emitted when a signature response is received.
     * @notice Any address can emit this event. Clients should always verify the validity of the signature.
     * @param requestId The ID of the request. Must be calculated off-chain.
     * @param responder The address of the responder.
     * @param signature The signature response.
     */
    event SignatureResponded(bytes32 indexed requestId, address responder, Signature signature);

    /**
     * @dev Emitted when the MPC network returns execution results for a
     * bidirectional request via {respondBidirectional}.
     * @notice Any address can emit this event. Clients MUST verify the
     * signature over `keccak256(abi.encodePacked(requestId, serializedOutput))`
     * against the MPC child key derived with the constant path
     * `"ethereum response key"` before trusting the output.
     * @param requestId The ID of the request. Must be calculated off-chain.
     * @param responder The address of the responder.
     * @param serializedOutput The execution output serialized per the request's
     * respondSerializationSchema. Failed destination transactions are prefixed
     * with the 0xdeadbeef error magic.
     * @param signature The signature over `keccak256(abi.encodePacked(requestId, serializedOutput))`.
     */
    event RespondBidirectional(
        bytes32 indexed requestId,
        address responder,
        bytes serializedOutput,
        Signature signature
    );

    /**
     * @dev Emitted when a signature error is received.
     * @notice Any address can emit this event. Do not rely on it for business logic.
     * @param requestId The ID of the request. Must be calculated off-chain.
     * @param responder The address of the responder.
     * @param errorMessage The error message.
     */
    event SignatureError(bytes32 indexed requestId, address responder, string errorMessage);

    /**
     * @dev Emitted when the admin updates the signature deposit via {setSignatureDeposit}.
     * @param oldDeposit The previous deposit amount.
     * @param newDeposit The new deposit amount.
     */
    event DepositUpdated(uint256 oldDeposit, uint256 newDeposit);

    /**
     * @dev Emitted when the admin withdraws funds via {withdraw}.
     * @param amount The amount withdrawn.
     * @param recipient The recipient address.
     */
    event FundsWithdrawn(uint256 amount, address recipient);

    /**
     * @dev Constructor for the ChainSignatures contract.
     * @param _admin The address of the program admin (typically controlled by the MPC network).
     * @param _signatureDeposit The deposit required for signature requests.
     */
    constructor(address _admin, uint256 _signatureDeposit) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        signatureDeposit = _signatureDeposit;
    }

    /**
     * @dev Request a signature from the MPC network on a 32-byte payload.
     *
     * The payload is typically a transaction hash that needs to be signed.
     * The MPC network responds with a signature via {respond}.
     * @param _request The signature request details.
     */
    function sign(SignRequest memory _request) external payable {
        if (msg.value < signatureDeposit) revert InsufficientDeposit();

        emit SignatureRequested(
            msg.sender,
            _request.payload,
            _request.keyVersion,
            msg.value,
            block.chainid,
            _request.path,
            _request.algo,
            _request.dest,
            _request.params
        );
    }

    /**
     * @dev Initiate a bidirectional cross-chain transaction with execution
     * result callback — the primary entry point for cross-chain transactions.
     * The MPC signs and answers via {respond}; the caller broadcasts the signed
     * transaction (the MPC does NOT broadcast); the execution result arrives
     * via {respondBidirectional}. Full lifecycle:
     * https://docs.sig.network/architecture/sign-bidirectional
     * @param _request The bidirectional request details.
     */
    function signBidirectional(SignBidirectionalRequest memory _request) external payable {
        if (msg.value < signatureDeposit) revert InsufficientDeposit();
        if (_request.serializedTransaction.length == 0) revert InvalidTransaction();

        emit SignBidirectional(
            msg.sender,
            _request.serializedTransaction,
            _request.caip2Id,
            _request.keyVersion,
            msg.value,
            block.chainid,
            _request.path,
            _request.algo,
            _request.dest,
            _request.params,
            _request.outputDeserializationSchema,
            _request.respondSerializationSchema
        );
    }

    /**
     * @dev Respond to signature requests with generated signatures. Called by
     * MPC responders after signature generation; supports batched responses.
     * @notice Any address can call this function. Clients must verify signature
     * validity by recovering the public key and comparing with the expected
     * derived MPC key.
     * @param _responses The array of signature responses.
     */
    function respond(Response[] calldata _responses) external {
        for (uint256 i = 0; i < _responses.length; i++) {
            emit SignatureResponded(_responses[i].requestId, msg.sender, _responses[i].signature);
        }
    }

    /**
     * @dev Finalize a bidirectional flow with execution results from the
     * destination chain. Called by MPC responders after observing transaction
     * confirmation on the destination chain.
     * @notice Any address can call this function. Clients must verify the
     * signature before trusting the output — see {RespondBidirectional}.
     * @param _requestId The original request identifier.
     * @param _serializedOutput The execution output serialized per the request's
     * respondSerializationSchema. For failed destination transactions the output
     * carries the magic prefix 0xdeadbeef.
     * @param _signature The signature over `keccak256(abi.encodePacked(_requestId, _serializedOutput))`.
     */
    function respondBidirectional(
        bytes32 _requestId,
        bytes calldata _serializedOutput,
        Signature calldata _signature
    ) external {
        emit RespondBidirectional(_requestId, msg.sender, _serializedOutput, _signature);
    }

    /**
     * @dev Report signature generation errors from the MPC network.
     * @notice Solely for debugging purposes. Any address can call this
     * function; error events are not cryptographically verified and must not
     * be relied upon for business logic.
     * @param _errors The array of signature generation errors.
     */
    function respondError(ErrorResponse[] calldata _errors) external {
        for (uint256 i = 0; i < _errors.length; i++) {
            emit SignatureError(_errors[i].requestId, msg.sender, _errors[i].errorMessage);
        }
    }

    /**
     * @dev Get the current signature deposit amount.
     * @return The current signature deposit amount.
     */
    function getSignatureDeposit() external view returns (uint256) {
        return signatureDeposit;
    }

    /**
     * @dev Update the required signature deposit amount. Admin only.
     * @param _amount The new deposit amount.
     */
    function setSignatureDeposit(uint256 _amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 oldDeposit = signatureDeposit;
        signatureDeposit = _amount;

        emit DepositUpdated(oldDeposit, _amount);
    }

    /**
     * @dev Withdraw accumulated funds from the contract. Admin only.
     * @param _amount The amount to withdraw.
     * @param _receiver The address to receive the withdrawn funds.
     */
    function withdraw(uint256 _amount, address _receiver) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_receiver == address(0)) revert InvalidRecipient();
        if (_amount > address(this).balance) revert InsufficientFunds();

        (bool success, ) = payable(_receiver).call{ value: _amount }("");
        if (!success) revert TransferFailed();

        emit FundsWithdrawn(_amount, _receiver);
    }
}
