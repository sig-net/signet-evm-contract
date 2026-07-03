// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { EVMTransactionLib } from "signet.sol/contracts/evm/EVMTransactionLib.sol";

import { ChainSignatures } from "../contracts/ChainSignatures.sol";

/**
 * @title ERC-20 cross-chain vault (EVM -> EVM example)
 * @dev Example consumer of the ChainSignatures contract implementing ERC-20
 * custody on a destination EVM chain, mirroring the Solana
 * `solana-contract-examples` ERC-20 vault (deposit / claim / withdraw /
 * complete-withdraw) and the Canton `signet-vault-v1` package.
 *
 * ## Key model
 *
 * All MPC child keys are derived with THIS contract's address as the KDF
 * predecessor (it is the `sender` of every `signBidirectional` call):
 *
 * | Key                       | Derivation path             | Holds                          |
 * | ------------------------- | --------------------------- | ------------------------------ |
 * | Per-user deposit address  | `"0x<user address hex>"`    | User's pre-deposit funds       |
 * | Vault address             | `"root"`                    | Custodied ERC-20 on dest chain |
 * | Response verification key | `"ethereum response key"`   | Signs MPC outcome reports      |
 *
 * `vaultEvmAddress` and `responseSigner` are derived off-chain (signet.js
 * `deriveChildPublicKey`) and pinned once via {initialize} — the predecessor
 * is this contract's address, which is only known after deployment. This
 * mirrors the Canton Vault, which stores `evmVaultAddress` and
 * `mpcResponseVerifyKey` at creation. (The Solana example instead derives
 * addresses on-chain via a secp256k1_recover trick; the EVM `ecrecover`
 * precompile only returns addresses, not curve points, so on-chain point
 * addition is not available without a full EC library.)
 *
 * ## Deposit flow
 *
 * 1. The user funds their derived deposit address on the destination chain.
 * 2. {depositErc20} builds the ERC-20 `transfer(vaultEvmAddress, amount)`
 *    transaction on-chain, records a single-use pending entry keyed by the
 *    request ID, and requests the MPC signature via `signBidirectional`.
 * 3. The MPC signs (delivered via `respond`); the user broadcasts the signed
 *    transaction to the destination chain.
 * 4. The MPC observes execution and reports the outcome via
 *    `respondBidirectional`; {claimErc20} verifies the outcome signature
 *    on-chain and credits the user's vault balance.
 *
 * ## Withdrawal flow
 *
 * 1. {withdrawErc20} optimistically debits the user's balance, builds the
 *    `transfer(recipient, amount)` transaction from the vault address
 *    (path `"root"`), and requests the signature.
 * 2. After broadcast + observation, {completeWithdrawErc20} verifies the
 *    outcome: on failure (0xdeadbeef prefix or `false` return) the balance
 *    is refunded.
 */
contract Erc20Vault is Ownable {
    /// @dev Destination-chain EIP-1559 fee/nonce parameters supplied by the
    /// caller (fetched off-chain), mirroring the Solana example's
    /// `EvmTransactionParams`.
    struct EvmTransactionParams {
        uint64 chainId;
        uint64 nonce;
        uint128 value;
        uint128 gasLimit;
        uint128 maxFeePerGas;
        uint128 maxPriorityFeePerGas;
    }

    struct PendingDeposit {
        address requester;
        address erc20Address;
        uint128 amount;
        bool exists;
    }

    struct PendingWithdrawal {
        address requester;
        address erc20Address;
        address recipientAddress;
        uint128 amount;
        bool exists;
    }

    uint32 public constant KEY_VERSION = 1;
    string public constant ROOT_PATH = "root";
    string internal constant ALGO = "ECDSA";
    string internal constant DEST = "ethereum";
    string internal constant PARAMS = "";
    /// @dev JSON ABI schema for the ERC-20 `transfer` bool return value, used
    /// both to parse the destination output and to serialize the response.
    bytes internal constant BOOL_SCHEMA = '[{"name":"","type":"bool"}]';
    /// @dev Magic prefix the MPC prepends to outputs of failed transactions.
    bytes4 internal constant ERROR_PREFIX = 0xdeadbeef;

    ChainSignatures public immutable chainSignatures;

    /// @dev Vault custody address on the destination chain — MPC child key
    /// (predecessor = this contract, path = "root").
    address public vaultEvmAddress;
    /// @dev Signer of MPC outcome reports — MPC child key (predecessor = this
    /// contract, path = "ethereum response key").
    address public responseSigner;
    bool public initialized;

    mapping(bytes32 requestId => PendingDeposit) public pendingDeposits;
    mapping(bytes32 requestId => PendingWithdrawal) public pendingWithdrawals;
    mapping(address user => mapping(address erc20 => uint128)) public userBalances;

    error NotInitialized();
    error AlreadyInitialized();
    error InvalidAddress();
    error DuplicateRequest();
    error UnknownRequest();
    error InvalidSignature();
    error InvalidOutput();
    error DepositFailed();
    error TransferReturnedFalse();
    error InsufficientBalance();

    event DepositInitiated(
        bytes32 indexed requestId,
        address indexed requester,
        address erc20Address,
        uint128 amount,
        string path
    );

    event DepositClaimed(
        bytes32 indexed requestId,
        address indexed requester,
        address erc20Address,
        uint128 amount
    );

    event WithdrawalInitiated(
        bytes32 indexed requestId,
        address indexed requester,
        address erc20Address,
        uint128 amount,
        address recipientAddress
    );

    event WithdrawalCompleted(bytes32 indexed requestId, address indexed requester, bool refunded);

    constructor(address _chainSignatures, address _owner) Ownable(_owner) {
        chainSignatures = ChainSignatures(_chainSignatures);
    }

    /**
     * @dev One-time pinning of the off-chain-derived MPC child addresses.
     * Both are derived from the MPC root public key with THIS contract's
     * address as predecessor (see contract docs), so they can only be
     * computed after deployment.
     * @param _vaultEvmAddress Child address for path "root".
     * @param _responseSigner Child address for path "ethereum response key".
     */
    function initialize(address _vaultEvmAddress, address _responseSigner) external onlyOwner {
        if (initialized) revert AlreadyInitialized();
        if (_vaultEvmAddress == address(0) || _responseSigner == address(0))
            revert InvalidAddress();
        vaultEvmAddress = _vaultEvmAddress;
        responseSigner = _responseSigner;
        initialized = true;
    }

    /**
     * @dev Initiate an ERC-20 deposit: request an MPC signature over a
     * `transfer(vaultEvmAddress, amount)` from the user's derived deposit
     * address on the destination chain. The recipient is always the vault
     * address — it cannot be caller-supplied.
     * @param erc20Address The ERC-20 token contract on the destination chain.
     * @param amount The token amount to deposit.
     * @param txParams Destination-chain fee/nonce parameters for the deposit
     * address (fetched off-chain).
     * @return requestId The request identifier tracking this deposit.
     */
    function depositErc20(
        address erc20Address,
        uint128 amount,
        EvmTransactionParams calldata txParams
    ) external payable returns (bytes32 requestId) {
        if (!initialized) revert NotInitialized();

        // Per-user key namespace: path = lowercase hex of the user address.
        string memory path = Strings.toHexString(msg.sender);
        bytes memory rlpTx = _buildErc20TransferTx(erc20Address, vaultEvmAddress, amount, txParams);
        string memory caip2Id = _caip2Id(txParams.chainId);

        requestId = _computeRequestId(rlpTx, caip2Id, path);
        if (pendingDeposits[requestId].exists) revert DuplicateRequest();
        pendingDeposits[requestId] = PendingDeposit({
            requester: msg.sender,
            erc20Address: erc20Address,
            amount: amount,
            exists: true
        });

        _requestSignature(rlpTx, caip2Id, path);

        emit DepositInitiated(requestId, msg.sender, erc20Address, amount, path);
    }

    /**
     * @dev Claim a deposit after the MPC reported the destination-chain
     * outcome. Verifies the outcome signature against {responseSigner} and
     * credits the requester's balance on success.
     * @param requestId The deposit request identifier.
     * @param serializedOutput The MPC-reported output (ABI-encoded bool).
     * @param signature The MPC signature over
     * `keccak256(abi.encodePacked(requestId, serializedOutput))`.
     */
    function claimErc20(
        bytes32 requestId,
        bytes calldata serializedOutput,
        ChainSignatures.Signature calldata signature
    ) external {
        PendingDeposit memory pending = pendingDeposits[requestId];
        if (!pending.exists) revert UnknownRequest();
        // Delete first: single-use guarantee against outcome replay.
        delete pendingDeposits[requestId];

        _verifyResponseSignature(requestId, serializedOutput, signature);

        if (_hasErrorPrefix(serializedOutput)) revert DepositFailed();
        if (!_decodeAbiBool(serializedOutput)) revert TransferReturnedFalse();

        userBalances[pending.requester][pending.erc20Address] += pending.amount;

        emit DepositClaimed(requestId, pending.requester, pending.erc20Address, pending.amount);
    }

    /**
     * @dev Initiate an ERC-20 withdrawal: optimistically debit the caller's
     * balance and request an MPC signature over a
     * `transfer(recipientAddress, amount)` from the vault address
     * (path "root") on the destination chain.
     * @param erc20Address The ERC-20 token contract on the destination chain.
     * @param amount The token amount to withdraw.
     * @param recipientAddress The destination-chain recipient.
     * @param txParams Destination-chain fee/nonce parameters for the vault
     * address (fetched off-chain).
     * @return requestId The request identifier tracking this withdrawal.
     */
    function withdrawErc20(
        address erc20Address,
        uint128 amount,
        address recipientAddress,
        EvmTransactionParams calldata txParams
    ) external payable returns (bytes32 requestId) {
        if (!initialized) revert NotInitialized();
        if (recipientAddress == address(0)) revert InvalidAddress();
        if (userBalances[msg.sender][erc20Address] < amount) revert InsufficientBalance();

        // Optimistic debit: refunded by completeWithdrawErc20 on failure.
        userBalances[msg.sender][erc20Address] -= amount;

        bytes memory rlpTx = _buildErc20TransferTx(
            erc20Address,
            recipientAddress,
            amount,
            txParams
        );
        string memory caip2Id = _caip2Id(txParams.chainId);

        requestId = _computeRequestId(rlpTx, caip2Id, ROOT_PATH);
        if (pendingWithdrawals[requestId].exists) revert DuplicateRequest();
        pendingWithdrawals[requestId] = PendingWithdrawal({
            requester: msg.sender,
            erc20Address: erc20Address,
            recipientAddress: recipientAddress,
            amount: amount,
            exists: true
        });

        _requestSignature(rlpTx, caip2Id, ROOT_PATH);

        emit WithdrawalInitiated(requestId, msg.sender, erc20Address, amount, recipientAddress);
    }

    /**
     * @dev Complete a withdrawal after the MPC reported the destination-chain
     * outcome. Verifies the outcome signature against {responseSigner}; on
     * failure (0xdeadbeef prefix or `false` return value) the optimistically
     * debited balance is refunded.
     * @param requestId The withdrawal request identifier.
     * @param serializedOutput The MPC-reported output (ABI-encoded bool,
     * possibly prefixed with the 0xdeadbeef error magic).
     * @param signature The MPC signature over
     * `keccak256(abi.encodePacked(requestId, serializedOutput))`.
     */
    function completeWithdrawErc20(
        bytes32 requestId,
        bytes calldata serializedOutput,
        ChainSignatures.Signature calldata signature
    ) external {
        PendingWithdrawal memory pending = pendingWithdrawals[requestId];
        if (!pending.exists) revert UnknownRequest();
        delete pendingWithdrawals[requestId];

        _verifyResponseSignature(requestId, serializedOutput, signature);

        bool refunded = _hasErrorPrefix(serializedOutput) || !_decodeAbiBool(serializedOutput);
        if (refunded) {
            userBalances[pending.requester][pending.erc20Address] += pending.amount;
        }

        emit WithdrawalCompleted(requestId, pending.requester, refunded);
    }

    /**
     * @dev Build the RLP-encoded unsigned EIP-1559 ERC-20 `transfer` for the
     * destination chain.
     */
    function _buildErc20TransferTx(
        address erc20Address,
        address recipient,
        uint128 amount,
        EvmTransactionParams calldata txParams
    ) internal pure returns (bytes memory) {
        // EVMTransactionLib encodes `to == address(0)` as contract creation,
        // which must not be expressible through the vault.
        if (erc20Address == address(0)) revert InvalidAddress();
        EVMTransactionLib.EVMTransaction memory evmTx = EVMTransactionLib.EVMTransaction({
            chainId: txParams.chainId,
            nonce: txParams.nonce,
            maxPriorityFeePerGas: txParams.maxPriorityFeePerGas,
            maxFeePerGas: txParams.maxFeePerGas,
            gasLimit: txParams.gasLimit,
            to: erc20Address,
            value: txParams.value,
            input: abi.encodeCall(IERC20.transfer, (recipient, amount)),
            accessList: new EVMTransactionLib.AccessListEntry[](0)
        });
        return EVMTransactionLib.buildForSigning(evmTx);
    }

    /// @dev CAIP-2 identifier for the destination chain, e.g. "eip155:11155111".
    function _caip2Id(uint64 chainId) internal pure returns (string memory) {
        return string.concat("eip155:", Strings.toString(chainId));
    }

    /**
     * @dev Bidirectional request ID (this contract is the sender):
     * keccak256(abi.encodePacked(sender, serializedTransaction, caip2Id,
     * keyVersion, path, algo, dest, params)).
     */
    function _computeRequestId(
        bytes memory rlpTx,
        string memory caip2Id,
        string memory path
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    address(this),
                    rlpTx,
                    caip2Id,
                    KEY_VERSION,
                    path,
                    ALGO,
                    DEST,
                    PARAMS
                )
            );
    }

    /// @dev Forward the request (and the signature deposit) to ChainSignatures.
    function _requestSignature(
        bytes memory rlpTx,
        string memory caip2Id,
        string memory path
    ) internal {
        chainSignatures.signBidirectional{ value: msg.value }(
            ChainSignatures.SignBidirectionalRequest({
                serializedTransaction: rlpTx,
                caip2Id: caip2Id,
                keyVersion: KEY_VERSION,
                path: path,
                algo: ALGO,
                dest: DEST,
                params: PARAMS,
                outputDeserializationSchema: BOOL_SCHEMA,
                respondSerializationSchema: BOOL_SCHEMA
            })
        );
    }

    /**
     * @dev Verify the MPC outcome signature: recover the signer of
     * `keccak256(abi.encodePacked(requestId, serializedOutput))` and compare
     * against the pinned response-verification address.
     */
    function _verifyResponseSignature(
        bytes32 requestId,
        bytes calldata serializedOutput,
        ChainSignatures.Signature calldata signature
    ) internal view {
        if (signature.recoveryId > 1) revert InvalidSignature();
        bytes32 messageHash = keccak256(abi.encodePacked(requestId, serializedOutput));
        address recovered = ecrecover(
            messageHash,
            uint8(27 + signature.recoveryId),
            bytes32(signature.bigR.x),
            bytes32(signature.s)
        );
        if (recovered == address(0) || recovered != responseSigner) revert InvalidSignature();
    }

    /// @dev True when the output carries the 0xdeadbeef failure prefix.
    function _hasErrorPrefix(bytes calldata serializedOutput) internal pure returns (bool) {
        return serializedOutput.length >= 4 && bytes4(serializedOutput[:4]) == ERROR_PREFIX;
    }

    /**
     * @dev Strict ABI bool decoding: exactly one 32-byte slot holding 0 or 1
     * (fail-closed, matching the Canton vault's abiDecodeBool).
     */
    function _decodeAbiBool(bytes calldata serializedOutput) internal pure returns (bool) {
        if (serializedOutput.length != 32) revert InvalidOutput();
        uint256 word = uint256(bytes32(serializedOutput));
        if (word > 1) revert InvalidOutput();
        return word == 1;
    }
}
