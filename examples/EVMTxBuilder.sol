// SPDX-License-Identifier: MIT
// Vendored from sig-net/signet.sol (contracts/libraries/EVMTxBuilder.sol),
// where it is validated byte-for-byte against viem's serializeTransaction.
pragma solidity ^0.8.20;

import { Lib_RLPWriter as RLPWriter } from "@eth-optimism/contracts/libraries/rlp/Lib_RLPWriter.sol";

/**
 * @title EVMTxBuilder
 * @notice Minimal library for building EIP-1559 (type-2) transaction payloads on-chain.
 * @dev Serialization uses Optimism's Lib_RLPWriter. This library does not sign transactions.
 * Use {hashEvmTx} on the result of {serializeEvmTxUnsigned} and sign off-chain.
 * Only EIP-1559 transactions are supported.
 */
library EVMTxBuilder {
    uint8 constant EIP_1559_TYPE = 2;

    /**
     * @dev Access list entry for EIP-2930/EIP-1559 transactions.
     * @param addr Address whose storage is accessed
     * @param storageKeys Array of 32-byte storage keys accessed for the address
     */
    struct AccessListEntry {
        address addr;
        bytes32[] storageKeys;
    }

    /**
     * @dev Compact signature components used by typed transactions.
     * @param v y-parity (0 or 1) for EIP-1559
     * @param r Secp256k1 signature r value
     * @param s Secp256k1 signature s value
     */
    struct Signature {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /**
     * @dev Representation of an EIP-1559 transaction prior to signing.
     * @param chainId Chain identifier
     * @param nonce Sender's nonce
     * @param to Recipient (omit by setting hasTo=false for contract creation)
     * @param hasTo Whether the `to` field is present
     * @param value Native token amount in wei
     * @param input Calldata bytes
     * @param gasLimit Maximum gas provided
     * @param maxFeePerGas Max fee per gas (ceiling)
     * @param maxPriorityFeePerGas Priority fee per gas (tip)
     * @param accessList Optional access list entries
     */
    struct EVMTransaction {
        uint256 chainId;
        uint256 nonce;
        address to;
        bool hasTo;
        uint256 value;
        bytes input;
        uint256 gasLimit;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        AccessListEntry[] accessList;
    }

    /**
     * @notice Serializes an EIP-1559 transaction without a signature.
     * @param evmTx Transaction fields to serialize
     * @return RLP-encoded payload prefixed with the EIP-1559 type byte
     */
    function serializeEvmTxUnsigned(
        EVMTransaction memory evmTx
    ) internal pure returns (bytes memory) {
        bytes memory result = new bytes(1);
        result[0] = bytes1(EIP_1559_TYPE);

        bytes memory encodedFields = encodeFields(evmTx);

        return bytes.concat(result, encodedFields);
    }

    /**
     * @notice Serializes an EIP-1559 transaction and appends a compact signature.
     * @param evmTx Transaction fields to serialize
     * @param signature Compact signature (y-parity, r, s)
     * @return RLP-encoded payload prefixed with the EIP-1559 type byte
     */
    function serializeEvmTxSigned(
        EVMTransaction memory evmTx,
        Signature memory signature
    ) internal pure returns (bytes memory) {
        bytes memory result = new bytes(1);
        result[0] = bytes1(EIP_1559_TYPE);

        bytes memory encodedFieldsWithSignature = encodeFieldsWithSignature(evmTx, signature);

        return bytes.concat(result, encodedFieldsWithSignature);
    }

    /**
     * @dev Encodes the 9 core EIP-1559 fields as a single RLP list.
     * @param evmTx The transaction to encode
     * @return RLP-encoded list of core fields
     */
    function encodeFields(EVMTransaction memory evmTx) internal pure returns (bytes memory) {
        return RLPWriter.writeList(_coreElements(evmTx));
    }

    /**
     * @dev Encodes the 9 core fields plus the compact signature as a single RLP list.
     * @param evmTx The transaction to encode
     * @param signature The signature to include
     * @return RLP-encoded list of core fields plus signature
     */
    function encodeFieldsWithSignature(
        EVMTransaction memory evmTx,
        Signature memory signature
    ) internal pure returns (bytes memory) {
        bytes[] memory base = _coreElements(evmTx);
        bytes[] memory elements = new bytes[](12);
        for (uint i = 0; i < base.length; ) {
            elements[i] = base[i];
            unchecked {
                ++i;
            }
        }
        elements[9] = RLPWriter.writeUint(uint(signature.v));
        elements[10] = RLPWriter.writeBytes(abi.encodePacked(signature.r));
        elements[11] = RLPWriter.writeBytes(abi.encodePacked(signature.s));
        return RLPWriter.writeList(elements);
    }

    /**
     * @dev Produces the 9 core EIP-1559 transaction fields as RLP elements.
     * @param evmTx Transaction fields to serialize
     * @return elements Array of 9 RLP-encoded core fields
     */
    function _coreElements(
        EVMTransaction memory evmTx
    ) internal pure returns (bytes[] memory elements) {
        elements = new bytes[](9);
        elements[0] = RLPWriter.writeUint(uint(evmTx.chainId));
        elements[1] = RLPWriter.writeUint(uint(evmTx.nonce));
        elements[2] = RLPWriter.writeUint(uint(evmTx.maxPriorityFeePerGas));
        elements[3] = RLPWriter.writeUint(uint(evmTx.maxFeePerGas));
        elements[4] = RLPWriter.writeUint(uint(evmTx.gasLimit));
        if (evmTx.hasTo) {
            elements[5] = RLPWriter.writeAddress(evmTx.to);
        } else {
            elements[5] = RLPWriter.writeBytes("");
        }
        elements[6] = RLPWriter.writeUint(uint(evmTx.value));
        elements[7] = RLPWriter.writeBytes(evmTx.input);
        elements[8] = _writeAccessList(evmTx.accessList);
        return elements;
    }

    /**
     * @notice Computes the keccak256 hash of serialized transaction bytes.
     * @dev Pass the output of {serializeEvmTxUnsigned} here to obtain the digest for off-chain signing.
     * @param txBytes RLP-encoded transaction bytes (including type byte)
     * @return digest The 32-byte keccak256 hash to sign
     */
    function hashEvmTx(bytes memory txBytes) internal pure returns (bytes32) {
        return keccak256(txBytes);
    }

    /**
     * @dev Encodes an access list as per EIP-2930/EIP-1559.
     * @param accessList Array of entries, each with an address and storage keys
     * @return Encoded RLP list for the access list
     */
    function _writeAccessList(
        AccessListEntry[] memory accessList
    ) internal pure returns (bytes memory) {
        if (accessList.length == 0) {
            bytes[] memory empty = new bytes[](0);
            return RLPWriter.writeList(empty);
        }
        bytes[] memory elements = new bytes[](accessList.length);
        for (uint i = 0; i < accessList.length; ) {
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLPWriter.writeAddress(accessList[i].addr);

            bytes[] memory keys = new bytes[](accessList[i].storageKeys.length);
            for (uint j = 0; j < accessList[i].storageKeys.length; ) {
                keys[j] = RLPWriter.writeBytes(abi.encodePacked(accessList[i].storageKeys[j]));
                unchecked {
                    ++j;
                }
            }
            entry[1] = RLPWriter.writeList(keys);
            elements[i] = RLPWriter.writeList(entry);
            unchecked {
                ++i;
            }
        }
        return RLPWriter.writeList(elements);
    }
}
