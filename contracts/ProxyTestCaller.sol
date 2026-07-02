// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./ChainSignatures.sol";

/**
 * @title Proxy test caller
 * @dev Test contract that forwards signature requests to the ChainSignatures
 * contract through an external call — the EVM analog of the Solana
 * `proxy-test-cpi` program, demonstrating how a consumer contract integrates.
 *
 * Note the key difference from Solana CPI: on the EVM the proxy contract
 * itself becomes `msg.sender` of the forwarded call, so the emitted event's
 * `sender` (and therefore the request ID and the MPC key-derivation
 * predecessor) is THIS contract's address, not the originating wallet. This
 * matches how real EVM consumer contracts own their derived MPC keys.
 */
contract ProxyTestCaller {
    ChainSignatures public immutable signetContract;

    constructor(address _signetContract) {
        signetContract = ChainSignatures(_signetContract);
    }

    /**
     * @dev Forward a simple signature request, passing the sent value through
     * as the deposit.
     * @param _request The signature request details.
     */
    function callSign(ChainSignatures.SignRequest memory _request) external payable {
        signetContract.sign{ value: msg.value }(_request);
    }

    /**
     * @dev Forward a bidirectional signature request, passing the sent value
     * through as the deposit.
     * @param _request The bidirectional request details.
     */
    function callSignBidirectional(
        ChainSignatures.SignBidirectionalRequest memory _request
    ) external payable {
        signetContract.signBidirectional{ value: msg.value }(_request);
    }
}
