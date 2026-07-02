// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title Test ERC-20 token for the vault example e2e tests
 * @dev Standard OpenZeppelin ERC-20 with a switch that makes `transfer`
 * return `false` without reverting — OpenZeppelin's implementation never
 * does this, and the vault's refund path needs a real on-chain `false`
 * return to be exercised end-to-end.
 */
contract TestERC20 is ERC20 {
    bool public returnFalseOnTransfer;

    constructor() ERC20("Test Token", "TST") {
        _mint(msg.sender, 1_000_000 ether);
    }

    function setReturnFalseOnTransfer(bool value) external {
        returnFalseOnTransfer = value;
    }

    function transfer(address to, uint256 value) public override returns (bool) {
        if (returnFalseOnTransfer) {
            return false;
        }
        return super.transfer(to, value);
    }
}
