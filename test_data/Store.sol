// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Store {
    uint256 public value;

    function set(uint256 x) external {
        value = x;
    }
}

