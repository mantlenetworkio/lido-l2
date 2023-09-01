// SPDX-FileCopyrightText: 2022 Lido <info@lido.fi>
// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.10;

import {ERC20Bridged} from "./ERC20Bridged.sol";
import {IERC2612} from "@openzeppelin/contracts/interfaces/draft-IERC2612.sol";

/// @author 0xMantle
/// @notice Extends the ERC20 functionality that allows the bridge to mint/burn tokens
contract ERC20BridgedPermit is ERC20Bridged, IERC2612 {
    mapping(address => uint256) public override nonces;

    bytes32 public immutable PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 public immutable DOMAIN_SEPARATOR;

    constructor(string memory name_, string memory symbol_, uint8 decimals_, address bridge_)
        ERC20Bridged(name_, symbol_, decimals_, bridge_)
    {
        uint256 chainId;

        assembly {
            chainId := chainid()
        }

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name_)),
                keccak256(bytes(version())),
                chainId,
                address(this)
            )
        );
    }

    function version() public pure virtual returns (string memory) {
        return "1";
    }

    function permit(address owner, address spender, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        public
        virtual
        override
    {
        require(deadline >= block.timestamp, "ERC20Permit: expired deadline");

        bytes32 hashStruct = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, amount, nonces[owner]++, deadline));

        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));

        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0) && signer == owner, "ERC20Permit: invalid signature");

        _approve(owner, spender, amount);
    }
}
