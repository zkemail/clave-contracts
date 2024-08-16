pragma solidity ^0.8.17;

import {L2ContractHelper} from '@matterlabs/zksync-contracts/l2/contracts/L2ContractHelper.sol';
import {DEPLOYER_SYSTEM_CONTRACT, IContractDeployer} from '@matterlabs/zksync-contracts/l2/system-contracts/Constants.sol';
import {SystemContractsCaller} from '@matterlabs/zksync-contracts/l2/system-contracts/libraries/SystemContractsCaller.sol';

import {EmailAuth, ERC1967Proxy, Create2} from '../EmailRecoveryManager.sol';

import "hardhat/console.sol";

contract Create2Address {

    EmailAuth emailAuth;
    bytes32 proxyBytecodeHash;
    address deployedProxyAddress;

    constructor() {
        console.log("constructor");
        emailAuth = new EmailAuth();
        proxyBytecodeHash = bytes32(0x010000795a7a1b6b550a8127b91748f90a87ac71b8861dce434b11125da32175);
    }

    function emailAuthImplementation() public view returns (address) {
        console.log("emailAuthImplementation");
        return address(emailAuth);
    }

    function chainId() public view returns (uint256) {
        return block.chainid;
    }

    function getDeployedProxyAddress() public view returns (address) {
        return deployedProxyAddress;
    }

    // These function is copied from EmailRecoveryManager.sol.
    // There are some little differences for testing, but the logic is the same.

    /// @notice Computes the address for email auth contract using the CREATE2 opcode.
    /// @dev This function utilizes the `Create2` library to compute the address. The computation uses a provided account address to be recovered, account salt,
    /// and the hash of the encoded ERC1967Proxy creation code concatenated with the encoded email auth contract implementation
    /// address and the initialization call data. This ensures that the computed address is deterministic and unique per account salt.
    /// @param recoveredAccount The address of the account to be recovered.
    /// @param accountSalt A bytes32 salt value, which is assumed to be unique to a pair of the guardian's email address and the wallet address to be recovered.
    /// @return address The computed address.
    function computeEmailAuthAddress(
        address recoveredAccount,
        bytes32 accountSalt
    ) public view returns (address) {
        // If on zksync, we use L2ContractHelper.computeCreate2Address
        // if (block.chainid == 324 || block.chainid == 300) {
            // TODO: The bytecodeHash is hardcoded here because type(ERC1967Proxy).creationCode doesn't work on eraVM currently
            // If you failed some test cases, check the bytecodeHash by yourself
            // see, test/ComputeCreate2Address.t.sol
            return
                L2ContractHelper.computeCreate2Address(
                    address(this),
                    accountSalt,
                    bytes32(0x010000795a7a1b6b550a8127b91748f90a87ac71b8861dce434b11125da32175),
                    keccak256(
                        abi.encode(
                            emailAuthImplementation(),
                            abi.encodeCall(
                                EmailAuth.initialize,
                                (recoveredAccount, accountSalt, address(this))
                            )
                        )
                    )
                );
        // } else {
        //     return
        //         Create2.computeAddress(
        //             accountSalt,
        //             keccak256(
        //                 abi.encodePacked(
        //                     type(ERC1967Proxy).creationCode,
        //                     abi.encode(
        //                         emailAuthImplementation(),
        //                         abi.encodeCall(
        //                             EmailAuth.initialize,
        //                             (recoveredAccount, accountSalt, address(this))
        //                         )
        //                     )
        //                 )
        //             )
        //         );
        // }
    }

    function deployProxy(address recoveredAccount, bytes32 accountSalt) public returns (address) {
        (bool success, bytes memory returnData) = SystemContractsCaller
            .systemCallWithReturndata(
                uint32(gasleft()),
                address(DEPLOYER_SYSTEM_CONTRACT),
            uint128(0),
            abi.encodeCall(
                DEPLOYER_SYSTEM_CONTRACT.create2,
                (
                    accountSalt,
                    proxyBytecodeHash,
                    abi.encode(
                                emailAuthImplementation(),
                                abi.encodeCall(
                                    EmailAuth.initialize,
                                    (
                                recoveredAccount,
                                accountSalt,
                                address(this)
                            )
                        )
                    )
                )
            )
        );
        address payable proxyAddress = abi.decode(returnData, (address));
        console.log("proxyAddress", proxyAddress);
        deployedProxyAddress = proxyAddress;
        // ERC1967Proxy proxy = ERC1967Proxy(proxyAddress);
        // guardianEmailAuth = EmailAuth(address(proxy));
        return address(proxyAddress);
    }
}