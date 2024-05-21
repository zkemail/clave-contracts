// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import {IAccount, ACCOUNT_VALIDATION_SUCCESS_MAGIC} from '@matterlabs/zksync-contracts/l2/system-contracts/interfaces/IAccount.sol';
import {Transaction, TransactionHelper} from '@matterlabs/zksync-contracts/l2/system-contracts/libraries/TransactionHelper.sol';
import {EfficientCall} from '@matterlabs/zksync-contracts/l2/system-contracts/libraries/EfficientCall.sol';
import {NONCE_HOLDER_SYSTEM_CONTRACT, DEPLOYER_SYSTEM_CONTRACT, INonceHolder} from '@matterlabs/zksync-contracts/l2/system-contracts/Constants.sol';
import {SystemContractsCaller} from '@matterlabs/zksync-contracts/l2/system-contracts/libraries/SystemContractsCaller.sol';
import {Utils} from '@matterlabs/zksync-contracts/l2/system-contracts/libraries/Utils.sol';
import {Initializable} from '@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol';

import {HookManager} from './managers/HookManager.sol';
import {ModuleManager} from './managers/ModuleManager.sol';
import {UpgradeManager} from './managers/UpgradeManager.sol';

import {TokenCallbackHandler, IERC165} from './helpers/TokenCallbackHandler.sol';

import {Errors} from './libraries/Errors.sol';
import {SignatureDecoder} from './libraries/SignatureDecoder.sol';

import {ERC1271Handler} from './handlers/ERC1271Handler.sol';
import {Call} from './batch/BatchCaller.sol';

import {IClaveAccount} from './interfaces/IClave.sol';

import {EmailAccountRecovery} from './email-auth/EmailAccountRecovery.sol';
/**
 * @title Main account contract for the Clave wallet infrastructure in zkSync Era
 * @author https://getclave.io
 */
contract ClaveImplementation is
    Initializable,
    UpgradeManager,
    HookManager,
    ModuleManager,
    ERC1271Handler,
    TokenCallbackHandler,
    IClaveAccount,
    EmailAccountRecovery
{
    // Helper library for the Transaction struct
    using TransactionHelper for Transaction;
    // Batch transaction helper contract
    address private immutable _BATCH_CALLER;

    /**
     * @notice Constructor for the account implementation
     * @param batchCaller address - Batch transaction helper contract
     */
    constructor(address batchCaller) {
        _BATCH_CALLER = batchCaller;
        _disableInitializers();
    }

    /**
     * @notice Initializer function for the account contract
     * @param initialR1Owner bytes calldata - The initial r1 owner of the account
     * @param initialR1Validator address    - The initial r1 validator of the account
     * @param modules bytes[] calldata      - The list of modules to enable for the account
     * @param initCall Call calldata         - The initial call to be executed after the account is created
     */
    function initialize(
        bytes calldata initialR1Owner,
        address initialR1Validator,
        bytes[] calldata modules,
        Call calldata initCall,
        address _verifier,
        address _dkim,
        address _emailAuthImplementation
    ) external initializer {
        _r1AddOwner(initialR1Owner);
        _r1AddValidator(initialR1Validator);

        for (uint256 i = 0; i < modules.length; ) {
            _addModule(modules[i]);
            unchecked {
                i++;
            }
        }

        if (initCall.target != address(0)) {
            uint128 value = Utils.safeCastToU128(initCall.value);
            _executeCall(initCall.target, value, initCall.callData, initCall.allowFailure);
        }

        isRecovering = false;
        verifierAddr = _verifier;
        dkimAddr = _dkim;
        emailAuthImplementationAddr = _emailAuthImplementation;
    }

    // Receive function to allow ETHs
    receive() external payable {}

    /**
     * @notice Called by the bootloader to validate that an account agrees to process the transaction
     * (and potentially pay for it).
     * @dev The developer should strive to preserve as many steps as possible both for valid
     * and invalid transactions as this very method is also used during the gas fee estimation
     * (without some of the necessary data, e.g. signature).
     * @param - bytes32                        - Not used
     * @param suggestedSignedHash bytes32      - The suggested hash of the transaction that is signed by the signer
     * @param transaction Transaction calldata - The transaction itself
     * @return magic bytes4 - The magic value that should be equal to the signature of this function
     * if the user agrees to proceed with the transaction.
     */
    function validateTransaction(
        bytes32,
        bytes32 suggestedSignedHash,
        Transaction calldata transaction
    ) external payable override onlyBootloader returns (bytes4 magic) {
        _incrementNonce(transaction.nonce);

        // The fact there is enough balance for the account
        // should be checked explicitly to prevent user paying for fee for a
        // transaction that wouldn't be included on Ethereum.
        if (transaction.totalRequiredBalance() > address(this).balance) {
            revert Errors.INSUFFICIENT_FUNDS();
        }

        // While the suggested signed hash is usually provided, it is generally
        // not recommended to rely on it to be present, since in the future
        // there may be tx types with no suggested signed hash.
        bytes32 signedHash = suggestedSignedHash == bytes32(0)
            ? transaction.encodeHash()
            : suggestedSignedHash;

        magic = _validateTransaction(signedHash, transaction);
    }

    /**
     * @notice Called by the bootloader to make the account execute the transaction.
     * @dev The transaction is considered successful if this function does not revert
     * @param - bytes32                        - Not used
     * @param - bytes32                        - Not used
     * @param transaction Transaction calldata - The transaction itself
     */
    function executeTransaction(
        bytes32,
        bytes32,
        Transaction calldata transaction
    ) external payable override onlyBootloader {
        _executeTransaction(transaction);
    }

    /**
     * @notice This function allows an EOA to start a transaction for the account.
     * @dev There is no point in providing possible signed hash in the `executeTransactionFromOutside` method,
     * since it typically should not be trusted.
     * @param transaction Transaction calldata - The transaction itself
     */
    function executeTransactionFromOutside(
        Transaction calldata transaction
    ) external payable override {
        // Check if msg.sender is authorized
        if (!_k1IsOwner(msg.sender)) {
            revert Errors.UNAUTHORIZED_OUTSIDE_TRANSACTION();
        }

        // Extract hook data from transaction.signature
        bytes[] memory hookData = SignatureDecoder.decodeSignatureOnlyHookData(
            transaction.signature
        );

        // Get the hash of the transaction
        bytes32 signedHash = transaction.encodeHash();

        // Run the validation hooks
        if (!runValidationHooks(signedHash, transaction, hookData)) {
            revert Errors.VALIDATION_HOOK_FAILED();
        }

        _executeTransaction(transaction);
    }

    /**
     * @notice This function allows the account to pay for its own gas and used when there is no paymaster
     * @param - bytes32                        - not used
     * @param - bytes32                        - not used
     * @param transaction Transaction calldata - Transaction to pay for
     * @dev "This method must send at least `tx.gasprice * tx.gasLimit` ETH to the bootloader address."
     */
    function payForTransaction(
        bytes32,
        bytes32,
        Transaction calldata transaction
    ) external payable override onlyBootloader {
        bool success = transaction.payToTheBootloader();

        if (!success) {
            revert Errors.FEE_PAYMENT_FAILED();
        }

        emit FeePaid();
    }

    /**
     * @notice This function is called by the system if the transaction has a paymaster
        and prepares the interaction with the paymaster
     * @param - bytes32               - not used 
     * @param - bytes32               - not used 
     * @param transaction Transaction - The transaction itself
     */
    function prepareForPaymaster(
        bytes32,
        bytes32,
        Transaction calldata transaction
    ) external payable override onlyBootloader {
        transaction.processPaymasterInput();
    }

    /// @dev type(IClave).interfaceId indicates Clave accounts
    function supportsInterface(
        bytes4 interfaceId
    ) public view override(IERC165, TokenCallbackHandler) returns (bool) {
        return
            interfaceId == type(IClaveAccount).interfaceId || super.supportsInterface(interfaceId);
    }

    function _validateTransaction(
        bytes32 signedHash,
        Transaction calldata transaction
    ) internal returns (bytes4 magicValue) {
        if (transaction.signature.length == 65) {
            // This is a gas estimation
            return bytes4(0);
        }

        // Extract the signature, validator address and hook data from the transaction.signature
        (bytes memory signature, address validator, bytes[] memory hookData) = SignatureDecoder
            .decodeSignature(transaction.signature);

        // Run validation hooks
        bool hookSuccess = runValidationHooks(signedHash, transaction, hookData);

        if (!hookSuccess) {
            return bytes4(0);
        }

        bool valid = _handleValidation(validator, signedHash, signature);

        magicValue = valid ? ACCOUNT_VALIDATION_SUCCESS_MAGIC : bytes4(0);
    }

    function _executeTransaction(
        Transaction calldata transaction
    ) internal runExecutionHooks(transaction) {
        address to = _safeCastToAddress(transaction.to);
        uint128 value = Utils.safeCastToU128(transaction.value);
        bytes calldata data = transaction.data;

        _executeCall(to, value, data, false);
    }

    function _executeCall(
        address to,
        uint128 value,
        bytes calldata data,
        bool allowFailure
    ) internal {
        uint32 gas = Utils.safeCastToU32(gasleft());

        if (to == address(DEPLOYER_SYSTEM_CONTRACT)) {
            // Note, that the deployer contract can only be called
            // with a "systemCall" flag.
            (bool success, bytes memory returnData) = SystemContractsCaller
                .systemCallWithReturndata(gas, to, value, data);
            if (!success && !allowFailure) {
                assembly {
                    let size := mload(returnData)
                    revert(add(returnData, 0x20), size)
                }
            }
        } else if (to == _BATCH_CALLER) {
            bool success = EfficientCall.rawDelegateCall(gas, to, data);
            if (!success && !allowFailure) {
                EfficientCall.propagateRevert();
            }
        } else {
            bool success = EfficientCall.rawCall(gas, to, value, data, false);
            if (!success && !allowFailure) {
                EfficientCall.propagateRevert();
            }
        }
    }

    function _incrementNonce(uint256 nonce) internal {
        SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()),
            address(NONCE_HOLDER_SYSTEM_CONTRACT),
            0,
            abi.encodeCall(INonceHolder.incrementMinNonceIfEquals, (nonce))
        );
    }

    function _safeCastToAddress(uint256 value) internal pure returns (address) {
        if (value > type(uint160).max) revert();
        return address(uint160(value));
    }

    // For EmailAccountRecovery

    enum GuardianStatus {
        NONE,
        REQUESTED,
        ACCEPTED
    }
    uint public constant DEFAULT_TIMELOCK_PERIOD = 3 days;

    bool public isRecovering;
    address public newSignerCandidate;
    mapping(address => GuardianStatus) public guardians;
    uint public timelockPeriod = DEFAULT_TIMELOCK_PERIOD;
    uint public timelock;

    function requestGuardian(address guardian) public {
        require(guardian != address(0), "invalid guardian");
        require(
            guardians[guardian] == GuardianStatus.NONE,
            "guardian status must be NONE"
        );
        guardians[guardian] = GuardianStatus.REQUESTED;
    }

    function acceptGuardian(
        address guardian,
        uint templateIdx,
        bytes[] memory subjectParams,
        bytes32
    ) internal override {
        require(!isRecovering, "recovery in progress");
        require(guardian != address(0), "invalid guardian");
        require(
            guardians[guardian] == GuardianStatus.REQUESTED,
            "guardian status must be REQUESTED"
        );
        require(templateIdx == 0, "invalid template index");
        require(subjectParams.length == 1, "invalid subject params");
        address walletAddrInEmail = abi.decode(subjectParams[0], (address));
        require(
            walletAddrInEmail == address(this),
            "invalid wallet address in email"
        );
        guardians[guardian] = GuardianStatus.ACCEPTED;
    }

    function processRecovery(
        address guardian,
        uint templateIdx,
        bytes[] memory subjectParams,
        bytes32
    ) internal override {
        require(!isRecovering, "recovery in progress");
        require(guardian != address(0), "invalid guardian");
        require(
            guardians[guardian] == GuardianStatus.ACCEPTED,
            "guardian status must be ACCEPTED"
        );
        require(templateIdx == 0, "invalid template index");
        require(subjectParams.length == 2, "invalid subject params");
        address walletAddrInEmail = abi.decode(subjectParams[0], (address));
        address newSignerInEmail = abi.decode(subjectParams[1], (address));
        require(
            walletAddrInEmail == address(this),
            "invalid guardian in email"
        );
        require(newSignerInEmail != address(0), "invalid new signer");
        isRecovering = true;
        newSignerCandidate = newSignerInEmail;
        timelock = block.timestamp + timelockPeriod;
    }

    function completeRecovery() public override {
        require(isRecovering, "recovery not in progress");
        require(timelock <= block.timestamp, "timelock not expired");
        isRecovering = false;
        timelock = 0;
        // _transferOwnership(newSignerCandidate);
        newSignerCandidate = address(0);
    }

    function acceptanceSubjectTemplates()
        public
        pure
        override
        returns (string[][] memory)
    {
        string[][] memory templates = new string[][](1);
        templates[0] = new string[](5);
        templates[0][0] = "Accept";
        templates[0][1] = "guardian";
        templates[0][2] = "request";
        templates[0][3] = "for";
        templates[0][4] = "{ethAddr}";
        return templates;
    }

    function recoverySubjectTemplates()
        public
        pure
        override
        returns (string[][] memory)
    {
        string[][] memory templates = new string[][](1);
        templates[0] = new string[](8);
        templates[0][0] = "Set";
        templates[0][1] = "the";
        templates[0][2] = "new";
        templates[0][3] = "signer";
        templates[0][4] = "of";
        templates[0][5] = "{ethAddr}";
        templates[0][6] = "to";
        templates[0][7] = "{ethAddr}";
        return templates;
    }

}
