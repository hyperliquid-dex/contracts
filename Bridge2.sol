// SPDX-License-Identifier: UNLICENSED

/*
    This bridge contract runs on Arbitrum, operating alongside the Hyperliquid L1.
    The only asset for now is USDC, though the logic extends to any other ERC20 token on Arbitrum.
    The L1 runs tendermint consensus, with validator set updates happening at the end of each epoch.
    Epoch duration TBD, but likely somewhere between 1 day and 1 week.
    "Bridge2" is to distinguish from the legacy Bridge contract.

    Validators:
      Each validator has a hot (in memory) and cold wallet.
      Automated withdrawals and validator set updates are approved by 2/3 of the validator power,
      signed by hot wallets.
      For additional security, withdrawals and validator set updates are pending for a dispute period.
      During this period, any locker may lock the bridge (preventing further withdrawals or updates).
      To unlock the bridge, a quorum of cold wallet signatures is required.

    Validator set updates:
      The active validators sign a hash of the new validator set and powers on the L1.
      This contract checks those signatures, and updates the hash of the active validator set.
      The active validators' L1 stake is still locked for at least one more epoch (unbonding period),
      and the new validators will slash the old ones' stake if they do not properly generate the validator set update signatures.
      The validator set change is pending for a period of time for the lockers to dispute the change.

    Withdrawals:
      The validators sign withdrawals on the L1, which the user sends to this contract in requestWithdrawal()
      This contract checks the signatures, and then creates a pending withdrawal which can be disputed for a period of time.
      After the dispute period has elapsed (measured in both time and blocks), a second transaction can be sent to finalize the withdrawal and release the USDC.

    Deposits:
      The validators on the L1 listen for and sign DepositEvent events emitted by this contract,
      crediting the L1 with the equivalent USDC. No additional work needs to be done on this contract.

    Signatures:
      For withdrawals and validator set updates, the signatures are sent to the bridge contract
      in the same order as the active validator set, i.e. signing validators should be a subsequence
      of active validators.

    Lockers:
      These addresses are approved by the validators to lock the contract if submitted signatures do not match
      the locker's view of the L1. Once locked, only a quorum of cold wallet validator signatures can unlock the bridge.
      This dispute period is used for both withdrawals and validator set updates.
      L1 operation will automatically register all validator hot addresses as lockers.
      Adding a locker requires hot wallet quorum, and removing requires cold wallet quorum.

    Finalizers:
      These addresses are approved by the validators to finalize withdrawals and validator set updates.
      While not strictly necessary due to the locking mechanism, this adds an additional layer of security without sacrificing functionality.
      Even if locking transactions are censored (which should be economically infeasible), this still requires attackers to control a finalizer private key.
      L1 operation will eventually register all validator hot addresses as finalizers,
      though there may be an intermediate phase where finalizers are a subset of trusted validators.
      Adding a finalizer requires hot wallet quorum, and removing requires cold wallet quorum.

    Unlocking:
      When the bridge is unlocked, a new validator set is atomically set and finalized.
      This is safe because the unlocking message is signed by a quorum of validator cold wallets.

    The L1 will ensure the following, though neither is required by the smart contract:
      1. The order of active validators are ordered in decreasing order of power.
      2. The validators are unique.

    On epoch changes, the L1 will ensure that new signatures are generated for unclaimed withdrawals
    for any validators that have changed.

    This bridge contract assumes there will be 20-30 validators on the L1, so signature sets fit in a single tx.
*/

pragma solidity ^0.8.9;

import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./Signature.sol";

struct ValidatorSet {
  uint64 epoch;
  address[] validators;
  uint64[] powers;
}

struct ValidatorSetUpdateRequest {
  uint64 epoch;
  address[] hotAddresses;
  address[] coldAddresses;
  uint64[] powers;
}

struct PendingValidatorSetUpdate {
  uint64 epoch;
  uint64 totalValidatorPower;
  uint64 updateTime;
  uint64 updateBlockNumber;
  uint64 nValidators;
  bytes32 hotValidatorSetHash;
  bytes32 coldValidatorSetHash;
}

struct DepositEvent {
  address user;
  uint64 usdc;
}

struct Withdrawal {
  address user;
  uint64 usdc;
  uint64 nonce;
  uint64 requestedTime;
  uint64 requestedBlockNumber;
  bytes32 message;
}

struct RequestedWithdrawalEvent {
  address user;
  uint64 usdc;
  uint64 nonce;
  bytes32 message;
  uint64 requestedTime;
}

struct FinalizedWithdrawalEvent {
  address user;
  uint64 usdc;
  uint64 nonce;
  bytes32 message;
}

struct RequestedValidatorSetUpdateEvent {
  uint64 epoch;
  bytes32 hotValidatorSetHash;
  bytes32 coldValidatorSetHash;
  uint64 updateTime;
}

struct FinalizedValidatorSetUpdateEvent {
  uint64 epoch;
  bytes32 hotValidatorSetHash;
  bytes32 coldValidatorSetHash;
}

contract Bridge2 is Pausable, ReentrancyGuard {
  using SafeERC20 for ERC20;
  ERC20 usdcToken;

  bytes32 public hotValidatorSetHash;
  bytes32 public coldValidatorSetHash;
  PendingValidatorSetUpdate public pendingValidatorSetUpdate;

  mapping(bytes32 => bool) usedMessages;
  mapping(address => bool) lockers;
  mapping(address => bool) finalizers;
  uint64 public epoch;
  uint64 public totalValidatorPower;
  uint64 public disputePeriodSeconds;
  // Need higher resolution than seconds for Arbitrum.
  uint64 public blockDurationMillis;

  // Expose this for convenience because we only store the hash.
  uint64 public nValidators;

  mapping(bytes32 => Withdrawal) requestedWithdrawals;
  mapping(bytes32 => bool) finalizedWithdrawals;
  mapping(bytes32 => bool) withdrawalsInvalidated;

  bytes32 immutable domainSeparator;

  // These events wrap structs because of a quirk of rust client code which parses them.
  event Deposit(DepositEvent e);
  event RequestedWithdrawal(RequestedWithdrawalEvent e);
  event FinalizedWithdrawal(FinalizedWithdrawalEvent e);
  event RequestedValidatorSetUpdate(RequestedValidatorSetUpdateEvent e);
  event FinalizedValidatorSetUpdate(FinalizedValidatorSetUpdateEvent e);
  event ModifiedLocker(address indexed locker, bool isLocker);
  event ModifiedFinalizer(address indexed finalizer, bool isFinalizer);
  event ChangedDisputePeriodSeconds(uint64 newDisputePeriodSeconds);
  event ChangedBlockDurationMillis(uint64 newBlockDurationMillis);
  event InvalidatedWithdrawals(bytes32[] withdrawalsInvalidated);

  // We could have the deployer initialize separately so that all function args in this file can be calldata.
  // However, calldata does not seem cheaper than memory on Arbitrum, so not a big deal for now.
  constructor(
    address[] memory hotAddresses,
    address[] memory coldAddresses,
    uint64[] memory powers,
    address usdcAddress,
    uint64 _disputePeriodSeconds,
    uint64 _blockDurationMillis
  ) {
    domainSeparator = makeDomainSeparator();
    totalValidatorPower = checkNewValidatorPowers(powers);

    require(
      hotAddresses.length == coldAddresses.length,
      "Hot and cold validator sets length mismatch"
    );
    nValidators = uint64(hotAddresses.length);

    ValidatorSet memory hotValidatorSet;
    hotValidatorSet = ValidatorSet({ epoch: 0, validators: hotAddresses, powers: powers });
    bytes32 newHotValidatorSetHash = makeValidatorSetHash(hotValidatorSet);
    hotValidatorSetHash = newHotValidatorSetHash;

    ValidatorSet memory coldValidatorSet;
    coldValidatorSet = ValidatorSet({ epoch: 0, validators: coldAddresses, powers: powers });
    bytes32 newColdValidatorSetHash = makeValidatorSetHash(coldValidatorSet);
    coldValidatorSetHash = newColdValidatorSetHash;

    usdcToken = ERC20(usdcAddress);
    disputePeriodSeconds = _disputePeriodSeconds;
    blockDurationMillis = _blockDurationMillis;
    addLockersAndFinalizers(hotAddresses);

    emit RequestedValidatorSetUpdate(
      RequestedValidatorSetUpdateEvent({
        epoch: 0,
        hotValidatorSetHash: hotValidatorSetHash,
        coldValidatorSetHash: coldValidatorSetHash,
        updateTime: uint64(block.timestamp)
      })
    );

    pendingValidatorSetUpdate = PendingValidatorSetUpdate({
      epoch: 0,
      totalValidatorPower: totalValidatorPower,
      updateTime: 0,
      updateBlockNumber: uint64(block.number),
      hotValidatorSetHash: hotValidatorSetHash,
      coldValidatorSetHash: coldValidatorSetHash,
      nValidators: nValidators
    });

    emit FinalizedValidatorSetUpdate(
      FinalizedValidatorSetUpdateEvent({
        epoch: 0,
        hotValidatorSetHash: hotValidatorSetHash,
        coldValidatorSetHash: coldValidatorSetHash
      })
    );
  }

  function addLockersAndFinalizers(address[] memory addresses) private {
    uint64 end = uint64(addresses.length);
    for (uint64 idx; idx < end; idx++) {
      address _address = addresses[idx];
      lockers[_address] = true;
      finalizers[_address] = true;
    }
  }

  // A utility function to make a checkpoint of the validator set supplied.
  // The checkpoint is the hash of all the validators, the powers and the epoch.
  function makeValidatorSetHash(ValidatorSet memory validatorSet) private pure returns (bytes32) {
    require(
      validatorSet.validators.length == validatorSet.powers.length,
      "Malformed validator set"
    );

    bytes32 checkpoint = keccak256(
      abi.encode(validatorSet.validators, validatorSet.powers, validatorSet.epoch)
    );
    return checkpoint;
  }

  // An external function anyone can call to deposit usdc into the brigde.
  // A deposit event will be emitted crediting the L1 with the usdc.
  function deposit(uint64 usdc) external whenNotPaused nonReentrant {
    address user = msg.sender;
    usdcToken.safeTransferFrom(user, address(this), usdc);
    emit Deposit(DepositEvent({ user: user, usdc: usdc }));
  }

  // An external function anyone can call to withdraw usdc from the bridge by providing valid signatures
  // from the active L1 validators.
  function requestWithdrawal(
    uint64 usdc,
    uint64 nonce,
    ValidatorSet calldata hotValidatorSet,
    address[] calldata signers,
    Signature[] calldata signatures
  ) external nonReentrant whenNotPaused {
    // NOTE: this is a temporary workaround because EIP-191 signatures do not match between rust client and solidity.
    // For now we do not care about the overhead with EIP-712 because Arbitrum gas is cheap.
    Agent memory agent = Agent(
      "a",
      keccak256(abi.encode("requestWithdrawal", msg.sender, usdc, nonce))
    );
    bytes32 message = hash(agent);
    checkValidWithdrawal(message);

    Withdrawal memory withdrawal = Withdrawal({
      user: msg.sender,
      usdc: usdc,
      nonce: nonce,
      requestedTime: uint64(block.timestamp),
      requestedBlockNumber: uint64(block.number),
      message: message
    });

    require(requestedWithdrawals[message].requestedTime == 0, "Withdrawal already requested");
    checkValidatorSignatures(message, hotValidatorSet, signers, signatures, hotValidatorSetHash);

    requestedWithdrawals[message] = withdrawal;
    emit RequestedWithdrawal(
      RequestedWithdrawalEvent({
        user: withdrawal.user,
        usdc: withdrawal.usdc,
        nonce: withdrawal.nonce,
        requestedTime: withdrawal.requestedTime,
        message: withdrawal.message
      })
    );
  }

  function finalizeWithdrawal(bytes32 message) private whenNotPaused {
    checkValidWithdrawal(message);

    require(!finalizedWithdrawals[message], "Withdrawal already finalized");

    Withdrawal memory withdrawal = requestedWithdrawals[message];
    require(
      withdrawal.user != address(0),
      "Withdrawal message does not correspond to an existing withdrawal request"
    );

    checkDisputePeriod(withdrawal.requestedTime, withdrawal.requestedBlockNumber);

    finalizedWithdrawals[message] = true;
    usdcToken.safeTransfer(withdrawal.user, withdrawal.usdc);
    emit FinalizedWithdrawal(
      FinalizedWithdrawalEvent({
        user: withdrawal.user,
        usdc: withdrawal.usdc,
        nonce: withdrawal.nonce,
        message: withdrawal.message
      })
    );
  }

  function batchedFinalizeWithdrawals(
    bytes32[] calldata messages
  ) external nonReentrant whenNotPaused {
    checkFinalizer(msg.sender);

    uint64 end = uint64(messages.length);
    for (uint64 idx; idx < end; idx++) {
      finalizeWithdrawal(messages[idx]);
    }
  }

  function checkValidWithdrawal(bytes32 message) private view {
    require(!withdrawalsInvalidated[message], "Withdrawal has been invalidated.");
  }

  function checkDisputePeriod(uint64 time, uint64 blockNumber) private view {
    require(
      block.timestamp > time + disputePeriodSeconds &&
        (uint64(block.number) - blockNumber) * blockDurationMillis > 1000 * disputePeriodSeconds,
      "Still in dispute period"
    );
  }

  // Utility function that verifies the signatures supplied and checks that the validators have reached quorum.
  function checkValidatorSignatures(
    bytes32 message,
    ValidatorSet memory activeValidatorSet, // Active set of all L1 validators
    address[] memory signers, // Subsequence of the active L1 validators that signed the message
    Signature[] memory signatures,
    bytes32 validatorSetHash
  ) private view {
    require(
      makeValidatorSetHash(activeValidatorSet) == validatorSetHash,
      "Supplied active validators and powers do not match the active checkpoint"
    );

    uint64 nSigners = uint64(signers.length);
    require(nSigners > 0, "Signers empty");
    require(nSigners == signatures.length, "Signatures and signers have different lengths");

    uint64 cumulativePower;
    uint64 signerIdx;
    uint64 end = uint64(activeValidatorSet.validators.length);

    for (uint64 activeValidatorSetIdx; activeValidatorSetIdx < end; activeValidatorSetIdx++) {
      address signer = signers[signerIdx];
      if (signer == activeValidatorSet.validators[activeValidatorSetIdx]) {
        uint64 power = activeValidatorSet.powers[activeValidatorSetIdx];
        require(
          recoverSigner(message, signatures[signerIdx], domainSeparator) == signer,
          "Validator signature does not match"
        );
        cumulativePower += power;

        if (3 * cumulativePower >= 2 * totalValidatorPower) {
          break;
        }

        signerIdx += 1;
        if (signerIdx >= nSigners) {
          break;
        }
      }
    }

    require(
      3 * cumulativePower >= 2 * totalValidatorPower,
      "Submitted validator set signatures do not have enough power"
    );
  }

  function checkMessageNotUsed(bytes32 message) private {
    require(!usedMessages[message], "message already used");
    usedMessages[message] = true;
  }

  // This function updates the validator set by checking that the active validators have signed
  // off on the new validator set
  function updateValidatorSet(
    ValidatorSetUpdateRequest memory newValidatorSet,
    ValidatorSet memory activeHotValidatorSet,
    address[] memory signers,
    Signature[] memory signatures
  ) external whenNotPaused {
    require(
      makeValidatorSetHash(activeHotValidatorSet) == hotValidatorSetHash,
      "Supplied active validators and powers do not match checkpoint"
    );

    Agent memory agent = Agent(
      "a",
      keccak256(
        abi.encode(
          "updateValidatorSet",
          newValidatorSet.epoch,
          newValidatorSet.hotAddresses,
          newValidatorSet.coldAddresses,
          newValidatorSet.powers
        )
      )
    );
    bytes32 message = hash(agent);
    updateValidatorSetInner(
      newValidatorSet,
      activeHotValidatorSet,
      signers,
      signatures,
      message,
      false
    );
  }

  function updateValidatorSetInner(
    ValidatorSetUpdateRequest memory newValidatorSet,
    ValidatorSet memory activeValidatorSet,
    address[] memory signers,
    Signature[] memory signatures,
    bytes32 message,
    bool useColdValidatorSet
  ) private {
    require(
      newValidatorSet.hotAddresses.length == newValidatorSet.coldAddresses.length,
      "New hot and cold validator sets length mismatch"
    );

    require(
      newValidatorSet.hotAddresses.length == newValidatorSet.powers.length,
      "New validator set and powers length mismatch"
    );

    require(
      newValidatorSet.epoch > activeValidatorSet.epoch,
      "New validator set epoch must be greater than the active epoch"
    );

    uint64 newTotalValidatorPower = checkNewValidatorPowers(newValidatorSet.powers);

    bytes32 validatorSetHash;
    if (useColdValidatorSet) {
      validatorSetHash = coldValidatorSetHash;
    } else {
      validatorSetHash = hotValidatorSetHash;
    }

    checkValidatorSignatures(message, activeValidatorSet, signers, signatures, validatorSetHash);

    ValidatorSet memory newHotValidatorSet;
    newHotValidatorSet = ValidatorSet({
      epoch: newValidatorSet.epoch,
      validators: newValidatorSet.hotAddresses,
      powers: newValidatorSet.powers
    });
    bytes32 newHotValidatorSetHash = makeValidatorSetHash(newHotValidatorSet);

    ValidatorSet memory newColdValidatorSet;
    newColdValidatorSet = ValidatorSet({
      epoch: newValidatorSet.epoch,
      validators: newValidatorSet.coldAddresses,
      powers: newValidatorSet.powers
    });
    bytes32 newColdValidatorSetHash = makeValidatorSetHash(newColdValidatorSet);

    uint64 updateTime = uint64(block.timestamp);
    pendingValidatorSetUpdate = PendingValidatorSetUpdate({
      epoch: newValidatorSet.epoch,
      totalValidatorPower: newTotalValidatorPower,
      updateTime: updateTime,
      updateBlockNumber: uint64(block.number),
      hotValidatorSetHash: newHotValidatorSetHash,
      coldValidatorSetHash: newColdValidatorSetHash,
      nValidators: uint64(newHotValidatorSet.validators.length)
    });

    emit RequestedValidatorSetUpdate(
      RequestedValidatorSetUpdateEvent({
        epoch: newValidatorSet.epoch,
        hotValidatorSetHash: newHotValidatorSetHash,
        coldValidatorSetHash: newColdValidatorSetHash,
        updateTime: updateTime
      })
    );
  }

  function finalizeValidatorSetUpdate() external nonReentrant whenNotPaused {
    checkFinalizer(msg.sender);

    require(
      pendingValidatorSetUpdate.updateTime != 0,
      "Pending validator set update already finalized"
    );

    checkDisputePeriod(
      pendingValidatorSetUpdate.updateTime,
      pendingValidatorSetUpdate.updateBlockNumber
    );

    finalizeValidatorSetUpdateInner();
  }

  function finalizeValidatorSetUpdateInner() private {
    hotValidatorSetHash = pendingValidatorSetUpdate.hotValidatorSetHash;
    coldValidatorSetHash = pendingValidatorSetUpdate.coldValidatorSetHash;
    epoch = pendingValidatorSetUpdate.epoch;
    totalValidatorPower = pendingValidatorSetUpdate.totalValidatorPower;
    nValidators = pendingValidatorSetUpdate.nValidators;
    pendingValidatorSetUpdate.updateTime = 0;

    emit FinalizedValidatorSetUpdate(
      FinalizedValidatorSetUpdateEvent({
        epoch: epoch,
        hotValidatorSetHash: pendingValidatorSetUpdate.hotValidatorSetHash,
        coldValidatorSetHash: pendingValidatorSetUpdate.coldValidatorSetHash
      })
    );
  }

  function modifyLocker(
    address locker,
    bool _isLocker,
    uint64 nonce,
    ValidatorSet calldata activeValidatorSet,
    address[] calldata signers,
    Signature[] memory signatures
  ) external {
    Agent memory agent = Agent(
      "a",
      keccak256(abi.encode("modifyLocker", locker, _isLocker, nonce))
    );
    bytes32 message = hash(agent);

    bytes32 validatorSetHash;
    if (_isLocker) {
      validatorSetHash = hotValidatorSetHash;
    } else {
      validatorSetHash = coldValidatorSetHash;
    }

    checkMessageNotUsed(message);
    checkValidatorSignatures(message, activeValidatorSet, signers, signatures, validatorSetHash);
    lockers[locker] = _isLocker;
    emit ModifiedLocker(locker, _isLocker);
  }

  function isLocker(address locker) external view returns (bool) {
    return lockers[locker];
  }

  function modifyFinalizer(
    address finalizer,
    bool _isFinalizer,
    uint64 nonce,
    ValidatorSet calldata activeValidatorSet,
    address[] calldata signers,
    Signature[] memory signatures
  ) external {
    Agent memory agent = Agent(
      "a",
      keccak256(abi.encode("modifyFinalizer", finalizer, _isFinalizer, nonce))
    );
    bytes32 message = hash(agent);

    bytes32 validatorSetHash;
    if (_isFinalizer) {
      validatorSetHash = hotValidatorSetHash;
    } else {
      validatorSetHash = coldValidatorSetHash;
    }

    checkMessageNotUsed(message);
    checkValidatorSignatures(message, activeValidatorSet, signers, signatures, validatorSetHash);
    finalizers[finalizer] = _isFinalizer;
    emit ModifiedFinalizer(finalizer, _isFinalizer);
  }

  function isFinalizer(address finalizer) external view returns (bool) {
    return finalizers[finalizer];
  }

  function checkFinalizer(address finalizer) private view {
    require(finalizers[finalizer], "Sender is not a finalizer");
  }

  // This function checks that the total power of the new validator set is greater than zero.
  function checkNewValidatorPowers(uint64[] memory powers) private pure returns (uint64) {
    uint64 cumulativePower;
    for (uint64 i; i < powers.length; i++) {
      cumulativePower += powers[i];
    }

    require(cumulativePower > 0, "Submitted validator powers must be greater than zero");
    return cumulativePower;
  }

  function changeDisputePeriodSeconds(
    uint64 newDisputePeriodSeconds,
    uint64 nonce,
    ValidatorSet memory activeColdValidatorSet,
    address[] memory signers,
    Signature[] memory signatures
  ) external whenPaused {
    Agent memory agent = Agent(
      "a",
      keccak256(abi.encode("changeDisputePeriodSeconds", newDisputePeriodSeconds, nonce))
    );
    bytes32 message = hash(agent);
    checkMessageNotUsed(message);
    checkValidatorSignatures(
      message,
      activeColdValidatorSet,
      signers,
      signatures,
      coldValidatorSetHash
    );

    disputePeriodSeconds = newDisputePeriodSeconds;
    emit ChangedDisputePeriodSeconds(newDisputePeriodSeconds);
  }

  function invalidateWithdrawals(
    bytes32[] memory messages,
    uint64 nonce,
    ValidatorSet memory activeColdValidatorSet,
    address[] memory signers,
    Signature[] memory signatures
  ) external whenPaused {
    Agent memory agent = Agent(
      "a",
      keccak256(abi.encode("invalidateWithdrawals", messages, nonce))
    );
    bytes32 message = hash(agent);
    checkMessageNotUsed(message);
    checkValidatorSignatures(
      message,
      activeColdValidatorSet,
      signers,
      signatures,
      coldValidatorSetHash
    );

    uint64 end = uint64(messages.length);
    for (uint64 idx; idx < end; idx++) {
      withdrawalsInvalidated[messages[idx]] = true;
    }

    emit InvalidatedWithdrawals(messages);
  }

  function changeBlockDurationMillis(
    uint64 newBlockDurationMillis,
    uint64 nonce,
    ValidatorSet memory activeColdValidatorSet,
    address[] memory signers,
    Signature[] memory signatures
  ) external whenPaused {
    Agent memory agent = Agent(
      "a",
      keccak256(abi.encode("changeBlockDurationMillis", newBlockDurationMillis, nonce))
    );
    bytes32 message = hash(agent);
    checkMessageNotUsed(message);
    checkValidatorSignatures(
      message,
      activeColdValidatorSet,
      signers,
      signatures,
      coldValidatorSetHash
    );

    blockDurationMillis = newBlockDurationMillis;
    emit ChangedBlockDurationMillis(newBlockDurationMillis);
  }

  function emergencyLock() external {
    require(lockers[msg.sender], "Sender is not authorized to lock smart contract");
    _pause();
  }

  function emergencyUnlock(
    ValidatorSetUpdateRequest memory newValidatorSet,
    ValidatorSet calldata activeColdValidatorSet,
    address[] calldata signers,
    Signature[] calldata signatures,
    uint64 nonce
  ) external {
    Agent memory agent = Agent(
      "a",
      keccak256(
        abi.encode(
          "unlock",
          newValidatorSet.epoch,
          newValidatorSet.hotAddresses,
          newValidatorSet.coldAddresses,
          newValidatorSet.powers,
          nonce
        )
      )
    );
    bytes32 message = hash(agent);
    checkMessageNotUsed(message);
    updateValidatorSetInner(
      newValidatorSet,
      activeColdValidatorSet,
      signers,
      signatures,
      message,
      true
    );
    finalizeValidatorSetUpdateInner();
    _unpause();
  }
}
