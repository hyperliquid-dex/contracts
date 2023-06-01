// SPDX-License-Identifier: UNLICENSED
// NOSHIP update docs here

/*
    This bridge contract runs on Arbitrum, operating alongside the Hyperliquid L1.
    The only asset for now is USDC, though the logic extends to any other ERC20 token on Arbitrum.
    The L1 runs tendermint consensus, with validator set updates happening at the end of each epoch.
    Epoch duration TBD, but likely somewhere between 1 day and 1 week

    Lockers:
      These addresses are approved by the validators to lock the contract if submitted signatures do not match
      the locker's view of the L1. Once locked, only a quorum of cold wallet validator signatures can unlock the bridge.
      This dispute period is used for both withdrawals and validator set updates.

    Validator set updates:
      The current validators sign a hash of the new validator set and powers on the L1.
      This contract checks those signatures, and updates the hash of the current validator set.
      The current validators' L1 stake is still locked for at least one more epoch (unbonding period),
      and the new validators will slash the old ones' stake if they do not properly generate the
      validator set update signatures.
      The validator set change is pending for a period of time for the lockers to dispute the change.

    Withdrawals:
      The validators sign withdrawals on the L1, which the user sends to this contract in claimWithdrawal().
      This contract checks the signatures, and then creates a pending withdrawal which can be disputed for a period of time.
      After the dispute period has elapsed, a second transaction can be sent to finalize the withdrawal and release the USDC.

    Deposits:
      The validators on the L1 listen for and sign DepositEvent events emitted by this contract,
      crediting the L1 with the equivalent USDC. No additional work needs to be done on this contract.

    Signatures:
      For withdrawals and validator set updates, the signatures are sent to the bridge contract
      in the same order as the current validator set, i.e. signing validators should be a subsequence
      of current validators.

    The L1 will ensure the following, though neither is required by the smart contract:
      1. The order of current validators are ordered in decreasing order of power.
      2. The validators are unique.

    On epoch changes, the L1 will ensure that new signatures are generated for unclaimed withdrawals
    for any validators that have changed.

    This bridge contract assumes there will be 20-30 validators,
    so passing the full set of validators as calldata is reasonable on Arbitrum.
*/

pragma solidity ^0.8.9;

import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
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
  uint64 powerThreshold;
  uint256 updateTime;
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
  uint64 claimedTime;
  bytes32 message;
}

struct ClaimedWithdrawalEvent {
  address user;
  uint64 usdc;
  uint64 nonce;
  bytes32 message;
  uint64 claimedTime;
}

struct FinalizedWithdrawalEvent {
  address user;
  uint64 usdc;
  uint64 nonce;
  bytes32 message;
}

// NOSHIP remove ownable and replace with checking validator signatures and time
contract Bridge2 is Ownable, Pausable, ReentrancyGuard {
  ERC20 usdcToken;

  bytes32 public hotValidatorSetHash;
  bytes32 public coldValidatorSetHash;
  PendingValidatorSetUpdate public pendingValidatorSetUpdate;
  mapping(bytes32 => bool) usedLockerUpdateMessages;
  mapping(address => bool) lockers;

  mapping(bytes32 => bool) usedUnlockMessages;

  uint64 public epoch;
  uint64 public powerThreshold;
  uint64 public disputePeriodSeconds;
  uint64 public immutable minTotalValidatorPower;
  // Expose this for convenience because we only store the hash.
  uint64 public nValidators;

  mapping(bytes32 => Withdrawal) claimedWithdrawals;
  mapping(bytes32 => bool) finalizedWithdrawals;

  bytes32 immutable domainSeparator;

  // These events wrap structs because of a quirk of rust client code which parses them.
  event Deposit(DepositEvent e);
  event ClaimedWithdrawal(ClaimedWithdrawalEvent e);
  event FinalizedWithdrawal(FinalizedWithdrawalEvent e);

  event ValidatorSetUpdateRequested(
    uint64 indexed epoch,
    address[] hotValidatorAddresses,
    address[] coldValidatorAddresses,
    uint64[] powers
  );

  event ValidatorSetUpdateFinalized(
    uint64 indexed epoch,
    bytes32 hotValidatorSetHash,
    bytes32 coldValidatorSetHash
  );

  event ModifiedLocker(address indexed locker, bool isLocker);

  // TODO if it saves gas, have the deployer initialize separately so that all function args can be calldata.
  // However, calldata does not seem to save gas on Arbitrum, so not a big deal for now.
  constructor(
    uint64 _minTotalValidatorPower,
    address[] memory hotValidatorAddresses,
    address[] memory coldValidatorAddresses,
    uint64[] memory powers,
    address usdcAddress,
    uint64 _disputePeriodSeconds
  ) {
    domainSeparator = makeDomainSeparator();
    minTotalValidatorPower = _minTotalValidatorPower;
    uint64 cumulativePower = checkNewValidatorPowers(powers);
    powerThreshold = (2 * cumulativePower) / 3;

    require(
      hotValidatorAddresses.length == coldValidatorAddresses.length,
      "Hot and cold validator sets length mismatch"
    );
    nValidators = uint64(hotValidatorAddresses.length);

    ValidatorSet memory hotValidatorSet;
    hotValidatorSet = ValidatorSet({ epoch: 0, validators: hotValidatorAddresses, powers: powers });
    bytes32 newHotValidatorSetHash = makeValidatorSetHash(hotValidatorSet);
    hotValidatorSetHash = newHotValidatorSetHash;

    ValidatorSet memory coldValidatorSet;
    coldValidatorSet = ValidatorSet({
      epoch: 0,
      validators: coldValidatorAddresses,
      powers: powers
    });
    bytes32 newColdValidatorSetHash = makeValidatorSetHash(coldValidatorSet);
    coldValidatorSetHash = newColdValidatorSetHash;

    usdcToken = ERC20(usdcAddress);
    // NOSHIP what should this be?
    // Also let validators set this
    disputePeriodSeconds = _disputePeriodSeconds;

    emit ValidatorSetUpdateRequested(0, hotValidatorAddresses, coldValidatorAddresses, powers);

    emit ValidatorSetUpdateFinalized(0, newHotValidatorSetHash, newColdValidatorSetHash);
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
    emit Deposit(DepositEvent({ user: user, usdc: usdc }));
    usdcToken.transferFrom(user, address(this), usdc);
  }

  // An external function anyone can call to withdraw usdc from the bridge by providing valid signatures
  // from the current L1 validators.
  function claimWithdrawal(
    uint64 usdc,
    uint64 nonce,
    ValidatorSet calldata hotValidatorSet,
    address[] calldata signers,
    Signature[] calldata signatures
  ) external nonReentrant whenNotPaused {
    // NOTE: this is a temporary workaround because EIP-191 signatures do not match between rust client and solidity.
    // For now we do not care about the overhead with EIP-712 because Arbitrum gas is basically free.
    Agent memory agent = Agent("a", keccak256(abi.encode(msg.sender, usdc, nonce)));
    bytes32 message = hash(agent);
    Withdrawal memory withdrawal = Withdrawal({
      user: msg.sender,
      usdc: usdc,
      nonce: nonce,
      claimedTime: uint64(block.timestamp),
      message: message
    });

    require(claimedWithdrawals[message].claimedTime == 0, "Withdrawal already claimed");
    checkValidatorSignatures(message, hotValidatorSet, signers, signatures, hotValidatorSetHash);

    claimedWithdrawals[message] = withdrawal;
    emit ClaimedWithdrawal(
      ClaimedWithdrawalEvent({
        user: withdrawal.user,
        usdc: withdrawal.usdc,
        nonce: withdrawal.nonce,
        claimedTime: withdrawal.claimedTime,
        message: withdrawal.message
      })
    );
  }

  function finalizeWithdrawal(bytes32 message) external nonReentrant whenNotPaused {
    require(!finalizedWithdrawals[message], "Withdrawal already finalized");
    Withdrawal memory withdrawal = claimedWithdrawals[message];

    require(
      block.timestamp > withdrawal.claimedTime + disputePeriodSeconds,
      "Withdrawal still in dispute period"
    );
    finalizedWithdrawals[message] = true;
    usdcToken.transfer(withdrawal.user, withdrawal.usdc);
    emit FinalizedWithdrawal(
      FinalizedWithdrawalEvent({
        user: withdrawal.user,
        usdc: withdrawal.usdc,
        nonce: withdrawal.nonce,
        message: withdrawal.message
      })
    );
  }

  // Utility function that verifies the signatures supplied and checks that the validators have reached quorum.
  function checkValidatorSignatures(
    bytes32 message,
    ValidatorSet memory curValidatorSet, // Current set of all L1 validators
    address[] memory signers, // Subsequence of the current L1 validators that signed the message
    Signature[] memory signatures,
    bytes32 validatorSetHash
  ) private view {
    require(
      makeValidatorSetHash(curValidatorSet) == validatorSetHash,
      "Supplied current validators and powers do not match the current checkpoint"
    );

    uint64 nSigners = uint64(signers.length);
    require(nSigners > 0, "Signers empty");
    require(nSigners == signatures.length, "Signatures and signers have different lengths");

    uint64 cumulativePower;
    uint64 signerIdx;
    uint64 end = uint64(curValidatorSet.validators.length);

    for (uint64 curValidatorSetIdx; curValidatorSetIdx < end; curValidatorSetIdx++) {
      address signer = signers[signerIdx];
      if (signer == curValidatorSet.validators[curValidatorSetIdx]) {
        uint64 power = curValidatorSet.powers[curValidatorSetIdx];
        require(
          recoverSigner(message, signatures[signerIdx], domainSeparator) == signer,
          "Validator signature does not match"
        );
        cumulativePower += power;

        if (cumulativePower >= powerThreshold) {
          break;
        }

        signerIdx += 1;
        if (signerIdx >= nSigners) {
          break;
        }
      }
    }

    require(
      cumulativePower >= powerThreshold,
      "Submitted validator set signatures do not have enough power"
    );
  }

  // This function updates the validator set by checking that the current validators have signed
  // off on the new validator set
  function updateValidatorSet(
    ValidatorSetUpdateRequest memory newValidatorSet,
    ValidatorSet memory curHotValidatorSet,
    address[] memory signers,
    Signature[] memory signatures
  ) external whenNotPaused {
    require(
      makeValidatorSetHash(curHotValidatorSet) == hotValidatorSetHash,
      "Supplied current validators and powers do not match checkpoint"
    );

    require(
      newValidatorSet.hotAddresses.length == newValidatorSet.coldAddresses.length,
      "New hot and cold validator sets length mismatch"
    );

    require(
      newValidatorSet.hotAddresses.length == newValidatorSet.powers.length,
      "New validator set and powers length mismatch"
    );

    require(
      newValidatorSet.epoch > curHotValidatorSet.epoch,
      "New validator set epoch must be greater than the current epoch"
    );

    uint64 cumulativePower = checkNewValidatorPowers(newValidatorSet.powers);

    Agent memory agent = Agent(
      "a",
      keccak256(
        abi.encode(
          newValidatorSet.epoch,
          newValidatorSet.hotAddresses,
          newValidatorSet.coldAddresses,
          newValidatorSet.powers
        )
      )
    );
    bytes32 message = hash(agent);
    checkValidatorSignatures(message, curHotValidatorSet, signers, signatures, hotValidatorSetHash);

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
    uint64 newPowerThreshold = (2 * cumulativePower) / 3;

    pendingValidatorSetUpdate = PendingValidatorSetUpdate({
      epoch: newValidatorSet.epoch,
      powerThreshold: newPowerThreshold,
      updateTime: block.timestamp,
      hotValidatorSetHash: newHotValidatorSetHash,
      coldValidatorSetHash: newColdValidatorSetHash
    });

    emit ValidatorSetUpdateRequested(
      newValidatorSet.epoch,
      newValidatorSet.hotAddresses,
      newValidatorSet.coldAddresses,
      newValidatorSet.powers
    );
  }

  function finalizeValidatorSetUpdate() external nonReentrant whenNotPaused {
    require(
      pendingValidatorSetUpdate.updateTime != 0,
      "Pending validator set update already finalized"
    );

    require(
      block.timestamp > pendingValidatorSetUpdate.updateTime + disputePeriodSeconds,
      "Validator set update still in dispute period"
    );

    hotValidatorSetHash = pendingValidatorSetUpdate.hotValidatorSetHash;
    coldValidatorSetHash = pendingValidatorSetUpdate.coldValidatorSetHash;
    epoch = pendingValidatorSetUpdate.epoch;
    powerThreshold = pendingValidatorSetUpdate.powerThreshold;
    nValidators = uint64(pendingValidatorSetUpdate.hotValidatorSetHash.length);
    pendingValidatorSetUpdate.updateTime = 0;

    emit ValidatorSetUpdateFinalized(epoch, hotValidatorSetHash, coldValidatorSetHash);
  }

  function modifyLocker(
    address locker,
    bool isLocker,
    uint64 nonce,
    ValidatorSet calldata curColdValidatorSet,
    address[] calldata signers,
    Signature[] memory signatures
  ) external {
    Agent memory agent = Agent("a", keccak256(abi.encode(locker, isLocker, nonce)));
    bytes32 message = hash(agent);

    require(!usedLockerUpdateMessages[message], "Locker message already used");

    checkValidatorSignatures(
      message,
      curColdValidatorSet,
      signers,
      signatures,
      coldValidatorSetHash
    );
    usedLockerUpdateMessages[message] = true;
    lockers[locker] = isLocker;
    emit ModifiedLocker(locker, isLocker);
  }

  // This function checks that the total power of the new validator set is greater than minTotalValidatorPower.
  function checkNewValidatorPowers(uint64[] memory powers) private view returns (uint64) {
    uint64 cumulativePower;
    for (uint64 i; i < powers.length; i++) {
      cumulativePower += powers[i];
    }

    require(
      cumulativePower >= minTotalValidatorPower,
      "Submitted validator powers is less than minTotalValidatorPower"
    );
    return cumulativePower;
  }

  // Ownership will be relinquished on public launch. The owner does not need power to force withdraw,
  // as that is controlled by the initially skewed distribution of L1 stake.
  // NOLAUNCH should be signed by validators' cold keys
  function changePowerThreshold(uint64 _powerThreshold) external onlyOwner whenPaused {
    powerThreshold = _powerThreshold;
  }

  function emergencyLock() external {
    require(lockers[msg.sender], "Sender is not authorized to lock smart contract");
    _pause();
  }

  function emergencyUnlock(
    uint64 nonce,
    ValidatorSet calldata curColdValidatorSet,
    address[] calldata signers,
    Signature[] calldata signatures
  ) external {
    Agent memory agent = Agent("a", keccak256(abi.encode("unlock", nonce)));
    bytes32 message = hash(agent);

    require(!usedUnlockMessages[message], "Unlocking request message already used");
    checkValidatorSignatures(
      message,
      curColdValidatorSet,
      signers,
      signatures,
      coldValidatorSetHash
    );
    _unpause();
  }
}
