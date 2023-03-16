// SPDX-License-Identifier: UNLICENSED

/*
    This bridge contract runs on Arbitrum, operating alongside the Hyperliquid L1.
    The only asset for now is USDC, though the logic extends to any other ERC20 token on Arbitrum.
    The L1 runs tendermint consensus, with validator set updates happening at the end of each epoch.
    Epoch duration TBD, but likely somewhere between 1 day and 1 week

    Validator set updates:
      The current validators sign a hash of the new validator set and powers on the L1.
      This contract checks those signatures, and updates the hash of the current validator set.
      The current validators' stake is still locked for at least one more epoch (unbonding period),
      and the new validators will slash the old ones' stake if they do not properly generate the
      validator set update signatures.

    Withdrawals:
      The validators sign withdrawals on the L1, which the user sends to this contract in withdraw().
      This contract checks the signatures, and then sends the USDC to the user.

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
  uint256 epoch;
  address[] validators;
  uint256[] powers;
}

struct DepositEvent {
  address user;
  uint256 usdc;
  uint256 timestamp;
}

struct WithdrawEvent {
  address user;
  uint256 usdc;
  ValidatorSet validatorSet;
  uint256 timestamp;
}

contract Bridge2 is Ownable, Pausable, ReentrancyGuard {
  ERC20 usdcToken;

  bytes32 public validatorSetCheckpoint;
  uint256 public epoch;
  uint256 public powerThreshold;
  uint256 public minTotalValidatorPower;
  // Expose this for convenience because we only store the hash.
  uint256 public nValidators;

  mapping(bytes32 => bool) processedWithdrawals;

  // These events wrap structs because of a quirk of rust client code which parses them.
  event Deposit(DepositEvent e);
  event Withdraw(WithdrawEvent e);

  event ValidatorSetUpdatedEvent(uint256 indexed epoch, address[] validators, uint256[] powers);

  // TODO if it saves gas, have the deployer initialize separately so that all function args can be calldata.
  // However, calldata does not seem to save gas on Arbitrum, so not a big deal for now.
  constructor(
    uint256 _minTotalValidatorPower,
    address[] memory validators,
    uint256[] memory powers,
    address usdcAddress
  ) {
    minTotalValidatorPower = _minTotalValidatorPower;
    powerThreshold = (2 * _minTotalValidatorPower) / 3;

    checkNewValidatorPowers(powers);
    nValidators = validators.length;

    ValidatorSet memory validatorSet;
    validatorSet = ValidatorSet(0, validators, powers);
    bytes32 newCheckpoint = makeCheckpoint(validatorSet);
    validatorSetCheckpoint = newCheckpoint;
    usdcToken = ERC20(usdcAddress);

    emit ValidatorSetUpdatedEvent(0, validators, powers);
  }

  function makeCheckpoint(ValidatorSet memory validatorSet) private pure returns (bytes32) {
    require(
      validatorSet.validators.length == validatorSet.powers.length,
      "Malformed validator set"
    );

    bytes32 checkpoint = keccak256(
      abi.encode(validatorSet.validators, validatorSet.powers, validatorSet.epoch)
    );
    return checkpoint;
  }

  function deposit(uint256 usdc) external whenNotPaused nonReentrant {
    address user = msg.sender;
    usdcToken.transferFrom(user, address(this), usdc);
    emit Deposit(DepositEvent({ user: user, usdc: usdc, timestamp: blockMillis() }));
  }

  function withdraw(
    uint256 usdc,
    uint256 nonce,
    ValidatorSet calldata curValidatorSet,
    address[] calldata signers,
    Signature[] calldata signatures
  ) external nonReentrant whenNotPaused {
    // NOTE: this is a temporary workaround because EIP-191 signatures do not match between rust client and solidity.
    // For now we do not care about the overhead with EIP-712 because Arbitrum gas is basically free.
    Agent memory agent = Agent("a", keccak256(abi.encode(msg.sender, usdc, nonce)));
    bytes32 message = hash(agent);

    require(!processedWithdrawals[message], "Already withdrawn");
    processedWithdrawals[message] = true;

    checkValidatorSignatures(message, curValidatorSet, signers, signatures);
    usdcToken.transfer(msg.sender, usdc);

    emit Withdraw(
      WithdrawEvent({
        user: msg.sender,
        usdc: usdc,
        validatorSet: curValidatorSet,
        timestamp: blockMillis()
      })
    );
  }

  function checkValidatorSignatures(
    bytes32 message,
    ValidatorSet memory curValidatorSet, // Current set of all L1 validators
    address[] memory signers, // Subsequence of the current L1 validators that signed the message
    Signature[] memory signatures
  ) private view {
    require(
      makeCheckpoint(curValidatorSet) == validatorSetCheckpoint,
      "Supplied current validators and powers do not match the current checkpoint"
    );

    uint256 nSigners = signers.length;
    require(nSigners > 0, "Signers empty");
    require(nSigners == signatures.length, "Signatures and signers have different lengths");

    uint256 cumulativePower = 0;
    uint256 signerIdx = 0;
    uint256 end = curValidatorSet.validators.length;

    for (uint256 curValidatorSetIdx = 0; curValidatorSetIdx < end; curValidatorSetIdx++) {
      address signer = signers[signerIdx];
      if (signer == curValidatorSet.validators[curValidatorSetIdx]) {
        uint256 power = curValidatorSet.powers[curValidatorSetIdx];
        require(
          recoverSigner(message, signatures[signerIdx]) == signer,
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

  function updateValidatorSet(
    ValidatorSet memory newValidatorSet,
    ValidatorSet memory curValidatorSet,
    address[] memory signers,
    Signature[] memory signatures
  ) external whenNotPaused {
    {
      require(
        makeCheckpoint(curValidatorSet) == validatorSetCheckpoint,
        "Supplied current validators and powers do not match checkpoint"
      );

      require(
        newValidatorSet.epoch > curValidatorSet.epoch,
        "New validator set epoch must be greater than the current epoch"
      );
    }

    uint256 cumulativePower = checkNewValidatorPowers(newValidatorSet.powers);
    bytes32 newCheckpoint = makeCheckpoint(newValidatorSet);
    Agent memory agent = Agent("a", newCheckpoint);
    bytes32 message = hash(agent);
    checkValidatorSignatures(message, curValidatorSet, signers, signatures);
    validatorSetCheckpoint = newCheckpoint;
    epoch = newValidatorSet.epoch;
    powerThreshold = (2 * cumulativePower) / 3;
    nValidators = newValidatorSet.validators.length;

    emit ValidatorSetUpdatedEvent(
      newValidatorSet.epoch,
      newValidatorSet.validators,
      newValidatorSet.powers
    );
  }

  function checkNewValidatorPowers(uint256[] memory powers) private view returns (uint256) {
    uint256 cumulativePower = 0;
    for (uint256 i = 0; i < powers.length; i++) {
      cumulativePower = cumulativePower + powers[i];
    }

    require(
      cumulativePower >= minTotalValidatorPower,
      "Submitted validator powers is less than minTotalValidatorPower"
    );
    return cumulativePower;
  }

  function blockMillis() private view returns (uint256) {
    return 1000 * block.timestamp;
  }

  // Ownership will be relinquished on public launch. The owner does not need power to force withdraw,
  // as that is controlled by the initially skewed distribution of L1 stake.
  function changePowerThreshold(uint256 _powerThreshold) external onlyOwner whenPaused {
    powerThreshold = _powerThreshold;
  }

  function emergencyPause() external onlyOwner {
    _pause();
  }

  function emergencyUnpause() external onlyOwner {
    _unpause();
  }
}
