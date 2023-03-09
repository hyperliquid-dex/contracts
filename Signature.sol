// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

struct Agent {
  string source;
  bytes32 connectionId;
}

struct Signature {
  uint256 r;
  uint256 s;
  uint8 v;
}

uint256 constant LOCALHOST_CHAIN_ID = 1337;
uint256 constant ARBITRUM_GOERLI_CHAIN_ID = 421613;
uint256 constant ARBITRUM_CHAIN_ID = 42161;

bytes32 constant EIP712DOMAIN_TYPEHASH = keccak256(
  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
);

bytes32 constant AGENT_TYPEHASH = keccak256("Agent(string source,bytes32 connectionId)");

// TODO use the actual contract address
address constant VERIFYING_CONTRACT = address(0);

bytes32 constant LOCALHOST_DOMAIN_HASH = keccak256(
  abi.encode(
    EIP712DOMAIN_TYPEHASH,
    keccak256(bytes("Exchange")),
    keccak256(bytes("1")),
    LOCALHOST_CHAIN_ID,
    VERIFYING_CONTRACT
  )
);

bytes32 constant ARBITRUM_GOERLI_DOMAIN_HASH = keccak256(
  abi.encode(
    EIP712DOMAIN_TYPEHASH,
    keccak256(bytes("Exchange")),
    keccak256(bytes("1")),
    ARBITRUM_GOERLI_CHAIN_ID,
    VERIFYING_CONTRACT
  )
);

bytes32 constant ARBITRUM_DOMAIN_HASH = keccak256(
  abi.encode(
    EIP712DOMAIN_TYPEHASH,
    keccak256(bytes("Exchange")),
    keccak256(bytes("1")),
    ARBITRUM_CHAIN_ID,
    VERIFYING_CONTRACT
  )
);

function hash(Agent memory agent) pure returns (bytes32) {
  return keccak256(abi.encode(AGENT_TYPEHASH, keccak256(bytes(agent.source)), agent.connectionId));
}

function recoverSigner(bytes32 dataHash, Signature memory sig) view returns (address) {
  bytes32 domainHash;
  if (block.chainid == ARBITRUM_CHAIN_ID) {
    domainHash = ARBITRUM_DOMAIN_HASH;
  } else if (block.chainid == LOCALHOST_CHAIN_ID) {
    domainHash = LOCALHOST_DOMAIN_HASH;
  } else if (block.chainid == ARBITRUM_GOERLI_CHAIN_ID) {
    domainHash = ARBITRUM_GOERLI_DOMAIN_HASH;
  } else {
    require(false, "bad chainId");
  }
  bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainHash, dataHash));
  return ecrecover(digest, sig.v, bytes32(sig.r), bytes32(sig.s));
}
