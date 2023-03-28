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

bytes32 constant EIP712_DOMAIN_SEPARATOR = keccak256(
  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
);

bytes32 constant AGENT_TYPEHASH = keccak256("Agent(string source,bytes32 connectionId)");

address constant VERIFYING_CONTRACT = address(0);

function hash(Agent memory agent) pure returns (bytes32) {
  return keccak256(abi.encode(AGENT_TYPEHASH, keccak256(bytes(agent.source)), agent.connectionId));
}

function makeDomainSeparator() view returns (bytes32) {
  return
    keccak256(
      abi.encode(
        EIP712_DOMAIN_SEPARATOR,
        keccak256(bytes("Exchange")),
        keccak256(bytes("1")),
        block.chainid,
        VERIFYING_CONTRACT
      )
    );
}

function recoverSigner(
  bytes32 dataHash,
  Signature memory sig,
  bytes32 domainSeparator
) pure returns (address) {
  bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, dataHash));
  address signerRecovered = ecrecover(digest, sig.v, bytes32(sig.r), bytes32(sig.s));
  require(signerRecovered != address(0), "Invalid signature, recovered the zero address");

  return signerRecovered;
}
