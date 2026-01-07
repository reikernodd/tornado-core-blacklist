// https://tornado.cash
/*
 * d888888P                                           dP              a88888b.                   dP
 *    88                                              88             d8'   `88                   88
 *    88    .d8888b. 88d888b. 88d888b. .d8888b. .d888b88 .d8888b.    88        .d8888b. .d8888b. 88d888b.
 *    88    88'  `88 88'  `88 88'  `88 88'  `88 88'  `88 88'  `88    88        88'  `88 Y8ooooo. 88'  `88
 *    88    88.  .88 88       88    88 88.  .88 88.  .88 88.  .88 dP Y8.   .88 88.  .88       88 88    88
 *    dP    `88888P' dP       dP    dP `88888P8 `88888P8 `88888P' 88  Y88888P' `88888P8 `88888P' dP    dP
 * ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo
 */

// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

interface IHasher {
  function poseidon(uint256[] calldata inputs) external pure returns (uint256);
}

contract MerkleTreeWithHistory {
  uint256 public constant FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
  uint256 public constant ZERO_VALUE = 21663839004416932945382355908790599225266501822907911457504978515578255421292; // = keccak256("tornado") % FIELD_SIZE
  IHasher public immutable hasher;

  uint32 public levels;

  // the following variables are made public for easier testing and debugging and
  // are not supposed to be accessed in regular code

  // filledSubtrees and roots could be bytes32[size], but using mappings makes it cheaper because
  // it removes index range check on every interaction
  mapping(uint256 => bytes32) public filledSubtrees;
  mapping(uint256 => bytes32) public roots;
  uint32 public constant ROOT_HISTORY_SIZE = 30;
  uint32 public currentRootIndex = 0;
  uint32 public nextIndex = 0;

  constructor(uint32 _levels, IHasher _hasher) {
    require(_levels > 0, "_levels should be greater than zero");
    require(_levels < 32, "_levels should be less than 32");
    levels = _levels;
    hasher = _hasher;

    for (uint32 i = 0; i < _levels; i++) {
      filledSubtrees[i] = zeros(i);
    }

    roots[0] = zeros(_levels - 1);
  }

  /**
    @dev Hash 2 tree leaves, returns Poseidon(_left, _right)
  */
  function hashLeftRight(
    IHasher _hasher,
    bytes32 _left,
    bytes32 _right
  ) public pure returns (bytes32) {
    require(uint256(_left) < FIELD_SIZE, "_left should be inside the field");
    require(uint256(_right) < FIELD_SIZE, "_right should be inside the field");
    uint256[] memory inputs = new uint256[](2);
    inputs[0] = uint256(_left);
    inputs[1] = uint256(_right);
    return bytes32(_hasher.poseidon(inputs));
  }

  function _insert(bytes32 _leaf) internal returns (uint32 index) {
    uint32 _nextIndex = nextIndex;
    require(_nextIndex != uint32(2)**levels, "Merkle tree is full. No more leaves can be added");
    uint32 currentIndex = _nextIndex;
    bytes32 currentLevelHash = _leaf;
    bytes32 left;
    bytes32 right;

    for (uint32 i = 0; i < levels; i++) {
      if (currentIndex % 2 == 0) {
        left = currentLevelHash;
        right = zeros(i);
        filledSubtrees[i] = currentLevelHash;
      } else {
        left = filledSubtrees[i];
        right = currentLevelHash;
      }
      currentLevelHash = hashLeftRight(hasher, left, right);
      currentIndex /= 2;
    }

    uint32 newRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
    currentRootIndex = newRootIndex;
    roots[newRootIndex] = currentLevelHash;
    nextIndex = _nextIndex + 1;
    return _nextIndex;
  }

  /**
    @dev Whether the root is present in the root history
  */
  function isKnownRoot(bytes32 _root) public view returns (bool) {
    if (_root == 0) {
      return false;
    }
    uint32 _currentRootIndex = currentRootIndex;
    uint32 i = _currentRootIndex;
    do {
      if (_root == roots[i]) {
        return true;
      }
      if (i == 0) {
        i = ROOT_HISTORY_SIZE;
      }
      i--;
    } while (i != _currentRootIndex);
    return false;
  }

  /**
    @dev Returns the last root
  */
  function getLastRoot() public view returns (bytes32) {
    return roots[currentRootIndex];
  }

  /// @dev provides Zero (Empty) elements for a Poseidon MerkleTree. Up to 32 levels
  function zeros(uint256 i) public pure returns (bytes32) {
    if (i == 0) return bytes32(0x2fe54c60d3acabf3343a35b6eba15db4821b340f76e741e2249685ed4899af6c);
    else if (i == 1) return bytes32(0x0e80204ea120b6116713569b8e063dd73d86b97fbaa5e38bba1989e5483ae6ba);
    else if (i == 2) return bytes32(0x2833499329c433b186f0859001cb75f2e2adaeb2e52562f2bb496153bc78809c);
    else if (i == 3) return bytes32(0x03a589f7271aa01ab2b2704c24f2d4e8ce022a7f0331f818b2fbd629ffd3f90e);
    else if (i == 4) return bytes32(0x035bfd5623eea842777d95c9e6d90afe7b14ed557f95bc10caa4325342de0d6d);
    else if (i == 5) return bytes32(0x196349ac368b96d64fb1e3163ca8174b9aaa6f36741051074a7b28193d7b2041);
    else if (i == 6) return bytes32(0x03b4b0eb55313670b28b9acf9a9ad65b1245d0728ea0cf409d615f86198b5109);
    else if (i == 7) return bytes32(0x082968da6f8664d7dac132783a65b8126a7e24c0700186866fac3a6a5eddcf0e);
    else if (i == 8) return bytes32(0x0243645de2dd1f5630bc6cabf7f175567f0a576f40361837d52893417cd5de41);
    else if (i == 9) return bytes32(0x143767667b19b2e2ac8fbdc00df2bfb9025d04d9cb7a1f6fda27b10b3273ca4b);
    else if (i == 10) return bytes32(0x22e875e5e54d8569fb40d0c568984e87b4c97da6383d8d8a334a79e22b48fd54);
    else if (i == 11) return bytes32(0x12c2124f020735af7cc5e84aaca6c4f23edaf5156f78982851647483e88666ba);
    else if (i == 12) return bytes32(0x10c26de9b22129ee8ca79a300c4583f639493418f861fe9904e2044fa2121832);
    else if (i == 13) return bytes32(0x1a75f4c95ed0184fcadd6b99375619d54e5151c75c8a3dc85ab1508ce7b2aca5);
    else if (i == 14) return bytes32(0x2f77bf1a25a3966e41e04050b41a1fe863ebf10c0d0daea51dcb7a2a81a568fb);
    else if (i == 15) return bytes32(0x0169cf86934651854a13223cc269ba1dd901646a676604288bc30d083fb92ded);
    else if (i == 16) return bytes32(0x1a0955631d8a21fc554d71fb0adf302d7db2979879dc27b60ca0b5c2a7fec3f2);
    else if (i == 17) return bytes32(0x179e27ed8730f82aa7d6609cd8c9cf8de3fa7c1f83be08f27126171c70044c1b);
    else if (i == 18) return bytes32(0x045d57705bc4e9f6541ca84dbaea34fbae55b40717a39ad3aa626887f7b3edc8);
    else if (i == 19) return bytes32(0x1cac34b26c1160fbefc0d645777540a68c22e55258a9b29cab88fe37a8bfd6ff);
    else revert("Index out of bounds");
  }
}