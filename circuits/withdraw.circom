pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/merkleTree.circom";

// MerkleProof verification template
template MerkleProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output root;

    component selectors[levels];
    component hashers[levels];

    for (var i = 0; i < levels; i++) {
        selectors[i] = DualMux();
        selectors[i].in[0] <== i == 0 ? leaf : hashers[i - 1].hash;
        selectors[i].in[1] <== pathElements[i];
        selectors[i].s <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== selectors[i].out[0];
        hashers[i].inputs[1] <== selectors[i].out[1];
    }

    root <== hashers[levels - 1].hash;
}

// DualMux helper for MerkleProof
template DualMux() {
    signal input in[2];
    signal input s;
    signal output out[2];

    s * (1 - s) === 0;
    out[0] <== (in[1] - in[0])*s + in[0];
    out[1] <== (in[0] - in[1])*s + in[1];
}

// Main Circuit
template Withdraw(levels) {
    // Public Inputs
    signal input root;          // The actual on-chain Merkle Root of all deposits
    signal input subsetRoot;    // The root of the "Clean Tree" (Blocklist applied)
    signal input nullifierHash; // To prevent double spending
    signal input recipient;     // Address to receive funds (binding to prevent front-running)
    signal input relayer;       // Address of relayer (binding)
    signal input fee;           // Fee for relayer (binding)
    signal input refund;        // Refund amount (binding)

    // Private Inputs
    signal input nullifier;
    signal input secret;
    signal input pathElements[levels];      // Path in the Main Tree
    signal input pathIndices[levels];       // Indices in the Main Tree
    signal input subsetPathElements[levels]; // Path in the Subset Tree
    // Note: pathIndices are the same for both trees because the leaf position doesn't change!

    // 1. Verify Leaf Construction
    component hasher = Poseidon(2);
    hasher.inputs[0] <== nullifier;
    hasher.inputs[1] <== secret;
    signal leaf <== hasher.hash;

    // 2. Verify Nullifier Hash
    component nullifierHasher = Poseidon(1);
    nullifierHasher.inputs[0] <== nullifier;
    nullifierHasher.out === nullifierHash;

    // 3. Verify Membership in Main Tree (Standard Tornado)
    component mainTree = MerkleProof(levels);
    mainTree.leaf <== leaf;
    for (var i = 0; i < levels; i++) {
        mainTree.pathElements[i] <== pathElements[i];
        mainTree.pathIndices[i] <== pathIndices[i];
    }
    mainTree.root === root;

    // 4. Verify Membership in Subset Tree (The "Safe" Part)
    component subsetTree = MerkleProof(levels);
    subsetTree.leaf <== leaf; // CRITICAL: Must use the SAME leaf
    for (var i = 0; i < levels; i++) {
        subsetTree.pathElements[i] <== subsetPathElements[i];
        subsetTree.pathIndices[i] <== pathIndices[i]; // Indices must be identical
    }
    subsetTree.root === subsetRoot;

    // 5. Square Constraints for Public Bindings (Prevent tampering)
    component txHasher = Poseidon(5);
    txHasher.inputs[0] <== recipient;
    txHasher.inputs[1] <== relayer;
    txHasher.inputs[2] <== fee;
    txHasher.inputs[3] <== refund;
    txHasher.inputs[4] <== nullifierHash;
    // The output is not checked here, but binds the inputs to the proof generation 
    // if this hash is used in the solidity verifier or signal aggregation.
}

component main {public [root, subsetRoot, nullifierHash, recipient, relayer, fee, refund]} = Withdraw(20);
