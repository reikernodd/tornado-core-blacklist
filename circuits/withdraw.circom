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
    signal input subsetRoot;    // The root of the "Clean Tree" (Allowlist or Blocklist complement)
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
    
    // Note: pathIndices are the same for both trees because the leaf position 
    // is identical in the main tree and the subset tree (sparse tree).

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
    // This proves the deposit actually exists in the history of the protocol.
    component mainTree = MerkleProof(levels);
    mainTree.leaf <== leaf;
    for (var i = 0; i < levels; i++) {
        mainTree.pathElements[i] <== pathElements[i];
        mainTree.pathIndices[i] <== pathIndices[i];
    }
    mainTree.root === root;

    // 4. Verify Membership in Subset Tree (The "Privacy Pool" Logic)
    // This proves: "My leaf exists in the tree defined by subsetRoot".
    // 
    // How this works for "Any Set of Lists":
    // The subsetRoot should be the Merkle Root of a tree that contains 
    // ONLY the "allowed" deposits (or the complement of "blocked" deposits).
    // By proving your leaf is in this tree, you prove you are part of that specific subset.
    //
    // Since we use the SAME leaf and SAME pathIndices as the main tree,
    // we effectively prove: Leaf is in (Main Tree AND Subset Tree).
    component subsetTree = MerkleProof(levels);
    subsetTree.leaf <== leaf; 
    for (var i = 0; i < levels; i++) {
        subsetTree.pathElements[i] <== subsetPathElements[i];
        subsetTree.pathIndices[i] <== pathIndices[i]; 
    }
    subsetTree.root === subsetRoot;

    // 5. Binding Constraints
    // In this implementation, we use the public inputs directly.
    // The Verifier contract MUST ensure `recipient`, `relayer`, etc., match the transaction.
}

component main {public [root, subsetRoot, nullifierHash, recipient, relayer, fee, refund]} = Withdraw(20);
