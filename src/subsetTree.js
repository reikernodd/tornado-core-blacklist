const merkleTree = require('fixed-merkle-tree')
const Web3 = require('web3')
const { bigInt } = require('snarkjs')

// A simple empty leaf value (zero)
const ZERO_VALUE = '0000000000000000000000000000000000000000000000000000000000000000'

/**
 * Constructs the "Subset Tree" (Allowlist Tree)
 * * @param {Array} allDepositEvents - Array of all 'Deposit' events from the contract
 * @param {Array} blockedCommitments - Array of commitments (strings) that are on the BLOCKLIST
 * @param {Number} treeHeight - Height of the Merkle Tree (e.g., 20)
 * @returns {Object} The tree object and the subsetRoot
 */
function buildSubsetTree(allDepositEvents, blockedCommitments, treeHeight = 20) {
    // 1. Sort events by leafIndex to ensure correct tree position
    const sortedEvents = allDepositEvents.sort((a, b) => a.returnValues.leafIndex - b.returnValues.leafIndex)
    
    // 2. Extract leaves, but filter out the "Bad" ones
    // If a deposit is BLOCKED, we replace it with a ZERO_VALUE in the subset tree.
    // This effectively removes it from the set.
    const leaves = sortedEvents.map(e => {
        const commitment = e.returnValues.commitment
        if (blockedCommitments.includes(commitment)) {
            // This deposit is blocked! It does not exist in the Subset Tree.
            return ZERO_VALUE
        } else {
            // This deposit is good. It exists in the Subset Tree.
            return commitment
        }
    })

    // 3. Construct the Merkle Tree
    const tree = new merkleTree(treeHeight, leaves)
    return tree
}

/**
 * Prepares the inputs for the Privacy Pool Circuit
 */
async function generatePrivacyPoolInputs(deposit, allDepositEvents, blockedCommitments, contract, recipient, relayer, fee, refund) {
    const TREE_HEIGHT = 20;

    // 1. Build Main Tree (All deposits)
    // We need this to prove "I deposited funds into the contract"
    const leavesMain = allDepositEvents
        .sort((a, b) => a.returnValues.leafIndex - b.returnValues.leafIndex)
        .map(e => e.returnValues.commitment)
    const mainTree = new merkleTree(TREE_HEIGHT, leavesMain)
    
    // Find my deposit index
    const depositEvent = allDepositEvents.find(e => e.returnValues.commitment === deposit.commitmentHex)
    if (!depositEvent) throw new Error('Deposit not found on-chain')
    const leafIndex = depositEvent.returnValues.leafIndex

    // Path for Main Tree
    const { pathElements: pathElementsMain, pathIndices: pathIndicesMain } = mainTree.path(leafIndex)


    // 2. Build Subset Tree (Only Good deposits)
    // We need this to prove "I am NOT in the blocked list"
    const subsetTree = buildSubsetTree(allDepositEvents, blockedCommitments, TREE_HEIGHT)
    
    // Verify I am not blocked myself
    if (blockedCommitments.includes(deposit.commitmentHex)) {
        throw new Error('Your deposit is on the blocklist! You cannot use this subset root.')
    }

    // Path for Subset Tree
    // CRITICAL: We use the SAME leafIndex. The sparse tree structure mirrors the main tree.
    const { pathElements: pathElementsSubset } = subsetTree.path(leafIndex)

    // 3. Prepare Circuit Inputs
    const input = {
        // Public Inputs
        root: mainTree.root(),
        subsetRoot: subsetTree.root(),
        nullifierHash: deposit.nullifierHash,
        recipient: bigInt(recipient),
        relayer: bigInt(relayer),
        fee: bigInt(fee),
        refund: bigInt(refund),

        // Private Inputs
        nullifier: deposit.nullifier,
        secret: deposit.secret,
        pathElements: pathElementsMain,
        pathIndices: pathIndicesMain, // Shared indices
        subsetPathElements: pathElementsSubset
    }

    return input;
}

module.exports = {
    buildSubsetTree,
    generatePrivacyPoolInputs
}
