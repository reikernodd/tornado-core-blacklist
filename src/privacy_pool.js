const merkleTree = require('fixed-merkle-tree')
const snarkjs = require('snarkjs')
const { bigInt } = snarkjs
const path = require('path')
const poseidon = require(path.join(__dirname, '../node_modules/fixed-merkle-tree/node_modules/circomlib/src/poseidon.js'))

const poseidonHash = (...args) => {
  const inputs = args.length === 1 && Array.isArray(args[0]) ? args[0] : args
  return poseidon(inputs)
}
const ZERO_VALUE = '21663839004416932945382355908790599225266501822907911457504978515578255421292'

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
    const tree = new merkleTree(treeHeight, leaves, { hashFunction: poseidonHash, zeroElement: ZERO_VALUE })
    return tree
}

module.exports = {
    buildSubsetTree
}