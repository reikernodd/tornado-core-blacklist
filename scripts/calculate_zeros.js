const path = require('path')
const poseidon = require(path.join(__dirname, '../node_modules/fixed-merkle-tree/node_modules/circomlib/src/poseidon.js'))
const { bigInt } = require('snarkjs')

const ZERO_VALUE = bigInt('21663839004416932945382355908790599225266501822907911457504978515578255421292')

function main() {
    let current = ZERO_VALUE
    for (let i = 0; i < 20; i++) {
        console.log(`else if (i == ${i}) return bytes32(0x${current.toString(16).padStart(64, '0')});`)
        current = poseidon([current, current])
    }
}

main()
