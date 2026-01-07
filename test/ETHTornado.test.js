/* global artifacts, web3, contract */
require('chai').use(require('bn-chai')(web3.utils.BN)).use(require('chai-as-promised')).should()
const fs = require('fs')

const { toBN, randomHex } = require('web3-utils')
const { takeSnapshot, revertSnapshot } = require('../scripts/ganacheHelper')

const Tornado = artifacts.require('./ETHTornado.sol')
const { ETH_AMOUNT, MERKLE_TREE_HEIGHT } = process.env

// const websnarkUtils = require('websnark/src/utils')
// const buildGroth16 = require('websnark/src/groth16')
// const stringifyBigInts = require('websnark/tools/stringifybigint').stringifyBigInts
const snarkjs = require('snarkjs')
// const bigInt = snarkjs.bigInt
const crypto = require('crypto')
const circomlib = require('circomlib')
const MerkleTree = require('fixed-merkle-tree')

function stringifyBigInts(obj) {
  if (typeof obj === 'bigint') return obj.toString()
  if (typeof obj === 'number') return obj.toString()
  if (Array.isArray(obj)) return obj.map(stringifyBigInts)
  if (typeof obj === 'object' && obj !== null) {
    const res = {}
    for (const key in obj) {
      res[key] = stringifyBigInts(obj[key])
    }
    return res
  }
  return obj
}

const rbigint = (nbytes) => BigInt('0x' + crypto.randomBytes(nbytes).toString('hex'))
const path = require('path')
const poseidon = require(path.join(__dirname, '../node_modules/fixed-merkle-tree/node_modules/circomlib/src/poseidon.js'))
const poseidonHash = (...args) => {
  const inputs = args.length === 1 && Array.isArray(args[0]) ? args[0] : args
  return poseidon(inputs)
}
const toFixedHex = (number, length = 32) =>
  '0x' +
  (typeof number === 'bigint' ? number.toString(16) : BigInt(number).toString(16))
    .padStart(length * 2, '0')
const getRandomRecipient = () => rbigint(20)

function generateDeposit() {
  let deposit = {
    secret: rbigint(31),
    nullifier: rbigint(31),
  }
  deposit.commitment = poseidonHash([deposit.nullifier, deposit.secret])
  return deposit
}

// eslint-disable-next-line no-unused-vars
function BNArrayToStringArray(array) {
  const arrayToPrint = []
  array.forEach((item) => {
    arrayToPrint.push(item.toString())
  })
  return arrayToPrint
}

function snarkVerify(proof) {
  proof = unstringifyBigInts2(proof)
  const verification_key = unstringifyBigInts2(require('../build/circuits/withdraw_verification_key.json'))
  return snarkjs['groth'].isValid(verification_key, proof, proof.publicSignals)
}

contract('ETHTornado', (accounts) => {
  let tornado
  const sender = accounts[0]
  const operator = accounts[0]
  const levels = MERKLE_TREE_HEIGHT || 16
  const value = ETH_AMOUNT || '1000000000000000000' // 1 ether
  let snapshotId
  let tree
  const fee = BigInt(ETH_AMOUNT) / 2n
  const refund = BigInt(0)
  const recipient = getRandomRecipient()
  const relayer = accounts[1]
  // let groth16
  // let circuit
  // let proving_key

  async function prove(input) {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, 'build/circuits/withdraw_js/withdraw.wasm', 'withdraw_final.zkey');
    const callData = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)
    const json = JSON.parse('[' + callData + ']')
    return {
      pA: json[0],
      pB: json[1],
      pC: json[2],
      args: json[3]
    }
  }

  before(async () => {
    tree = new MerkleTree(levels, [], { hashFunction: poseidonHash, zeroElement: '21663839004416932945382355908790599225266501822907911457504978515578255421292' })
    tornado = await Tornado.deployed()
    snapshotId = await takeSnapshot()
    // groth16 = await buildGroth16()
    // circuit = require('../build/circuits/withdraw.json')
    // proving_key = fs.readFileSync('build/circuits/withdraw_proving_key.bin').buffer
  })

  describe('#constructor', () => {
    it('should initialize', async () => {
      const etherDenomination = await tornado.denomination()
      etherDenomination.should.be.eq.BN(toBN(value))
    })
  })

  describe('#deposit', () => {
    it('should emit event', async () => {
      let commitment = toFixedHex(42)
      let { logs } = await tornado.deposit(commitment, { value, from: sender })

      logs[0].event.should.be.equal('Deposit')
      logs[0].args.commitment.should.be.equal(commitment)
      logs[0].args.leafIndex.should.be.eq.BN(0)

      commitment = toFixedHex(12)
      ;({ logs } = await tornado.deposit(commitment, { value, from: accounts[2] }))

      logs[0].event.should.be.equal('Deposit')
      logs[0].args.commitment.should.be.equal(commitment)
      logs[0].args.leafIndex.should.be.eq.BN(1)
    })

    it('should throw if there is a such commitment', async () => {
      const commitment = toFixedHex(42)
      await tornado.deposit(commitment, { value, from: sender }).should.be.fulfilled
      const error = await tornado.deposit(commitment, { value, from: sender }).should.be.rejected
      error.reason.should.be.equal('The commitment has been submitted')
    })
  })

  describe('snark proof verification on js side', () => {
    it('should detect tampering', async () => {
      const deposit = generateDeposit()
      tree.insert(deposit.commitment)
      const { pathElements, pathIndices } = tree.path(0)

      const input = stringifyBigInts({
        root: tree.root(),
        subsetRoot: tree.root(),
        nullifierHash: poseidonHash([deposit.nullifier]),
        nullifier: deposit.nullifier,
        relayer: operator,
        recipient,
        fee,
        refund,
        secret: deposit.secret,
        pathElements: pathElements,
        pathIndices: pathIndices,
        subsetPathElements: pathElements
      })

      const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, 'build/circuits/withdraw_js/withdraw.wasm', 'withdraw_final.zkey');
      const vKey = require('../build/circuits/withdraw_verification_key.json');
      let result = await snarkjs.groth16.verify(vKey, publicSignals, proof);
      result.should.be.equal(true)

      // tamper with public signals
      publicSignals[1] = '133792158246920651341275668520530514036799294649489851421007411546007850802'
      result = await snarkjs.groth16.verify(vKey, publicSignals, proof);
      result.should.be.equal(false)
    })
  })

  describe('#withdraw', () => {
    it('should work', async () => {
      const deposit = generateDeposit()
      const user = accounts[4]
      tree.insert(deposit.commitment)

      const balanceUserBefore = await web3.eth.getBalance(user)

      // Uncomment to measure gas usage
      // let gas = await tornado.deposit.estimateGas(toBN(deposit.commitment.toString()), { value, from: user, gasPrice: '0' })
      // console.log('deposit gas:', gas)
      await tornado.deposit(toFixedHex(deposit.commitment), { value, from: user, gasPrice: '0' })

      const balanceUserAfter = await web3.eth.getBalance(user)
      balanceUserAfter.should.be.eq.BN(toBN(balanceUserBefore).sub(toBN(value)))

      const { pathElements, pathIndices } = tree.path(0)

      // Circuit input
      const input = stringifyBigInts({
        // public
        root: tree.root(),
        subsetRoot: tree.root(),
        nullifierHash: poseidonHash([deposit.nullifier]),
        relayer: operator,
        recipient,
        fee,
        refund,

        // private
        nullifier: deposit.nullifier,
        secret: deposit.secret,
        pathElements: pathElements,
        pathIndices: pathIndices,
        subsetPathElements: pathElements
      })

      const { pA, pB, pC, args } = await prove(input)

      const balanceTornadoBefore = await web3.eth.getBalance(tornado.address)
      const balanceRelayerBefore = await web3.eth.getBalance(relayer)
      const balanceOperatorBefore = await web3.eth.getBalance(operator)
      const balanceReceiverBefore = await web3.eth.getBalance(toFixedHex(recipient, 20))
      let isSpent = await tornado.isSpent(toFixedHex(input.nullifierHash))
      isSpent.should.be.equal(false)

      const { logs } = await tornado.withdraw(pA, pB, pC, ...args, { from: relayer, gasPrice: '0' })

      const balanceTornadoAfter = await web3.eth.getBalance(tornado.address)
      const balanceRelayerAfter = await web3.eth.getBalance(relayer)
      const balanceOperatorAfter = await web3.eth.getBalance(operator)
      const balanceReceiverAfter = await web3.eth.getBalance(toFixedHex(recipient, 20))
      const feeBN = toBN(fee.toString())
      balanceTornadoAfter.should.be.eq.BN(toBN(balanceTornadoBefore).sub(toBN(value)))
      balanceRelayerAfter.should.be.eq.BN(toBN(balanceRelayerBefore))
      balanceOperatorAfter.should.be.eq.BN(toBN(balanceOperatorBefore).add(feeBN))
      balanceReceiverAfter.should.be.eq.BN(toBN(balanceReceiverBefore).add(toBN(value)).sub(feeBN))

      logs[0].event.should.be.equal('Withdrawal')
      logs[0].args.nullifierHash.should.be.equal(toFixedHex(input.nullifierHash))
      logs[0].args.relayer.should.be.eq.BN(operator)
      logs[0].args.fee.should.be.eq.BN(feeBN)
      isSpent = await tornado.isSpent(toFixedHex(input.nullifierHash))
      isSpent.should.be.equal(true)
    })

    it('should prevent double spend', async () => {
      const deposit = generateDeposit()
      tree.insert(deposit.commitment)
      await tornado.deposit(toFixedHex(deposit.commitment), { value, from: sender })

      const { pathElements, pathIndices } = tree.path(0)

      const input = stringifyBigInts({
        root: tree.root(),
        subsetRoot: tree.root(),
        nullifierHash: poseidonHash([deposit.nullifier]),
        nullifier: deposit.nullifier,
        relayer: operator,
        recipient,
        fee,
        refund,
        secret: deposit.secret,
        pathElements: pathElements,
        pathIndices: pathIndices,
        subsetPathElements: pathElements
      })
      const { pA, pB, pC, args } = await prove(input)
      await tornado.withdraw(pA, pB, pC, ...args, { from: relayer }).should.be.fulfilled
      const error = await tornado.withdraw(pA, pB, pC, ...args, { from: relayer }).should.be.rejected
      error.reason.should.be.equal('The note has been already spent')
    })

    it('fee should be less or equal transfer value', async () => {
      const deposit = generateDeposit()
      tree.insert(deposit.commitment)
      await tornado.deposit(toFixedHex(deposit.commitment), { value, from: sender })

      const { pathElements, pathIndices } = tree.path(0)
      const largeFee = BigInt(value) + 1n
      const input = stringifyBigInts({
        root: tree.root(),
        subsetRoot: tree.root(),
        nullifierHash: poseidonHash([deposit.nullifier]),
        nullifier: deposit.nullifier,
        relayer: operator,
        recipient,
        fee: largeFee,
        refund,
        secret: deposit.secret,
        pathElements: pathElements,
        pathIndices: pathIndices,
        subsetPathElements: pathElements
      })

      const { pA, pB, pC, args } = await prove(input)
      const error = await tornado.withdraw(pA, pB, pC, ...args, { from: relayer }).should.be.rejected
      error.reason.should.be.equal('Fee exceeds transfer value')
    })

    it('should throw for corrupted merkle tree root', async () => {
      const deposit = generateDeposit()
      tree.insert(deposit.commitment)
      await tornado.deposit(toFixedHex(deposit.commitment), { value, from: sender })

      const { pathElements, pathIndices } = tree.path(0)

      const input = stringifyBigInts({
        root: tree.root(),
        subsetRoot: tree.root(),
        nullifierHash: poseidonHash([deposit.nullifier]),
        nullifier: deposit.nullifier,
        relayer: operator,
        recipient,
        fee,
        refund,
        secret: deposit.secret,
        pathElements: pathElements,
        pathIndices: pathIndices,
        subsetPathElements: pathElements
      })

      const { pA, pB, pC, args } = await prove(input)
      const corruptedArgs = [...args]
      corruptedArgs[0] = toFixedHex(randomHex(32))

      const error = await tornado.withdraw(pA, pB, pC, ...corruptedArgs, { from: relayer }).should.be.rejected
      error.reason.should.be.equal('Cannot find your merkle root')
    })

    it('should reject with tampered public inputs', async () => {
      const deposit = generateDeposit()
      tree.insert(deposit.commitment)
      await tornado.deposit(toFixedHex(deposit.commitment), { value, from: sender })

      let { pathElements, pathIndices } = tree.path(0)

      const input = stringifyBigInts({
        root: tree.root(),
        subsetRoot: tree.root(),
        nullifierHash: poseidonHash([deposit.nullifier]),
        nullifier: deposit.nullifier,
        relayer: operator,
        recipient,
        fee,
        refund,
        secret: deposit.secret,
        pathElements: pathElements,
        pathIndices: pathIndices,
        subsetPathElements: pathElements
      })
      const { pA, pB, pC, args } = await prove(input)
      
      let incorrectArgs

      // recipient
      incorrectArgs = [...args]
      incorrectArgs[3] = toFixedHex('0x0000000000000000000000007a1f9131357404ef86d7c38dbffed2da70321337', 20)
      let error = await tornado.withdraw(pA, pB, pC, ...incorrectArgs, { from: relayer }).should.be.rejected
      error.reason.should.be.equal('Invalid withdraw proof')

      // fee
      incorrectArgs = [...args]
      incorrectArgs[5] = toFixedHex('0x000000000000000000000000000000000000000000000000015345785d8a0000')
      error = await tornado.withdraw(pA, pB, pC, ...incorrectArgs, { from: relayer }).should.be.rejected
      error.reason.should.be.equal('Invalid withdraw proof')

      // should work with original values
      await tornado.withdraw(pA, pB, pC, ...args, { from: relayer }).should.be.fulfilled
    })

    it('should reject with non zero refund', async () => {
      const deposit = generateDeposit()
      tree.insert(deposit.commitment)
      await tornado.deposit(toFixedHex(deposit.commitment), { value, from: sender })

      const { pathElements, pathIndices } = tree.path(0)

      const input = stringifyBigInts({
        root: tree.root(),
        subsetRoot: tree.root(),
        nullifierHash: poseidonHash([deposit.nullifier]),
        nullifier: deposit.nullifier,
        relayer: operator,
        recipient,
        fee,
        refund: BigInt(1),
        secret: deposit.secret,
        pathElements: pathElements,
        pathIndices: pathIndices,
        subsetPathElements: pathElements
      })

      const { pA, pB, pC, args } = await prove(input)
      const error = await tornado.withdraw(pA, pB, pC, ...args, { from: relayer }).should.be.rejected
      error.reason.should.be.equal('Refund value is supposed to be zero for ETH instance')
    })
  })

  describe('#isSpent', () => {
    it('should work', async () => {
      const deposit1 = generateDeposit()
      const deposit2 = generateDeposit()
      tree.insert(deposit1.commitment)
      tree.insert(deposit2.commitment)
      await tornado.deposit(toFixedHex(deposit1.commitment), { value, gasPrice: '0' })
      await tornado.deposit(toFixedHex(deposit2.commitment), { value, gasPrice: '0' })

      const { pathElements, pathIndices } = tree.path(1)

      // Circuit input
      const input = stringifyBigInts({
        // public
        root: tree.root(),
        subsetRoot: tree.root(),
        nullifierHash: poseidonHash([deposit2.nullifier]),
        relayer: operator,
        recipient,
        fee,
        refund,

        // private
        nullifier: deposit2.nullifier,
        secret: deposit2.secret,
        pathElements: pathElements,
        pathIndices: pathIndices,
        subsetPathElements: pathElements
      })

      const { pA, pB, pC, args } = await prove(input)

      await tornado.withdraw(pA, pB, pC, ...args, { from: relayer, gasPrice: '0' })

      const nullifierHash1 = toFixedHex(poseidonHash([deposit1.nullifier]))
      const nullifierHash2 = toFixedHex(poseidonHash([deposit2.nullifier]))
      const spentArray = await tornado.isSpentArray([nullifierHash1, nullifierHash2])
      spentArray.should.be.deep.equal([false, true])
    })
  })

  afterEach(async () => {
    await revertSnapshot(snapshotId.result)
    // eslint-disable-next-line require-atomic-updates
    snapshotId = await takeSnapshot()
    tree = new MerkleTree(levels)
  })
})
