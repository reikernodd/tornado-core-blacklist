#!/bin/bash
set -e

echo "Starting Trusted Setup Ceremony..."

# 1. Powers of Tau
# Create a new powers of tau ceremony (bn128, 12)
if [ ! -f "pot16_0000.ptau" ]; then
    echo "Creation of Powers of Tau..."
    snarkjs powersoftau new bn128 16 pot16_0000.ptau -v
fi

# Contribute to the ceremony
if [ ! -f "pot16_final.ptau" ]; then
    echo "Contribution to Powers of Tau..."
    snarkjs powersoftau contribute pot16_0000.ptau pot16_0001.ptau --name="First Contribution" -v -e="random text"
    
    # Prepare for phase 2
    echo "Preparing for Phase 2..."
    snarkjs powersoftau prepare phase2 pot16_0001.ptau pot16_final.ptau -v
fi

# 2. Circuit Setup (Groth16)
# Ensure build directory exists
mkdir -p build/circuits

if [ ! -f "withdraw_final.zkey" ]; then
    echo "Groth16 Setup..."
    snarkjs groth16 setup build/circuits/withdraw.r1cs pot16_final.ptau withdraw_0000.zkey

    echo "Contribution to zkey..."
    snarkjs zkey contribute withdraw_0000.zkey withdraw_final.zkey --name="Second Contribution" -v -e="more random text"
fi

# 3. Export Keys
echo "Exporting Verification Key..."
snarkjs zkey export verificationkey withdraw_final.zkey build/circuits/withdraw_verification_key.json

echo "Exporting Solidity Verifier..."
snarkjs zkey export solidityverifier withdraw_final.zkey contracts/Verifier.sol

echo "Trusted Setup Complete!"
