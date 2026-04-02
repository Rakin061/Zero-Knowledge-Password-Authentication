#!/usr/bin/env bash
# =============================================================
# setup.sh — One-time trusted setup for zk-password-auth
# CISC 878 Advanced Cryptographic Techniques — Queen's University
#
# Run this ONCE before using register.js or login.js.
# All generated files except verification_key.json are gitignored.
#
# Prerequisites:
#   - circom 2.x installed (https://docs.circom.io/getting-started/installation/)
#   - snarkjs installed: npm install -g snarkjs
#   - Node.js LTS installed: https://nodejs.org/
#
# Usage:
#   bash scripts/setup.sh
# =============================================================

set -e  # exit on any error

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"
SETUP="$ROOT/setup"
CIRCUITS="$ROOT/circuits"

echo "[SETUP] ZK Password Auth — Trusted Setup Pipeline"
echo "[SETUP] =========================================="
echo ""

# Check prerequisites
for cmd in circom snarkjs node; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "[SETUP] ERROR: '$cmd' not found. Please install it first."
        exit 1
    fi
done

# Install npm dependencies
echo "[SETUP] Installing npm dependencies..."
cd "$ROOT"
npm install
echo ""

# Step 1: Compile circuit
echo "[SETUP] Step 1/6: Compiling circuit..."
mkdir -p "$BUILD"
circom "$CIRCUITS/password_policy.circom" --r1cs --wasm --sym -o "$BUILD/"
echo "[SETUP] Circuit compiled successfully."
echo ""

# Print constraint count
CONSTRAINTS=$(snarkjs r1cs info "$BUILD/password_policy.r1cs" 2>&1 | grep "# of Constraints" | awk '{print $NF}')
echo "[SETUP] Circuit constraints: $CONSTRAINTS"
echo ""

# Step 2: Powers of Tau — Phase 1
# Using bn128 14 (2^14 = 16384 capacity) to handle Poseidon + policy constraints
echo "[SETUP] Step 2/6: Powers of Tau — Phase 1 (bn128 14)..."
mkdir -p "$SETUP"
snarkjs powersoftau new bn128 14 "$SETUP/pot14_0000.ptau" -v
echo ""

# Step 3: Phase 1 contribution
echo "[SETUP] Step 3/6: Phase 1 contribution..."
snarkjs powersoftau contribute \
    "$SETUP/pot14_0000.ptau" \
    "$SETUP/pot14_0001.ptau" \
    --name="ZK Password Auth Setup" \
    -e="$(date +%s%N)-$(hostname)-entropy"
echo ""

# Step 4: Prepare Phase 2
echo "[SETUP] Step 4/6: Prepare Phase 2..."
snarkjs powersoftau prepare phase2 \
    "$SETUP/pot14_0001.ptau" \
    "$SETUP/pot14_final.ptau" \
    -v
echo ""

# Step 5: Circuit-specific setup (Phase 2)
echo "[SETUP] Step 5/6: Circuit-specific zkey generation..."
snarkjs groth16 setup \
    "$BUILD/password_policy.r1cs" \
    "$SETUP/pot14_final.ptau" \
    "$SETUP/password_policy_0000.zkey"
echo ""

# Step 6: Contribute to Phase 2 and export verification key
echo "[SETUP] Step 6/6: Phase 2 contribution and export verification key..."
snarkjs zkey contribute \
    "$SETUP/password_policy_0000.zkey" \
    "$SETUP/circuit_final.zkey" \
    --name="ZK Password Auth Circuit Key" \
    -e="$(date +%s%N)-$(hostname)-circuit-entropy"

snarkjs zkey export verificationkey \
    "$SETUP/circuit_final.zkey" \
    "$SETUP/verification_key.json"

echo ""
echo "[SETUP] ✓ Trusted setup complete!"
echo "[SETUP] ✓ Proving key:       $SETUP/circuit_final.zkey"
echo "[SETUP] ✓ Verification key:  $SETUP/verification_key.json"
echo "[SETUP] ✓ WASM witness gen:  $BUILD/password_policy_js/password_policy.wasm"
echo ""
echo "[SETUP] You can now run:"
echo "  node scripts/register.js"
echo "  node scripts/login.js"
echo "  node test/run_tests.js"
