# =============================================================
# setup.ps1 — One-time trusted setup for zk-password-auth (Windows)
# CISC 878 Advanced Cryptographic Techniques — Queen's University
#
# Run this ONCE before using register.js or login.js.
# Open PowerShell and run:
#   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
#   .\scripts\setup.ps1
#
# Prerequisites:
#   - Node.js LTS: https://nodejs.org/
#   - Circom: https://docs.circom.io/getting-started/installation/
#   - snarkjs: npm install -g snarkjs
# =============================================================

$ErrorActionPreference = "Stop"

$Root    = Split-Path -Parent $PSScriptRoot
$Build   = Join-Path $Root "build"
$Setup   = Join-Path $Root "setup"
$Circuit = Join-Path $Root "circuits\password_policy.circom"

Write-Host "[SETUP] ZK Password Auth - Trusted Setup Pipeline" -ForegroundColor Cyan
Write-Host "[SETUP] ==========================================" -ForegroundColor Cyan
Write-Host ""

# Check prerequisites
foreach ($cmd in @("circom", "snarkjs", "node")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Error "[SETUP] ERROR: '$cmd' not found. Please install it first."
        exit 1
    }
}

# Install npm dependencies
Write-Host "[SETUP] Installing npm dependencies..." -ForegroundColor Yellow
Set-Location $Root
npm install
Write-Host ""

# Step 1: Compile circuit
Write-Host "[SETUP] Step 1/6: Compiling circuit..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $Build | Out-Null
circom $Circuit --r1cs --wasm --sym -o $Build
Write-Host "[SETUP] Circuit compiled." -ForegroundColor Green
Write-Host ""

# Step 2: Powers of Tau Phase 1
Write-Host "[SETUP] Step 2/6: Powers of Tau Phase 1 (bn128 14)..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $Setup | Out-Null
snarkjs powersoftau new bn128 14 "$Setup\pot14_0000.ptau" -v
Write-Host ""

# Step 3: Phase 1 contribution
Write-Host "[SETUP] Step 3/6: Phase 1 contribution..." -ForegroundColor Yellow
$entropy1 = [System.Guid]::NewGuid().ToString() + (Get-Date -Format "yyyyMMddHHmmss")
snarkjs powersoftau contribute "$Setup\pot14_0000.ptau" "$Setup\pot14_0001.ptau" --name="ZK Password Auth Setup" -e="$entropy1"
Write-Host ""

# Step 4: Prepare Phase 2
Write-Host "[SETUP] Step 4/6: Prepare Phase 2..." -ForegroundColor Yellow
snarkjs powersoftau prepare phase2 "$Setup\pot14_0001.ptau" "$Setup\pot14_final.ptau" -v
Write-Host ""

# Step 5: Circuit-specific zkey
Write-Host "[SETUP] Step 5/6: Circuit-specific zkey generation..." -ForegroundColor Yellow
snarkjs groth16 setup "$Build\password_policy.r1cs" "$Setup\pot14_final.ptau" "$Setup\password_policy_0000.zkey"
Write-Host ""

# Step 6: Phase 2 contribution + export verification key
Write-Host "[SETUP] Step 6/6: Phase 2 contribution and verification key export..." -ForegroundColor Yellow
$entropy2 = [System.Guid]::NewGuid().ToString() + (Get-Date -Format "yyyyMMddHHmmss")
snarkjs zkey contribute "$Setup\password_policy_0000.zkey" "$Setup\circuit_final.zkey" --name="ZK Password Auth Circuit Key" -e="$entropy2"
snarkjs zkey export verificationkey "$Setup\circuit_final.zkey" "$Setup\verification_key.json"

Write-Host ""
Write-Host "[SETUP] Trusted setup complete!" -ForegroundColor Green
Write-Host "[SETUP] Proving key:      $Setup\circuit_final.zkey" -ForegroundColor Green
Write-Host "[SETUP] Verification key: $Setup\verification_key.json" -ForegroundColor Green
Write-Host "[SETUP] WASM:             $Build\password_policy_js\password_policy.wasm" -ForegroundColor Green
Write-Host ""
Write-Host "You can now run:" -ForegroundColor Cyan
Write-Host "  node scripts\register.js"
Write-Host "  node scripts\login.js"
Write-Host "  node test\run_tests.js"
