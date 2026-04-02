This directory contains trusted setup artifacts.

Files committed to git:
  verification_key.json   — Public verifier key (committed, required for verification)

Files NOT committed (gitignored — too large, 50-200MB):
  pot14_0000.ptau         — Phase 1 initial powers of tau
  pot14_0001.ptau         — Phase 1 after contribution
  pot14_final.ptau        — Phase 1 finalized
  password_policy_0000.zkey  — Phase 2 initial zkey
  circuit_final.zkey      — Final proving key (used by prover)

Run scripts/setup.sh (Linux/macOS) or scripts/setup.ps1 (Windows)
to regenerate all setup files from scratch.

SECURITY NOTE:
  This is a single-party trusted setup for proof-of-concept purposes.
  In production, a multi-party computation (MPC) ceremony would be used
  to ensure no single party retains the toxic waste (tau secret).
