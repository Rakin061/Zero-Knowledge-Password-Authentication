pragma circom 2.0.0;

// ============================================================
// ZK Password Policy Circuit
// CISC 878 Advanced Cryptographic Techniques — Queen's University
// ============================================================
//
// ACADEMIC MOTIVATION:
// Traditional password systems expose the password to the server during
// policy checking. PAKE protocols (SRP, OPAQUE) solve transmission security
// but do not cryptographically enforce password policy at registration.
//
// This circuit fills that gap: the prover convinces the verifier that they
// know a secret password that:
//   1. Satisfies the policy (length >= 12, has digit, has special char)
//   2. Correctly maps to a stored commitment: Poseidon(pw, salt) == h
//
// Without ever revealing the password to the server.
// This serves as a cryptographic building block for PAKE-based systems.
//
// ZK SCHEME: Groth16 (smallest proofs, fastest verification)
// HASH:      Poseidon (field-native, ~250 constraints vs SHA-256's ~25,000)
// LIBRARY:   circomlib (standard gadgets: comparators, IsZero, Poseidon)
// ============================================================

// Stub — full constraints added in subsequent commits
template PasswordPolicy() {
    // Public inputs
    signal input salt;
    signal input h;       // stored commitment = Poseidon(pw[0..31], salt)

    // Private inputs (witness — never leave the client)
    signal input pw[32];  // ASCII byte array, padded with zeros to fixed length 32
    signal input L;       // actual password length (private)

    // Outputs (none — circuit is a predicate)
}

component main { public [salt, h] } = PasswordPolicy();
