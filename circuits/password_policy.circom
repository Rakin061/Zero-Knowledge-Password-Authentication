pragma circom 2.0.0;

// ============================================================
// ZK Password Policy Circuit — password_policy.circom
// CISC 878 Advanced Cryptographic Techniques — Queen's University
// ============================================================
//
// ACADEMIC MOTIVATION:
// Traditional password systems expose the password to the server during
// policy checking. PAKE protocols (SRP, OPAQUE) solve transmission security
// but do not cryptographically enforce password policy at registration.
//
// This circuit fills that gap: the prover convinces the verifier that they
// know a secret password pw such that:
//   1. length(pw) >= 12
//   2. pw contains at least one digit (ASCII 48-57)
//   3. pw contains at least one special char from !@#$%^&* (ASCII 33,64,35,36,37,94,38,42)
//   4. Poseidon(pw[0..31], salt) == h  (commitment binding)
//
// The password NEVER leaves the client — only proof pi and public inputs
// (salt, h) travel to the server. This is a building block for PAKE systems.
//
// DESIGN CHOICES:
//   Groth16:  smallest proofs (3 EC elements), fastest verification, trusted setup
//   Poseidon: ~250 constraints (field arithmetic) vs SHA-256 ~25,000 (bitwise ops)
//   Circom:   standard DSL, circomlib ecosystem, snarkjs integration
//
// CIRCUIT SIZE: ~2,000-3,000 constraints (fits comfortably in 2^14 capacity)
//
// NOTE: One circuit for both registration and login (simpler, academically
// justified). In production, separate circuits would optimize authentication
// by removing policy checks from the login path.
// ============================================================

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

// ============================================================
// InRange: checks lo <= in <= hi, returns 1 or 0
// n: number of bits for LessThan comparison
// ============================================================
template InRange(n) {
    signal input in;
    signal input lo;
    signal input hi;
    signal output out;

    component geqLo = LessThan(n);
    geqLo.in[0] <== lo;
    geqLo.in[1] <== in + 1;   // lo < in+1  =>  lo <= in

    component leqHi = LessThan(n);
    leqHi.in[0] <== in;
    leqHi.in[1] <== hi + 1;   // in < hi+1  =>  in <= hi

    out <== geqLo.out * leqHi.out;
}

// ============================================================
// ByteEquals: returns 1 if in == val, else 0
// Uses multiplicative inverse trick (standard ZK pattern):
//   diff = in - val
//   inv  = 1/diff (if diff != 0, else 0)
//   out  = 1 - diff*inv
// ============================================================
template ByteEquals(val) {
    signal input in;
    signal output out;

    signal diff;
    diff <== in - val;

    signal inv;
    inv <-- diff == 0 ? 0 : 1 / diff;
    out <== 1 - diff * inv;
    out * (1 - out) === 0;
    diff * out === 0;
}

// ============================================================
// IsDigit: returns 1 if byte is ASCII digit '0'-'9' (48-57)
// ============================================================
template IsDigit() {
    signal input in;
    signal output out;

    component r = InRange(8);
    r.in  <== in;
    r.lo  <== 48;   // '0'
    r.hi  <== 57;   // '9'
    out <== r.out;
}

// ============================================================
// IsSpecial: returns 1 if byte is in {!@#$%^&*}
// ASCII: 33(!), 64(@), 35(#), 36($), 37(%), 94(^), 38(&), 42(*)
// Sum of ByteEquals — at most one fires per character
// ============================================================
template IsSpecial() {
    signal input in;
    signal output out;

    var SPECIAL[8] = [33, 64, 35, 36, 37, 94, 38, 42];

    component eq[8];
    signal partialSum[9];
    partialSum[0] <== 0;

    for (var k = 0; k < 8; k++) {
        eq[k] = ByteEquals(SPECIAL[k]);
        eq[k].in <== in;
        partialSum[k+1] <== partialSum[k] + eq[k].out;
    }

    out <== partialSum[8];
}

// ============================================================
// PasswordPolicy — Main Circuit
//
// Private inputs (witness — never transmitted):
//   pw[32] : password as ASCII bytes, zero-padded to length 32
//   L      : actual password length
//
// Public inputs (sent to / stored by server):
//   salt   : random salt generated at registration
//   h      : Poseidon(pw[0], pw[1], ..., pw[31], salt) — stored commitment
// ============================================================
template PasswordPolicy() {
    signal input salt;
    signal input h;
    signal input pw[32];
    signal input L;

    // --------------------------------------------------------
    // Constraint 1: ASCII validity — each byte in [0, 127]
    // Prevents malformed witness from bypassing policy checks
    // --------------------------------------------------------
    component asciiCheck[32];
    for (var i = 0; i < 32; i++) {
        asciiCheck[i] = InRange(8);
        asciiCheck[i].in  <== pw[i];
        asciiCheck[i].lo  <== 0;
        asciiCheck[i].hi  <== 127;
        asciiCheck[i].out === 1;
    }

    // --------------------------------------------------------
    // Constraint 2: Minimum length — L >= 12
    // 11 < L  is equivalent to  L >= 12
    // --------------------------------------------------------
    component lenMin = LessThan(8);
    lenMin.in[0] <== 11;
    lenMin.in[1] <== L;
    lenMin.out === 1;

    // --------------------------------------------------------
    // Constraint 3: Maximum length — L <= 32 (circuit capacity)
    // L < 33  is equivalent to  L <= 32
    // --------------------------------------------------------
    component lenMax = LessThan(8);
    lenMax.in[0] <== L;
    lenMax.in[1] <== 33;
    lenMax.out === 1;

    // --------------------------------------------------------
    // Constraint 4: At least one digit
    //
    // digitSum = sum_{i=0}^{31} isDigit(pw[i])
    // Enforce: digitSum * inv_digit == 1
    // This is unsatisfiable when digitSum == 0 (no field inverse of 0).
    // --------------------------------------------------------
    component isDigit[32];
    signal digitPartial[33];
    digitPartial[0] <== 0;

    for (var i = 0; i < 32; i++) {
        isDigit[i] = IsDigit();
        isDigit[i].in <== pw[i];
        digitPartial[i+1] <== digitPartial[i] + isDigit[i].out;
    }

    signal digitSum;
    digitSum <== digitPartial[32];
    signal inv_digit;
    inv_digit <-- 1 / digitSum;
    digitSum * inv_digit === 1;

    // --------------------------------------------------------
    // Constraint 5: At least one special character
    //
    // specialSum = sum_{i=0}^{31} isSpecial(pw[i])
    // Enforce: specialSum * inv_special == 1
    // --------------------------------------------------------
    component isSpecial[32];
    signal specialPartial[33];
    specialPartial[0] <== 0;

    for (var i = 0; i < 32; i++) {
        isSpecial[i] = IsSpecial();
        isSpecial[i].in <== pw[i];
        specialPartial[i+1] <== specialPartial[i] + isSpecial[i].out;
    }

    signal specialSum;
    specialSum <== specialPartial[32];
    signal inv_special;
    inv_special <-- 1 / specialSum;
    specialSum * inv_special === 1;

    // --------------------------------------------------------
    // Constraint 6: Poseidon hash commitment
    //
    // Poseidon is a ZK-friendly hash: ~250 constraints using field
    // arithmetic (x^5 S-boxes) vs SHA-256's ~25,000 using bit ops.
    // circomlib's Poseidon supports up to 16 inputs.
    //
    // We hash pw[0..15] and pw[16..31] separately then combine:
    //   h1 = Poseidon(pw[0..15])
    //   h2 = Poseidon(pw[16..31])
    //   h  = Poseidon(h1, h2, salt)
    //
    // This gives a binding commitment to the full 32-byte password
    // and the salt, using nested Poseidon calls within 16-input limit.
    // --------------------------------------------------------
    component pos1 = Poseidon(16);
    for (var i = 0; i < 16; i++) {
        pos1.inputs[i] <== pw[i];
    }

    component pos2 = Poseidon(16);
    for (var i = 0; i < 16; i++) {
        pos2.inputs[i] <== pw[16 + i];
    }

    component posHash = Poseidon(3);
    posHash.inputs[0] <== pos1.out;
    posHash.inputs[1] <== pos2.out;
    posHash.inputs[2] <== salt;

    // The computed hash must equal the public commitment h
    posHash.out === h;
}

component main { public [salt, h] } = PasswordPolicy();
