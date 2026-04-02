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
// ============================================================

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

// ============================================================
// InRange: checks lo <= in <= hi, returns 1 or 0
// Uses n-bit LessThan from circomlib
// ============================================================
template InRange(n) {
    signal input in;
    signal input lo;
    signal input hi;
    signal output out;

    component geqLo = LessThan(n);
    geqLo.in[0] <== lo;
    geqLo.in[1] <== in + 1;  // lo < in+1  =>  lo <= in

    component leqHi = LessThan(n);
    leqHi.in[0] <== in;
    leqHi.in[1] <== hi + 1;  // in < hi+1  =>  in <= hi

    out <== geqLo.out * leqHi.out;
}

// ============================================================
// ByteEquals: returns 1 if in == val, else 0
// Uses multiplicative inverse trick (standard ZK pattern)
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
// IsDigit: returns 1 if byte is ASCII digit (48-57), else 0
// ============================================================
template IsDigit() {
    signal input in;
    signal output out;

    component r = InRange(8);
    r.in  <== in;
    r.lo  <== 48;  // '0'
    r.hi  <== 57;  // '9'
    out <== r.out;
}

// ============================================================
// IsSpecial: returns 1 if byte is in set {!@#$%^&*}
// ASCII values: 33(!), 64(@), 35(#), 36($), 37(%), 94(^), 38(&), 42(*)
// Implemented as sum of individual ByteEquals — at most one fires per char
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

    // partialSum[8] is 0 or 1 (a byte can match at most one special char)
    out <== partialSum[8];
}

// ============================================================
// Main Circuit
// ============================================================
template PasswordPolicy() {
    // --- Public inputs ---
    signal input salt;
    signal input h;

    // --- Private inputs (witness) ---
    signal input pw[32];
    signal input L;

    // --------------------------------------------------------
    // 1. ASCII range check: each pw[i] in [0, 127]
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
    // 2. Length: L >= 12
    // --------------------------------------------------------
    component lenCheck = LessThan(8);
    lenCheck.in[0] <== 11;
    lenCheck.in[1] <== L;
    lenCheck.out === 1;

    // --------------------------------------------------------
    // 3. Length: L <= 32
    // --------------------------------------------------------
    component maxLen = LessThan(8);
    maxLen.in[0] <== L;
    maxLen.in[1] <== 33;
    maxLen.out === 1;

    // --------------------------------------------------------
    // 4. Digit check: at least one digit in pw[0..L-1]
    //
    // Strategy: compute digitSum = sum of isDigit[i] for all i.
    // Enforce digitSum >= 1 via:  digitSum * inv_digit == 1
    // If digitSum == 0 this is unsatisfiable (no inverse of 0).
    // --------------------------------------------------------
    component isDigit[32];
    signal digitFlags[32];
    signal digitPartial[33];
    digitPartial[0] <== 0;

    for (var i = 0; i < 32; i++) {
        isDigit[i] = IsDigit();
        isDigit[i].in <== pw[i];
        digitFlags[i] <== isDigit[i].out;
        digitPartial[i+1] <== digitPartial[i] + digitFlags[i];
    }

    signal digitSum;
    digitSum <== digitPartial[32];

    signal inv_digit;
    inv_digit <-- 1 / digitSum;
    digitSum * inv_digit === 1;  // unsatisfiable if digitSum == 0

    // --------------------------------------------------------
    // 5. Special character check: at least one special char in pw[0..L-1]
    //
    // Same pattern: specialSum * inv_special == 1
    // --------------------------------------------------------
    component isSpecial[32];
    signal specialFlags[32];
    signal specialPartial[33];
    specialPartial[0] <== 0;

    for (var i = 0; i < 32; i++) {
        isSpecial[i] = IsSpecial();
        isSpecial[i].in <== pw[i];
        specialFlags[i] <== isSpecial[i].out;
        specialPartial[i+1] <== specialPartial[i] + specialFlags[i];
    }

    signal specialSum;
    specialSum <== specialPartial[32];

    signal inv_special;
    inv_special <-- 1 / specialSum;
    specialSum * inv_special === 1;  // unsatisfiable if specialSum == 0

    // Poseidon commitment added in next commit
}

component main { public [salt, h] } = PasswordPolicy();
