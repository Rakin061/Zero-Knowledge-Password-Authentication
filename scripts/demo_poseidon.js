/**
 * demo_poseidon.js — Real-time Poseidon hash demonstration
 * CISC 878 Advanced Cryptographic Techniques — Queen's University
 *
 * Usage: node scripts/demo_poseidon.js
 *
 * Shows the Poseidon commitment computation step by step,
 * matching exactly what happens inside the ZK circuit.
 */

'use strict';

const { buildPoseidon } = require('circomlibjs');
const crypto = require('crypto');

function pwToBytes(password) {
    const bytes = new Array(32).fill(0);
    for (let i = 0; i < Math.min(password.length, 32); i++) {
        bytes[i] = password.charCodeAt(i);
    }
    return bytes;
}

async function main() {
    const password = process.argv[2] || 'Hello1!World2';

    console.log('');
    console.log('╔══════════════════════════════════════════════════════════╗');
    console.log('║       Poseidon Hash Commitment — Step-by-Step Demo       ║');
    console.log('║       CISC 878  |  Zero-Knowledge Password Auth          ║');
    console.log('╚══════════════════════════════════════════════════════════╝');
    console.log('');

    // Step 1: Password encoding
    console.log(`  Password input : "${password}"`);
    console.log(`  Length         : ${password.length} characters`);

    const pwBytes = pwToBytes(password);
    console.log(`  ASCII bytes    : [${pwBytes.slice(0, password.length).join(', ')}]`);
    console.log(`  Padded to 32   : [${pwBytes.slice(0, password.length).join(', ')}, ${Array(32 - password.length).fill(0).join(', ')}]`);
    console.log('');

    // Step 2: Policy check (off-circuit preview)
    const hasDigit   = pwBytes.some(b => b >= 48 && b <= 57);
    const hasSpecial = pwBytes.some(b => [33,64,35,36,37,94,38,42].includes(b));
    console.log('  Policy checks (also enforced as circuit constraints):');
    console.log(`    Length >= 12  : ${password.length >= 12 ? '✓ PASS' : '✗ FAIL'} (length = ${password.length})`);
    console.log(`    Has digit     : ${hasDigit   ? '✓ PASS' : '✗ FAIL'}`);
    console.log(`    Has special   : ${hasSpecial ? '✓ PASS' : '✗ FAIL'}`);
    console.log('');

    // Step 3: Salt generation
    const saltBytes = crypto.randomBytes(31);
    const salt = BigInt('0x' + saltBytes.toString('hex'));
    console.log('  Salt (random, 248-bit):');
    console.log(`    ${salt}`);
    console.log('');

    // Step 4: Poseidon computation — mirrors the circuit exactly
    console.log('  Initializing Poseidon (BN128 field)...');
    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    console.log('  Poseidon initialized.');
    console.log('');

    // h1 = Poseidon(pw[0..15])  — matches circuit line 226-229
    const pw1 = pwBytes.slice(0, 16);
    const h1raw = poseidon(pw1);
    const h1 = F.toObject(h1raw);
    console.log('  h1 = Poseidon(pw[0..15])       ← circuit lines 226-229');
    console.log(`       ${h1}`);
    console.log('');

    // h2 = Poseidon(pw[16..31]) — matches circuit line 231-234
    const pw2 = pwBytes.slice(16, 32);
    const h2raw = poseidon(pw2);
    const h2 = F.toObject(h2raw);
    console.log('  h2 = Poseidon(pw[16..31])      ← circuit lines 231-234');
    console.log(`       ${h2}`);
    console.log('');

    // h = Poseidon(h1, h2, salt) — matches circuit line 236-239
    const hraw = poseidon([h1, h2, salt]);
    const h = F.toObject(hraw);
    console.log('  h  = Poseidon(h1, h2, salt)    ← circuit lines 236-239');
    console.log(`       ${h}`);
    console.log('');

    // What the server stores
    console.log('  ┌─────────────────────────────────────────────────────┐');
    console.log('  │  Server stores (public — no password):              │');
    console.log(`  │  salt = ${salt.toString().slice(0,48)}...  │`);
    console.log(`  │  h    = ${h.toString().slice(0,48)}...  │`);
    console.log('  └─────────────────────────────────────────────────────┘');
    console.log('');

    // Circuit binding constraint
    console.log('  Circuit constraint (line 242 of password_policy.circom):');
    console.log('    posHash.out === h');
    console.log('  → The ZK proof guarantees this holds WITHOUT revealing the password.');
    console.log('');

    // SHA-256 comparison
    const sha = crypto.createHash('sha256').update(password).digest('hex');
    console.log('  Comparison — SHA-256 of same password (NOT used in circuit):');
    console.log(`    ${sha}`);
    console.log('  → SHA-256 needs ~25,000 constraints in a ZK circuit.');
    console.log('    Poseidon needs ~250 constraints (100x fewer).');
    console.log('');
}

main().catch(err => {
    console.error('Error:', err.message);
    process.exit(1);
});
