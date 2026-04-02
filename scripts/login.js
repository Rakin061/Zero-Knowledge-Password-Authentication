#!/usr/bin/env node
/**
 * login.js — ZK Password Authentication CLI
 * CISC 878 Advanced Cryptographic Techniques — Queen's University
 *
 * Authentication flow:
 *   1. User enters username + password (locally — never transmitted)
 *   2. Server provides: salt + h (stored commitment) for the username
 *   3. Client generates witness: circuit enforces Poseidon(pw, salt) == h
 *      AND policy constraints (same circuit as registration)
 *   4. Groth16 prove: produces proof pi
 *   5. Groth16 verify: server checks proof against stored h
 *   6. Login succeeds if and only if proof verifies
 *
 * SECURITY NOTE:
 * The password is used locally as a private witness to the ZK circuit.
 * It is never transmitted over any network connection.
 * Only the proof pi and public inputs (salt, h) are sent to the server.
 * The server cannot reconstruct the password from these values.
 *
 * In a production PAKE-based system:
 * - The commitment h would be used to derive a PAKE verifier
 * - This ZK proof serves as the policy enforcement building block
 * - Full key exchange would happen via OPAQUE or SRP after verification
 */

'use strict';

const fs       = require('fs');
const readline = require('readline');
const snarkjs  = require('snarkjs');

const {
    encodePassword,
    loadUsers,
    saveMetrics,
    printMetrics,
    checkSetupFiles,
    PATHS,
} = require('./helpers');

const { poseidonCommitment } = require('./poseidon_hash');

// ============================================================
// Prompt helper (shared pattern with register.js)
// ============================================================
function prompt(question) {
    return new Promise((resolve) => {
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        rl.question(question, (answer) => {
            rl.close();
            resolve(answer);
        });
    });
}

// ============================================================
// Main authentication logic
// ============================================================
async function login() {
    console.log('[ZK-AUTH] Zero-Knowledge Password Authentication');
    console.log('[ZK-AUTH] ========================================');

    // Validate setup files exist
    try {
        checkSetupFiles();
    } catch (err) {
        console.error(`[ZK-AUTH] ✗ ${err.message}`);
        process.exit(1);
    }

    const username = (await prompt('Enter username: ')).trim();
    if (!username) {
        console.error('[ZK-AUTH] ✗ Username cannot be empty.');
        process.exit(1);
    }

    // Simulate server: look up stored commitment
    const users = loadUsers();
    if (!users[username]) {
        console.error(`[ZK-AUTH] ✗ User '${username}' not found.`);
        process.exit(1);
    }

    console.log(`[ZK-AUTH] Loading commitment for user '${username}'...`);
    const salt = BigInt(users[username].salt);
    const storedH = BigInt(users[username].h);

    const password = await prompt('Enter password: ');
    if (!password) {
        console.error('[ZK-AUTH] ✗ Password cannot be empty.');
        console.error('[ZK-AUTH] ✗ Authentication failed.');
        process.exit(1);
    }

    // Encode password locally
    let pwBytes, L;
    try {
        ({ pwBytes, L } = encodePassword(password));
    } catch (err) {
        console.error(`[ZK-AUTH] ✗ ${err.message}`);
        console.error('[ZK-AUTH] ✗ Authentication failed.');
        process.exit(1);
    }

    // Verify that the locally computed commitment matches the stored one.
    // This is a pre-check that avoids attempting witness generation when
    // the password is clearly wrong, giving a clear error message.
    // (The circuit would catch it anyway, but the error would be less clear.)
    const computedH = await poseidonCommitment(pwBytes, salt);
    if (computedH !== storedH) {
        console.error('[ZK-AUTH] ✗ Witness generation failed: password does not match stored commitment.');
        console.error('[ZK-AUTH] ✗ Authentication failed.');
        process.exit(1);
    }

    // Prepare circuit inputs (same as registration — one circuit for both)
    const circuitInputs = {
        pw:   pwBytes.map(String),
        L:    String(L),
        salt: salt.toString(),
        h:    storedH.toString(),
    };

    // Generate witness
    console.log('[ZK-AUTH] Generating witness...');
    let witness;
    try {
        const { wtns } = await snarkjs.wtns.calculate(
            circuitInputs,
            PATHS.wasmFile,
            { type: 'mem' }
        );
        witness = wtns;
    } catch (err) {
        console.error('[ZK-AUTH] ✗ Witness generation failed: password does not match stored commitment.');
        console.error('[ZK-AUTH] ✗ Authentication failed.');
        if (process.env.ZK_DEBUG) console.error(err);
        process.exit(1);
    }

    // Generate Groth16 proof
    console.log('[ZK-AUTH] Generating Groth16 proof...');
    const tProveStart = Date.now();
    let proof, publicSignals;
    try {
        ({ proof, publicSignals } = await snarkjs.groth16.prove(PATHS.finalZKey, witness));
    } catch (err) {
        console.error('[ZK-AUTH] ✗ Proof generation failed.');
        if (process.env.ZK_DEBUG) console.error(err);
        process.exit(1);
    }
    const provingTimeMs = Date.now() - tProveStart;

    // Verify proof (server-side simulation)
    console.log('[ZK-AUTH] Verifying proof...');
    const vKey = JSON.parse(fs.readFileSync(PATHS.verificationKey, 'utf8'));
    const tVerifyStart = Date.now();
    const isValid = await snarkjs.groth16.verify(vKey, publicSignals, proof);
    const verifyTimeMs = Date.now() - tVerifyStart;

    if (!isValid) {
        console.error('[ZK-AUTH] ✗ Proof verification failed.');
        console.error('[ZK-AUTH] ✗ Authentication failed.');
        process.exit(1);
    }

    // Save proof artifacts and metrics
    fs.mkdirSync(require('path').dirname(PATHS.proofFile), { recursive: true });
    fs.writeFileSync(PATHS.proofFile,  JSON.stringify(proof, null, 2));
    fs.writeFileSync(PATHS.publicFile, JSON.stringify(publicSignals, null, 2));
    const proofSizeBytes = fs.statSync(PATHS.proofFile).size;

    const metrics = { provingTimeMs, verifyTimeMs, proofSizeBytes };
    saveMetrics(metrics);

    console.log(`[ZK-AUTH] ✓ Authentication successful. Welcome, ${username}.`);
    printMetrics(metrics);
}

login().catch((err) => {
    console.error('[ZK-AUTH] Unexpected error:', err.message);
    if (process.env.ZK_DEBUG) console.error(err);
    process.exit(1);
});
