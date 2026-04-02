#!/usr/bin/env node
/**
 * register.js — ZK Password Registration CLI
 * CISC 878 Advanced Cryptographic Techniques — Queen's University
 *
 * Registration flow:
 *   1. User enters username + password (locally — never transmitted)
 *   2. Generate random salt
 *   3. Compute h = Poseidon(pw, salt) outside circuit (for public input)
 *   4. Generate witness: circuit enforces policy + hash commitment
 *   5. Groth16 prove: produces proof pi
 *   6. Groth16 verify: server checks proof
 *   7. Store (username, salt, h) in users.json
 *
 * SECURITY NOTE:
 * The password is used locally as a private witness to the ZK circuit.
 * It is never transmitted over any network connection.
 * Only the proof pi and public inputs (salt, h) are sent to the server.
 * The server cannot reconstruct the password from these values.
 *
 * In a production PAKE-based system:
 * - The commitment h would be used to derive a PAKE verifier
 * - Future logins would use PAKE protocol (e.g., OPAQUE) for key exchange
 * - This ZK proof serves as the policy enforcement building block
 */

'use strict';

const path        = require('path');
const fs          = require('fs');
const readline    = require('readline');
const snarkjs     = require('snarkjs');

const {
    encodePassword,
    generateSalt,
    loadUsers,
    saveUsers,
    saveMetrics,
    printMetrics,
    checkSetupFiles,
    PATHS,
} = require('./helpers');

const { poseidonCommitment } = require('./poseidon_hash');

// ============================================================
// Prompt helper
// ============================================================
function prompt(question, hidden = false) {
    return new Promise((resolve) => {
        const rl = readline.createInterface({
            input: process.stdin,
            output: hidden ? null : process.stdout,
            terminal: hidden,
        });

        if (hidden) {
            process.stdout.write(question);
            process.stdin.setRawMode(true);
            process.stdin.resume();
            process.stdin.setEncoding('utf8');

            let password = '';
            process.stdin.on('data', function onData(ch) {
                if (ch === '\r' || ch === '\n') {
                    process.stdin.setRawMode(false);
                    process.stdin.pause();
                    process.stdin.removeListener('data', onData);
                    process.stdout.write('\n');
                    resolve(password);
                } else if (ch === '\u0003') {
                    process.exit();
                } else if (ch === '\u007f' || ch === '\b') {
                    password = password.slice(0, -1);
                } else {
                    password += ch;
                }
            });
        } else {
            rl.question(question, (answer) => {
                rl.close();
                resolve(answer);
            });
        }
    });
}

// ============================================================
// Main registration logic
// ============================================================
async function register() {
    console.log('[ZK-AUTH] Zero-Knowledge Password Registration');
    console.log('[ZK-AUTH] =====================================');

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

    // Check if user already exists
    const users = loadUsers();
    if (users[username]) {
        console.error(`[ZK-AUTH] ✗ User '${username}' already exists.`);
        process.exit(1);
    }

    const password = await prompt('Enter password: ');
    if (!password || password.trim().length === 0) {
        console.error('[ZK-AUTH] ✗ Password cannot be empty.');
        process.exit(1);
    }

    // Encode password to byte array
    let pwBytes, L;
    try {
        ({ pwBytes, L } = encodePassword(password));
    } catch (err) {
        console.error(`[ZK-AUTH] ✗ ${err.message}`);
        console.error('[ZK-AUTH] ✗ Registration rejected.');
        process.exit(1);
    }

    // Step 1: Generate salt
    console.log('[ZK-AUTH] Generating salt...');
    const salt = generateSalt();

    // Step 2: Compute Poseidon commitment outside circuit
    console.log('[ZK-AUTH] Computing Poseidon commitment...');
    const h = await poseidonCommitment(pwBytes, salt);

    // Step 3: Prepare circuit inputs
    const circuitInputs = {
        pw:   pwBytes.map(String),
        L:    String(L),
        salt: salt.toString(),
        h:    h.toString(),
    };

    // Step 4: Generate witness
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
        // Witness generation failure = constraint violation = policy not met
        console.error('[ZK-AUTH] ✗ Witness generation failed: password does not satisfy policy constraints.');
        console.error('[ZK-AUTH] ✗ Registration rejected.');
        if (process.env.ZK_DEBUG) console.error(err);
        process.exit(1);
    }

    // Step 5: Generate Groth16 proof
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

    // Step 6: Verify proof (server-side simulation)
    console.log('[ZK-AUTH] Verifying proof...');
    const vKey = JSON.parse(fs.readFileSync(PATHS.verificationKey, 'utf8'));
    const tVerifyStart = Date.now();
    const isValid = await snarkjs.groth16.verify(vKey, publicSignals, proof);
    const verifyTimeMs = Date.now() - tVerifyStart;

    if (!isValid) {
        console.error('[ZK-AUTH] ✗ Proof verification failed. Registration rejected.');
        process.exit(1);
    }

    // Save proof artifacts
    fs.mkdirSync(path.dirname(PATHS.proofFile), { recursive: true });
    fs.writeFileSync(PATHS.proofFile,  JSON.stringify(proof, null, 2));
    fs.writeFileSync(PATHS.publicFile, JSON.stringify(publicSignals, null, 2));
    const proofSizeBytes = fs.statSync(PATHS.proofFile).size;

    // Step 7: Store user (simulate server storing commitment)
    users[username] = {
        salt: salt.toString(),
        h:    h.toString(),
    };
    saveUsers(users);

    // Metrics
    const metrics = { provingTimeMs, verifyTimeMs, proofSizeBytes };
    saveMetrics(metrics);

    console.log('[ZK-AUTH] ✓ Password policy verified in zero knowledge.');
    console.log(`[ZK-AUTH] ✓ Registration successful. User '${username}' stored.`);
    printMetrics(metrics);
}

register().catch((err) => {
    console.error('[ZK-AUTH] Unexpected error:', err.message);
    if (process.env.ZK_DEBUG) console.error(err);
    process.exit(1);
});
