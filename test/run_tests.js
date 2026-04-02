#!/usr/bin/env node
/**
 * run_tests.js — Automated test suite for zk-password-auth
 * CISC 878 Advanced Cryptographic Techniques — Queen's University
 *
 * Tests 7 scenarios covering the full policy and authentication flow.
 * Each test runs the full Groth16 pipeline (witness + prove + verify).
 *
 * Usage: node test/run_tests.js
 */

'use strict';

const fs      = require('fs');
const path    = require('path');
const snarkjs = require('snarkjs');

const { encodePassword, generateSalt, loadJson, saveJson, checkSetupFiles, PATHS } = require('../scripts/helpers');
const { poseidonCommitment } = require('../scripts/poseidon_hash');

// ============================================================
// Test infrastructure
// ============================================================

let passed = 0;
let failed = 0;
const results = [];

function pad(str, len) {
    return str + '.'.repeat(Math.max(1, len - str.length));
}

async function runTest(label, fn) {
    try {
        const result = await fn();
        if (result.pass) {
            passed++;
            results.push(`[TEST ${results.length + 1}] ${pad(label, 45)} PASS \u2713`);
        } else {
            failed++;
            results.push(`[TEST ${results.length + 1}] ${pad(label, 45)} FAIL \u2717  (${result.reason})`);
        }
    } catch (err) {
        failed++;
        results.push(`[TEST ${results.length + 1}] ${pad(label, 45)} FAIL \u2717  (${err.message})`);
    }
}

// ============================================================
// Core ZK helper — attempt witness + prove + verify
// ============================================================

async function tryProve(pwBytes, L, salt, h) {
    const inputs = {
        pw:   pwBytes.map(String),
        L:    String(L),
        salt: salt.toString(),
        h:    h.toString(),
    };

    let proof, publicSignals;
    try {
        ({ proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, PATHS.wasmFile, PATHS.finalZKey));
    } catch (_) {
        return { success: false, stage: 'witness' };
    }

    const vKey = loadJson(PATHS.verificationKey, 'Run setup to generate verification key');
    const valid = await snarkjs.groth16.verify(vKey, publicSignals, proof);
    return { success: valid, stage: 'verify', proof, publicSignals };
}

async function tryCommitAndProve(password) {
    const { pwBytes, L } = encodePassword(password);
    const salt = generateSalt();
    const h    = await poseidonCommitment(pwBytes, salt);
    return tryProve(pwBytes, L, salt, h);
}

// ============================================================
// Tests
// ============================================================

async function main() {
    console.log('[ZK-AUTH TEST] Running automated test suite...');
    console.log('[ZK-AUTH TEST] ================================');
    console.log('[ZK-AUTH TEST] Set ZK_DEBUG=1 for verbose error output.');
    console.log('');

    // Check setup files first
    try {
        checkSetupFiles();
    } catch (err) {
        console.error(`[ZK-AUTH TEST] Cannot run tests: ${err.message}`);
        process.exit(1);
    }

    // Clean up any leftover test users
    const testUsers = ['__test_user_valid__', '__test_user_login__'];
    const usersPath = PATHS.usersDb;
    let users = {};
    if (fs.existsSync(usersPath)) {
        users = JSON.parse(fs.readFileSync(usersPath, 'utf8'));
        for (const u of testUsers) delete users[u];
        fs.writeFileSync(usersPath, JSON.stringify(users, null, 2));
    }

    // ----------------------------------------------------------
    // TEST 1: Valid password — should register successfully
    // 'Hello1!World2' — 13 chars, has digit, has special char
    // ----------------------------------------------------------
    await runTest('Valid password registration', async () => {
        const result = await tryCommitAndProve('Hello1!World2');
        return result.success ? { pass: true } : { pass: false, reason: `failed at ${result.stage}` };
    });

    // ----------------------------------------------------------
    // TEST 2: Too short — 'Hi1!' is only 4 chars, < 12 minimum
    // Expected: witness generation fails (L >= 12 constraint violated)
    // ----------------------------------------------------------
    await runTest('Too short password rejected', async () => {
        const result = await tryCommitAndProve('Hi1!');
        return !result.success && result.stage === 'witness'
            ? { pass: true }
            : { pass: false, reason: `expected witness failure, got: success=${result.success} stage=${result.stage}` };
    });

    // ----------------------------------------------------------
    // TEST 3: No digit — 'HelloWorld!!' has special chars but no digit
    // Expected: witness generation fails (digitSum * inv_digit = 1 violated)
    // ----------------------------------------------------------
    await runTest('No digit rejected', async () => {
        const result = await tryCommitAndProve('HelloWorld!!');
        return !result.success && result.stage === 'witness'
            ? { pass: true }
            : { pass: false, reason: `expected witness failure, got: success=${result.success} stage=${result.stage}` };
    });

    // ----------------------------------------------------------
    // TEST 4: No special character — 'HelloWorld12' has digits but no special
    // Expected: witness generation fails (specialSum * inv_special = 1 violated)
    // ----------------------------------------------------------
    await runTest('No special character rejected', async () => {
        const result = await tryCommitAndProve('HelloWorld12');
        return !result.success && result.stage === 'witness'
            ? { pass: true }
            : { pass: false, reason: `expected witness failure, got: success=${result.success} stage=${result.stage}` };
    });

    // ----------------------------------------------------------
    // TEST 5: Valid register then correct login
    // Register a user, then authenticate with correct password
    // ----------------------------------------------------------
    await runTest('Correct password login succeeds', async () => {
        const pw = 'SecureP@ss99!';
        const { pwBytes, L } = encodePassword(pw);
        const salt = generateSalt();
        const h    = await poseidonCommitment(pwBytes, salt);

        // Register
        const regResult = await tryProve(pwBytes, L, salt, h);
        if (!regResult.success) return { pass: false, reason: 'registration failed' };

        // Store in users.json
        const dbUsers = fs.existsSync(usersPath)
            ? JSON.parse(fs.readFileSync(usersPath, 'utf8'))
            : {};
        dbUsers['__test_user_login__'] = { salt: salt.toString(), h: h.toString() };
        fs.writeFileSync(usersPath, JSON.stringify(dbUsers, null, 2));

        // Login with same password
        const loginResult = await tryProve(pwBytes, L, salt, h);
        return loginResult.success
            ? { pass: true }
            : { pass: false, reason: `login failed at ${loginResult.stage}` };
    });

    // ----------------------------------------------------------
    // TEST 6: Valid register then wrong password login
    // The commitment will not match, so pre-check catches it.
    // Even if attempted: witness generation fails (hash constraint violated)
    // ----------------------------------------------------------
    await runTest('Wrong password login rejected', async () => {
        // Use the user registered in TEST 5
        const dbUsers = fs.existsSync(usersPath)
            ? JSON.parse(fs.readFileSync(usersPath, 'utf8'))
            : {};
        if (!dbUsers['__test_user_login__']) {
            return { pass: false, reason: 'test user from TEST 5 not found' };
        }

        const salt     = BigInt(dbUsers['__test_user_login__'].salt);
        const storedH  = BigInt(dbUsers['__test_user_login__'].h);

        // Wrong password
        const wrongPw = 'WrongP@ss99!';
        const { pwBytes, L } = encodePassword(wrongPw);
        const computedH = await poseidonCommitment(pwBytes, salt);

        // Commitment mismatch — the circuit would fail too
        if (computedH === storedH) {
            return { pass: false, reason: 'hash collision — wrong password produced same commitment (extremely unlikely)' };
        }

        // Try proving with mismatched h: circuit constraint posHash.out === h will fail
        const result = await tryProve(pwBytes, L, salt, storedH);
        return !result.success
            ? { pass: true }
            : { pass: false, reason: 'expected failure, but proof verified with wrong password' };
    });

    // ----------------------------------------------------------
    // TEST 7: Login with unknown username
    // ----------------------------------------------------------
    await runTest('Unknown username rejected', async () => {
        const dbUsers = fs.existsSync(usersPath)
            ? JSON.parse(fs.readFileSync(usersPath, 'utf8'))
            : {};
        const unknownUser = '__nonexistent_user_xyzabc__';
        return !dbUsers[unknownUser]
            ? { pass: true }
            : { pass: false, reason: 'user unexpectedly found in database' };
    });

    // ----------------------------------------------------------
    // Clean up test users
    // ----------------------------------------------------------
    if (fs.existsSync(usersPath)) {
        const dbUsers = JSON.parse(fs.readFileSync(usersPath, 'utf8'));
        for (const u of testUsers) delete dbUsers[u];
        fs.writeFileSync(usersPath, JSON.stringify(dbUsers, null, 2));
    }

    // ----------------------------------------------------------
    // Print results
    // ----------------------------------------------------------
    console.log('');
    for (const r of results) console.log(r);
    console.log('');
    console.log(`${passed}/${passed + failed} tests passed.`);
    if (failed > 0) {
        console.log(`\n${failed} test(s) failed.`);
        process.exit(1);
    }
}

main().catch((err) => {
    console.error('[ZK-AUTH TEST] Fatal error:', err.message);
    if (process.env.ZK_DEBUG) console.error(err);
    process.exit(1);
});
