/**
 * helpers.js
 * Shared utilities for ZK password authentication scripts.
 *
 * CISC 878 Advanced Cryptographic Techniques — Queen's University
 *
 * Provides:
 *   - Password encoding (string -> ASCII byte array, zero-padded to 32)
 *   - Salt generation
 *   - Input validation (non-ASCII detection)
 *   - File loading helpers for setup artifacts
 *   - Metrics recording
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

const MAX_PW_LEN = 32;

// ============================================================
// Password encoding
// ============================================================

/**
 * Encode a password string as an array of 32 ASCII byte values.
 * Zero-pads from position L to 31.
 *
 * @param {string} password
 * @returns {{ pwBytes: number[], L: number }}
 * @throws if password contains non-ASCII chars or exceeds 32 chars
 */
function encodePassword(password) {
    if (password.length > MAX_PW_LEN) {
        throw new Error(`Password too long: max ${MAX_PW_LEN} characters (got ${password.length})`);
    }

    const pwBytes = new Array(MAX_PW_LEN).fill(0);
    for (let i = 0; i < password.length; i++) {
        const code = password.charCodeAt(i);
        if (code > 127) {
            throw new Error(
                `Password contains non-ASCII character at position ${i}: '${password[i]}' (code ${code}). ` +
                `Only ASCII characters (codes 0-127) are supported.`
            );
        }
        pwBytes[i] = code;
    }

    return { pwBytes, L: password.length };
}

// ============================================================
// Salt generation
// ============================================================

/**
 * Generate a cryptographically random salt as a BigInt.
 * Uses 31 bytes (248 bits) to stay safely within the BN128 scalar field.
 *
 * @returns {BigInt}
 */
function generateSalt() {
    // 31 bytes = 248 bits, safely below BN128 field size (~254 bits)
    const buf = crypto.randomBytes(31);
    return BigInt('0x' + buf.toString('hex'));
}

// ============================================================
// Path helpers
// ============================================================

const ROOT = path.resolve(__dirname, '..');

const PATHS = {
    verificationKey : path.join(ROOT, 'setup', 'verification_key.json'),
    finalZKey       : path.join(ROOT, 'setup', 'circuit_final.zkey'),
    wasmFile        : path.join(ROOT, 'build', 'password_policy_js', 'password_policy.wasm'),
    usersDb         : path.join(ROOT, 'db', 'users.json'),
    proofFile       : path.join(ROOT, 'proofs', 'proof.json'),
    publicFile      : path.join(ROOT, 'proofs', 'public.json'),
    metricsFile     : path.join(ROOT, 'proofs', 'metrics.json'),
};

/**
 * Load and parse a JSON file, with a helpful error if missing.
 * @param {string} filePath
 * @param {string} hint - human-readable description for error message
 * @returns {any}
 */
function loadJson(filePath, hint) {
    if (!fs.existsSync(filePath)) {
        throw new Error(
            `Missing required file: ${filePath}\n` +
            (hint ? `Hint: ${hint}` : '')
        );
    }
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

/**
 * Save a JSON file, creating parent directories if needed.
 * @param {string} filePath
 * @param {any} data
 */
function saveJson(filePath, data) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

// ============================================================
// User database helpers
// ============================================================

/**
 * Load the users database.
 * @returns {{ [username: string]: { salt: string, h: string } }}
 */
function loadUsers() {
    if (!fs.existsSync(PATHS.usersDb)) {
        return {};
    }
    return loadJson(PATHS.usersDb, 'Run register.js to create the first user.');
}

/**
 * Save the users database.
 * @param {{ [username: string]: { salt: string, h: string } }} users
 */
function saveUsers(users) {
    saveJson(PATHS.usersDb, users);
}

// ============================================================
// Metrics
// ============================================================

/**
 * Record performance metrics for the last proof operation.
 * @param {{ provingTimeMs: number, verifyTimeMs: number, proofSizeBytes: number }} metrics
 */
function saveMetrics(metrics) {
    saveJson(PATHS.metricsFile, {
        ...metrics,
        timestamp: new Date().toISOString(),
    });
}

/**
 * Format and print proof metrics to stdout.
 * @param {{ provingTimeMs: number, verifyTimeMs: number, proofSizeBytes: number }} metrics
 */
function printMetrics(metrics) {
    console.log(
        `[ZK-AUTH] Proof size: ${metrics.proofSizeBytes} bytes | ` +
        `Proving time: ${metrics.provingTimeMs}ms | ` +
        `Verification time: ${metrics.verifyTimeMs}ms`
    );
}

// ============================================================
// Setup file validation
// ============================================================

/**
 * Check that all required setup/build files exist before running.
 * Throws with a clear message if any are missing.
 */
function checkSetupFiles() {
    const required = [
        { path: PATHS.verificationKey, hint: 'Run scripts/setup.sh (or setup.ps1 on Windows) to generate keys.' },
        { path: PATHS.finalZKey,       hint: 'Run scripts/setup.sh (or setup.ps1 on Windows) to generate keys.' },
        { path: PATHS.wasmFile,        hint: 'Run: circom circuits/password_policy.circom --r1cs --wasm --sym -o build/' },
    ];

    for (const { path: p, hint } of required) {
        if (!fs.existsSync(p)) {
            throw new Error(`Setup incomplete. Missing: ${p}\nHint: ${hint}`);
        }
    }
}

module.exports = {
    encodePassword,
    generateSalt,
    loadJson,
    saveJson,
    loadUsers,
    saveUsers,
    saveMetrics,
    printMetrics,
    checkSetupFiles,
    PATHS,
    MAX_PW_LEN,
};
