/**
 * poseidon_hash.js
 * Outside-circuit Poseidon hash helper using circomlibjs.
 *
 * Mirrors the nested Poseidon structure in password_policy.circom:
 *   h1 = Poseidon(pw[0..15])
 *   h2 = Poseidon(pw[16..31])
 *   h  = Poseidon(h1, h2, salt)
 *
 * Used to compute the public commitment h before witness generation,
 * and to verify the commitment externally.
 *
 * SECURITY NOTE:
 * The password bytes are processed locally — they are never written to
 * disk or transmitted. Only the resulting hash h (commitment) is shared.
 */

'use strict';

const { buildPoseidon } = require('circomlibjs');

let poseidonInstance = null;

/**
 * Lazily initialize the Poseidon hash function.
 * @returns {Promise<Function>} Poseidon hash function
 */
async function getPoseidon() {
    if (!poseidonInstance) {
        poseidonInstance = await buildPoseidon();
    }
    return poseidonInstance;
}

/**
 * Compute the nested Poseidon commitment matching the circuit.
 *
 * @param {number[]} pwBytes - Array of 32 ASCII byte values (zero-padded)
 * @param {BigInt}   salt    - Random salt value as BigInt
 * @returns {Promise<BigInt>} h — the commitment as BigInt
 */
async function poseidonCommitment(pwBytes, salt) {
    if (pwBytes.length !== 32) {
        throw new Error(`poseidonCommitment: expected 32 bytes, got ${pwBytes.length}`);
    }

    const poseidon = await getPoseidon();

    // Match circuit: h1 = Poseidon(pw[0..15])
    const h1 = poseidon(pwBytes.slice(0, 16));
    const h1F = poseidon.F.toObject(h1);

    // Match circuit: h2 = Poseidon(pw[16..31])
    const h2 = poseidon(pwBytes.slice(16, 32));
    const h2F = poseidon.F.toObject(h2);

    // Match circuit: h = Poseidon(h1, h2, salt)
    const hRaw = poseidon([h1F, h2F, salt]);
    const h = poseidon.F.toObject(hRaw);

    return h;
}

module.exports = { poseidonCommitment, getPoseidon };
