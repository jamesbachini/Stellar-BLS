// soroban-data.js - Generate data for Soroban BLS contract
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Buffer } from "buffer";

const toHex = (u8) => {
  if (u8 instanceof Uint8Array || u8 instanceof Buffer) {
    return Buffer.from(u8).toString("hex");
  } else if (typeof u8.toHex === 'function') {
    return u8.toHex();
  } else {
    return u8.toString();
  }
};

// Generate N keypairs - use your existing ones for consistency
const N = 9;
const keypairs = [];

console.log("Generating BLS keypairs for Soroban...\n");

for (let i = 0; i < N; i++) {
  const sk = bls.utils.randomSecretKey();
  const pkPoint = bls.shortSignatures.getPublicKey(sk);
  
  // Get uncompressed public key (96 bytes) for Soroban
  let pkUncompressed;
  try {
    pkUncompressed = pkPoint.toBytes(false); // Try uncompressed
  } catch {
    // Fallback: convert hex to bytes (hex is typically uncompressed)
    const hexStr = pkPoint.toHex();
    pkUncompressed = Buffer.from(hexStr, 'hex');
  }
  
  keypairs.push({ sk, pkPoint, pkUncompressed });
}

// Display public keys in Soroban format (96 bytes uncompressed)
console.log("=== PUBLIC KEYS FOR SOROBAN INIT (96 bytes uncompressed) ===");

const pubkeyHexArray = keypairs.map((kp, i) => {
  const hex = toHex(kp.pkUncompressed);
  console.log(`Pubkey #${i + 1} (${kp.pkUncompressed.length}b): 0x${hex}`);
  return `"${hex}"`;
});

// DST for BLS signatures
const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
console.log(`--dst "${dst}"`);

// Message to sign - hash to 32 bytes as expected by contract
const messageText = "flip-the-flag";
const messageBytes = new TextEncoder().encode(messageText);
const messageHash = sha256(messageBytes); // 32-byte hash

console.log(`\n=== MESSAGE ===`);
console.log(`Original message: "${messageText}"`);
console.log(`Message hash (32b): 0x${toHex(messageHash)}`);

// Hash to curve for signing (this is what BLS signing expects)
const messageCurvePoint = bls.G1.hashToCurve(messageBytes);

// Generate signatures for specific signers
const signerIndices = [0, 3, 7]; // Signers 1, 4, and 8
console.log(`\n=== SIGNATURES ===`);
console.log(`Signing with signers: ${signerIndices.map(i => i + 1).join(", ")}\n`);

const signatures = signerIndices.map((idx, i) => {
  const { sk } = keypairs[idx];
  const sigPoint = bls.shortSignatures.sign(messageCurvePoint, sk);
  const sigCompressed = sigPoint.toBytes(); // 48 bytes compressed G2
  
  console.log(`Signer #${idx + 1} signature (${sigCompressed.length}b): 0x${toHex(sigCompressed)}`);
  return toHex(sigCompressed);
});

console.log(`
=== SOROBAN CONTRACT CALLS ===
soroban contract invoke \\
  --id YOUR_CONTRACT_ID \\
  --source YOUR_ACCOUNT \\
  -- init \\
  --pubkeys '[${pubkeyHexArray.join(", ")}]' \\
  --dst "${dst}"

soroban contract invoke \\
  --id YOUR_CONTRACT_ID \\
  --source YOUR_ACCOUNT \\
  -- authorize \\
  --message "${toHex(messageHash)}" \\
  --signer_indices '[${signerIndices.join(", ")}]' \\
  --sigs '[${signatures.map(s => `"${s}"`).join(", ")}]'

soroban contract invoke \\
  --id YOUR_CONTRACT_ID \\
  --source YOUR_ACCOUNT \\
  -- get_flag

=== SUMMARY ===
Public Keys: ${keypairs.length} keys, 96 bytes each (uncompressed G1)
Message Hash: ${messageHash.length} bytes
Signatures: ${signatures.length} signatures, 192 bytes each (uncompressed G2)
Threshold: 3 out of ${signatures.length} signatures required

Message hash: "${toHex(messageHash)}"
Signer indices: [${signerIndices.join(", ")}]
Signatures:
`);
signatures.forEach((sig, i) => console.log(`  ${i}: "${sig}"`));