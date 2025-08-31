import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Buffer } from "buffer";

const toHex = (u8) => {
  if (u8 instanceof Uint8Array || u8 instanceof Buffer) {
    return Buffer.from(u8).toString("hex");
  } else if (typeof u8.toHex === "function") {
    return u8.toHex();
  } else {
    return u8.toString();
  }
};

const N = 3;
const keypairs = [];

console.log("=== PUBLIC KEYS FOR SOROBAN INIT (96 bytes uncompressed) ===");
for (let i = 0; i < N; i++) {
  const sk = bls.utils.randomSecretKey();
  const pkUncompressed = bls.shortSignatures.getPublicKey(sk, false);
  const pkHex = pkUncompressed.toHex();
  console.log(`Pubkey #${i + 1} (${pkHex.length}b): ${pkHex}`);
  keypairs.push({ sk, pkHex });
}

const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const dstHex = Buffer.from(dst, "utf8").toString("hex");
console.log(`--dst "${dstHex}"`);


//const messageHash = sha256(messageBytes); // 32-byte hash
//const messageHashHex = toHex(messageHash); // 64 hex chars
//if (messageHashHex.length !== 64) {
//  throw new Error(`Message hash is not 32 bytes! length=${messageHashHex.length}`);
//}
console.log(`\n=== MESSAGE ===`);
const messageText = "privacy is a right";
const messageBytes = new TextEncoder().encode(messageText);
const messageG2Hash = bls.G2.hashToCurve(messageBytes);
const hexMessageHash = toHex(messageG2Hash);
console.log(`Original message: "${messageText}"`);
console.log(`Message hash (${hexMessageHash.length}b): ${hexMessageHash}`);
//const messageCurvePoint = bls.G1.hashToCurve(messageBytes);

const signerIndices = [0, 2]; // Signers #1 and #3
console.log(`\n=== SIGNATURES ===`);
console.log(`Signing with signers: ${signerIndices.map((i) => i + 1).join(", ")}\n`);
const signatures = signerIndices.map((idx) => {
  const { sk } = keypairs[idx];
    const sigG2 = bls.longSignatures.sign(messageG2Hash, sk);
    const hexSig = sigG2.toHex();
    console.log(`Signer #${idx + 1} signature (${hexSig.length}b): ${hexSig}`);
    return hexSig; 
  
  //const sigPoint = bls.shortSignatures.sign(messageCurvePoint, sk);
  //const hexSig = sigPoint.toHex();
  //console.log(`Signer #${idx + 1} signature (${hexSig.length}b): ${hexSig}`);
  //return hexSig;
  ////const sigUncompressed = sigPoint.toBytes(); // G2 compressed
  ////return toHex(sigUncompressed);
});

console.log(`
=== SOROBAN CONTRACT CALLS ===
stellar contract invoke \\
  --id YOUR_CONTRACT_ID \\
  --source james \\
  --network testnet \\
  -- init \\
  --pk1 ${keypairs[0].pkHex} \\
  --pk2 ${keypairs[1].pkHex} \\
  --pk3 ${keypairs[2].pkHex} \\
  --dst "${dstHex}"

stellar contract invoke \\
  --id YOUR_CONTRACT_ID \\
  --source james \\
  --network testnet \\
  -- authorize \\
  --message "${hexMessageHash}" \\
  --sig1 "${signatures[0]}" \\
  --sig2 "${signatures[1]}"

stellar contract invoke \\
  --id YOUR_CONTRACT_ID \\
  --source james \\
  --network testnet \\
  -- get_flag
`);
