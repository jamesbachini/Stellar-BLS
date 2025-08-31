// -------------------------------------------------------------
// Helper for the "ThresholdAccount" Soroban contract (2-of-3 BLS)
// -------------------------------------------------------------
import { randomBytes }      from 'crypto';
import { Buffer }           from 'buffer';
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";

const DST = 'THRESHOLD-BLS-SIG-V1';                 // MUST match contract
const CURVE_ORDER = bls.Fr.ORDER;

// ---------- helpers --------------------------------------------------------
const toHex = (u8) => Buffer.from(u8).toString('hex');
const mod   = (a, m = CURVE_ORDER) => ((a % m) + m) % m;

// extended-gcd inverse
const modInv = (a, m = CURVE_ORDER) => {
  let [lm, hm] = [1n, 0n];
  let [low, high] = [mod(a, m), m];
  while (low > 1n) {
    const r = high / low;
    [lm, hm] = [hm - lm * r, lm];
    [low, high] = [high - low * r, low];
  }
  return mod(lm, m);
};

// bigint <--> 32-byte scalar
const b2u8 = (b) => {
  const hex = b.toString(16).padStart(64, '0');
  return Uint8Array.from(Buffer.from(hex, 'hex'));
};
const randFr = () => (BigInt('0x' + randomBytes(32).toString('hex')) % CURVE_ORDER);

// ---------- 1. local 2-of-3 DKG (degree-1 polynomial) ----------------------
const a0 = randFr();               // secret   s
const a1 = randFr();               // random   a₁
const f  = (x) => mod(a0 + a1 * x);

const shares = [1n, 2n, 3n].map(x => ({ x, y: f(x) }));
console.log('Secret s       : 0x' + a0.toString(16));
shares.forEach((s, i) =>
  console.log(`Share #${i + 1}     : x=${s.x}  y=0x${s.y.toString(16)}`)
);

// group public key (96-byte **uncompressed** G1)
const groupPkBytes = bls.getPublicKey(b2u8(a0), /*compressed?*/ false);
console.log('\n=== GROUP PUBLIC KEY (hex, 96 bytes) ===');
console.log(toHex(groupPkBytes));

// ---------- 2. prepare message & choose 2 signers -------------------------
const messageText = 'privacy is a right';
const msgBytes = new TextEncoder().encode(messageText);
console.log(`\nMessage         : "${messageText}"`);

const signerIdx = [0, 2];                   // use share #1 and #3
console.log(`Using signers    : ${signerIdx.map(i => i + 1).join(', ')}`);

// ---------- 3. Reconstruct secret s from the two shares -------------------
const xs = signerIdx.map(i => shares[i].x);
const ys = signerIdx.map(i => shares[i].y);
const denom = mod(xs[0] - xs[1]);
const λ0 = mod(-xs[1] * modInv(denom));     // Lagrange coef for share 1
const λ1 = mod( xs[0] * modInv(denom));     // Lagrange coef for share 3
const sRec = mod(ys[0] * λ0 + ys[1] * λ1);
if (sRec !== a0) console.warn('(!) reconstruction mismatch');

// ---------- 4. Make aggregate signature σ (uncompressed, 192 bytes) -------
const sigCompressed   = await bls.sign(msgBytes, b2u8(sRec), { DST });
//const sigPoint        = bls.G2.ProjectivePoint.fromHex(sigCompressed);
const sigPoint        = bls.PointG2.fromHex(sigCompressed);
const sigUncompressed = sigPoint.toRawBytes(false);    // 192 bytes
console.log('\n=== AGGREGATE SIGNATURE (hex, 192 bytes) ===');
console.log(toHex(sigUncompressed));

// ---------- 5. Soroban CLI snippets ---------------------------------------
console.log(`
====================  SOROBAN DEMO  ====================

# 1) initialise the custom account with the group public key
soroban contract invoke \\
  --id  <CONTRACT_ID> \\
  --network testnet \\
  -- init \\
  --group_pk ${toHex(groupPkBytes)}

# 2) call a protected function ('ping')
#    <ACCOUNT_ADDR> is the address of the custom account
soroban contract invoke \\
  --id  <CONTRACT_ID> \\
  --network testnet \\
  --source <ACCOUNT_ADDR> \\
  -- ping \\
  --signature ${toHex(sigUncompressed)}

========================================================
`);