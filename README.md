# 🥷 SoroRing – Anonymous Auth with BLS Ring Signatures

Tutorial walkthrough: https://jamesbachini.com/privacy-on-stellar/

An experiment that lets any member of a public key-ring prove *membership* on Stellar without revealing **which** key signed. Powered by Soroban’s built-in BLS12-381 host functions.

**Key components**

1. A Soroban contract that  
   • stores the ring of public keys  
   • verifies BLS ring signatures on-chain  
   • bumps a `login_count` every successful proof  
2. A browser dApp that  
   • simulates `create_keys` and `sign` (no crypto libs in JS)  
   • invokes `init` and `verify` transactions  
3. Simple HTML/JS UI to click any wallet and “login anonymously”

---

## 1. 🧱 Deploy the Soroban Contract

`RingSigContract` exposes:

* `init(ring)`           → persist the list of public keys  
* `create_keys(n)`       → helper that *returns* `n` fresh (sk,pk) pairs  
* `sign(msg, ring, idx, sk)` → off-chain signer that emits a `RingSignature` struct  
* `verify(msg, sig)`     → on-chain verifier that also increments `login_count`

Example snippet:

```rust
#[contractimpl]
impl RingSigContract {
    pub fn verify(env: Env, msg: Bytes, sig: RingSignature) -> bool {
        // rebuild hash-chain, only true when loop closes
    }
}
```

### Build & Deploy (testnet)

```bash
cargo build --target wasm32-unknown-unknown --release

stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/sororing.wasm \
  --source james \
  --network testnet
```

Copy the returned contract ID for the UI.

---

## 2. 👛 Generate a Ring & Init the Contract

The front-end does it with one simulated call and one real tx:

```js
const N = 3; // ring size
const res      = await simulate("create_keys", U32(N));
const keyRing  = StellarSdk.scValToNative(res); // {secret_keys, ring}
await invoke("init", Vec(keyRing.ring.map(Bytes)));
```

---

## 3. 🔐 Sign & Verify a Message

1. Pick any index `i` you control.  
2. Simulate `sign()` with your secret key to obtain `{challenge, responses}`.  
3. Send `verify()` on-chain.  

```js
const msg   = Bytes(new TextEncoder().encode("zkLogin"));
const sigX  = await simulate(
  "sign",
  msg,
  Vec(keyRing.ring.map(Bytes)),
  U32(i),
  Bytes(keyRing.secret_keys[i])
);

const sig   = StellarSdk.scValToNative(sigX);
await invoke("verify", msg, Map([
  ["challenge", Bytes(sig.challenge)],
  ["responses", Vec(sig.responses.map(Bytes))]
]));
```

If the loop closes, the contract:

• returns `true`  
• increments `login_count`

---

## 4. 📂 Project Structure

```
.
├── contract/           # RingSigContract (Rust)
│   └── lib.rs
├── frontend/           # index.html + main.js (sim + tx helpers)
├── public/             # github-pages page
└── README.md           # ← you are here
```

---

## ⚠️ Notes

* Key generation in `create_keys()` uses `sha256` as a quick RNG — **not** for production.  
* Anyone can inspect the ring; only signers stay anonymous.  
* Make sure to use real randomness and secure key storage in a live system.

---

## 📝 License

MIT

---

## 🔗 Helpful Links

Developer Quick Start:
https://stellar.org/developers?utm_source=james-bachini&utm_medium=social&utm_campaign=lemonade-kol-developers-q2-25

Developer Docs:
https://developers.stellar.org/?utm_source=james-bachini&utm_medium=social&utm_campaign=lemonade-kol-dev-docs-q2-25

Dev Diaries:
https://stellar.org/?utm_source=james-bachini&utm_medium=social&utm_campaign=lemonade-kol-dev-diaries-q2-25

Flipside Challenges:
https://flipsidecrypto.xyz/earn/journey/stellar-onboarding?utm_source=james-bachini&ut[…]dium=social&utm_campaign=lemonade-kol-flipside-quests-q2-25

Stellar Main Site:
https://stellar.org/?utm_source=james-bachini&utm_medium=social&utm_campaign=lemonade-kol-general-q2-25

Meridian 2025:
https://meridian.stellar.org/register?utm_source=james-bachini&utm_medium=social&utm_campaign=lemonade-kol-meridian-2025-q2-25