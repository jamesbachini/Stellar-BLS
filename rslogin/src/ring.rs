use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use soroban_sdk::{
    self as soroban, Bytes, BytesN, Env, Vec,
    crypto::bls12_381::{Fr, G1Affine},
};

const G1_GENERATOR: [u8; 96] = include_bytes!("../g1_generator.bin").clone();

#[derive(Clone, Serialize)]
pub struct PublicKey(pub String);                 // hex encoded
#[derive(Clone)]
pub struct SecretKey(Fr);

#[derive(Serialize, Deserialize)]
pub struct RingSignature {
    pub challenge: String,       // hex
    pub responses: Vec<String>,  // hex
}

// ----------------------------------------------------------------------------------
// helper for 32 random bytes
fn random_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf
}

// ----------------------------------------------------------------------------------
pub struct Ring {
    pub pks: Vec<PublicKey>,
    sks:  Vec<SecretKey>,
}

impl Ring {
    pub fn new(size: usize) -> Self {
        let env  = Env::default();
        let bls  = env.crypto().bls12_381();
        let gen  = G1Affine::from_bytes(BytesN::from_array(&env, &G1_GENERATOR));

        let mut pks = Vec::with_capacity(size);
        let mut sks = Vec::with_capacity(size);

        for _ in 0..size {
            let sk = Fr::from_bytes(BytesN::from_array(&env, &random_32()));
            let pk = bls.g1_mul(&gen, &sk).to_bytes();

            pks.push(PublicKey(hex::encode(pk.to_array())));
            sks.push(SecretKey(sk));
        }
        Ring { pks, sks }
    }

    pub fn pk_bytes(&self) -> Vec<BytesN<96>> {
        let env = Env::default();
        self.pks
            .iter()
            .map(|pk| {
                let mut raw = [0u8; 96];
                raw.copy_from_slice(&hex::decode(&pk.0).unwrap());
                BytesN::from_array(&env, &raw)
            })
            .collect()
    }

    // --------------------------------------------------------------------------
    pub fn sign(&self, msg: &[u8], signer: usize) -> RingSignature {
        let env = Env::default();
        let mut ring_bytes = self.pk_bytes();

        // identical to on-chain code ------------------------------------------------
        let bls    = env.crypto().bls12_381();
        let gen_g  = G1Affine::from_bytes(BytesN::from_array(&env, &G1_GENERATOR));
        let sk     = &self.sks[signer].0;

        // replace the pk of the signer (doesn’t matter in practice but
        // keeps it 1-to-1 with the soroban test)
        let pk = bls.g1_mul(&gen_g, sk).to_bytes();
        ring_bytes.set(signer as u32, pk);

        let n = ring_bytes.len() as usize;
        let a = Fr::from_bytes(BytesN::from_array(&env, &random_32()));

        //  responses and challenges ------------------------------------------------
        let mut responses: Vec<BytesN<32>> = Vec::new(&env);
        for _ in 0..n {
            responses.push_back(BytesN::from_array(&env, &random_32()));
        }

        let mut base = Bytes::new(&env);
        for pk in ring_bytes.iter() {
            base.append(&pk.into());
        }
        base.append(&Bytes::from_slice(&env, msg));

        let xs = bls.g1_mul(&gen_g, &a);
        let mut pre = base.clone();
        pre.append(&xs.to_bytes().into());

        let mut c: Vec<Fr> = Vec::new(&env);
        for _ in 0..n {
            c.push_back(Fr::from_bytes(BytesN::from_array(&env, &[0u8; 32])));
        }

        let mut idx = (signer + 1) % n;
        c.set(idx as u32, Fr::from_bytes(env.crypto().sha256(&pre).into()));

        while idx != signer {
            let r_i = Fr::from_bytes(responses.get_unchecked(idx as u32));
            let p_i = G1Affine::from_bytes(ring_bytes.get_unchecked(idx as u32));

            let x1 = bls.g1_mul(&gen_g, &r_i);
            let x2 = bls.g1_mul(&p_i, &c.get_unchecked(idx as u32));
            let xi = bls.g1_add(&x1, &x2);

            let mut pre2 = base.clone();
            pre2.append(&xi.to_bytes().into());
            let ci1 = Fr::from_bytes(env.crypto().sha256(&pre2).into());

            idx = (idx + 1) % n;
            c.set(idx as u32, ci1);
        }

        let rs = a - c.get_unchecked(signer as u32) * sk.clone();
        responses.set(signer as u32, rs.to_bytes());

        RingSignature {
            challenge: hex::encode(c.get_unchecked(0).to_array()),
            responses: responses
                .iter()
                .map(|b| hex::encode(b.to_array()))
                .collect(),
        }
    }
}