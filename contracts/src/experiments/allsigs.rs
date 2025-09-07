#![no_std]

use soroban_sdk::{
    bytesn, contract, contracterror, contractimpl, contracttype, vec, Bytes, BytesN, Env, Vec,
    crypto::bls12_381::{G1Affine, G2Affine},
};

#[contract]
pub struct ThresholdAccount;

const DST: &str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    AggPk,
    Dst,
    Flag,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum BlsError {
    InvalidSignature = 1,
}

#[contractimpl]
impl ThresholdAccount {
    pub fn init(env: Env, aggregate_pk: BytesN<96>) {
        env.storage().persistent().set(&DataKey::AggPk, &aggregate_pk);
        env.storage()
            .instance()
            .set(&DataKey::Dst, &Bytes::from_slice(&env, DST.as_bytes()));
        env.storage().persistent().set(&DataKey::Flag, &false);
    }

    pub fn set_flag(
        env: Env,
        signature_payload: BytesN<32>,
        aggregate_signature: BytesN<192>,
    ) -> Result<(), BlsError> {
        let agg_pk_bytes: BytesN<96> = env.storage().persistent().get(&DataKey::AggPk).unwrap();
        let bls = env.crypto().bls12_381();
        let dst: Bytes = env.storage().instance().get(&DataKey::Dst).unwrap();
        let neg_g1 = G1Affine::from_bytes(bytesn!(
            &env,
            0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca
        ));
        let agg_pk = G1Affine::from_bytes(agg_pk_bytes);
        let msg_g2 = bls.hash_to_g2(&signature_payload.into(), &dst);
        let sig_g2 = G2Affine::from_bytes(aggregate_signature);
        let pks_g1: Vec<G1Affine> = vec![&env, agg_pk, neg_g1];
        let sigs_g2: Vec<G2Affine> = vec![&env, msg_g2, sig_g2];
        if bls.pairing_check(pks_g1, sigs_g2) {
            env.storage().persistent().set(&DataKey::Flag, &true);
            Ok(())
        } else {
            Err(BlsError::InvalidSignature)
        }
    }

    pub fn get_flag(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Flag)
            .unwrap_or(false)
    }

}

#[cfg(test)]
mod test {
    use super::*;
    extern crate std;
    extern crate hex_literal;
    use hex_literal::hex;
    use soroban_sdk::{
        crypto::bls12_381::{Fr, G1Affine},
        testutils::BytesN as _,
        vec, Bytes, BytesN, Env,
    };

    use super::ThresholdAccountClient;

    fn client(e: &Env) -> ThresholdAccountClient<'_> {
        ThresholdAccountClient::new(e, &e.register_contract(None, ThresholdAccount))
    }

    #[derive(Debug)]
    struct KeyPair {
        sk: [u8; 32],
        pk: [u8; 96],
    }

    const KEY_PAIRS: &[KeyPair] = &[
        KeyPair {
            sk: hex!("18a5ac3cfa6d0b10437a92c96f553311fc0e25500d691ae4b26581e6f925ec83"),
            pk: hex!("0914e32703bad05ccf4180e240e44e867b26580f36e09331997b2e9effe1f509b1a804fc7ba1f1334c8d41f060dd72550901c5549caef45212a236e288a785d762a087092c769bfa79611b96d73521ddd086b7e05b5c7e4210f50c2ee832e183"),
        },
        KeyPair {
            sk: hex!("738dbecafa122ee3c953f07e78461a4281cadec00c869098bac48c8c57b63374"),
            pk: hex!("05f4708a013699229f67d0e16f7c2af8a6557d6d11b737286cfb9429e092c31c412f623d61c7de259c33701aa5387b5004e2c03e8b7ea2740b10a5b4fd050eecca45ccf5588d024cbb7adc963006c29d45a38cb7a06ce2ac45fce52fc0d36572"),
        },
        KeyPair {
            sk: hex!("4bff25b53f29c8af15cf9b8e69988c3ff79c80811d5027c80920f92fad8d137d"),
            pk: hex!("18d0fef68a72e0746f8481fa72b78f945bf75c3a1e036fbbde62a421d8f9568a2ded235a27ad3eb0dc234b298b54dd540f61577bc4c6e8842f8aa953af57a6783924c479e78b0d4959038d3d108b3f6dc6a1b02ec605cb6d789af16cfe67f689"),
        },
    ];

    fn create_aggregate_signature(env: &Env, msg: &BytesN<32>, signer_indices: &[usize]) -> BytesN<192> {
        let bls = env.crypto().bls12_381();
        let dst = Bytes::from_slice(env, DST.as_bytes());
        let msg_g2 = bls.hash_to_g2(&msg.clone().into(), &dst);
        let first_signer = signer_indices[0];
        let sk = Fr::from_bytes(BytesN::from_array(env, &KEY_PAIRS[first_signer].sk));
        let mut agg_sig = bls.g2_mul(&msg_g2, &sk);
        for &i in &signer_indices[1..] {
            let sk = Fr::from_bytes(BytesN::from_array(env, &KEY_PAIRS[i].sk));
            let sig = bls.g2_mul(&msg_g2, &sk);
            agg_sig = bls.g2_add(&agg_sig, &sig);
        }
        agg_sig.to_bytes()
    }
    
    // This new helper creates the aggregate public key off-chain.
    fn create_aggregate_public_key(env: &Env, signer_indices: &[usize]) -> BytesN<96> {
        let bls = env.crypto().bls12_381();

        let first_signer = signer_indices[0];
        let pk_bytes = BytesN::from_array(env, &KEY_PAIRS[first_signer].pk);
        let mut agg_pk = G1Affine::from_bytes(pk_bytes);

        for &i in &signer_indices[1..] {
            let pk_bytes = BytesN::from_array(env, &KEY_PAIRS[i].pk);
            let pk = G1Affine::from_bytes(pk_bytes);
            agg_pk = bls.g1_add(&agg_pk, &pk);
        }

        agg_pk.to_bytes()
    }

    #[test]
    fn test_2_of_3_private_signature() {
        let e = Env::default();
        let cli = client(&e);

        // Define which members are signing. This is known off-chain only.
        let signer_indices = [0, 2];

        // 1. Create the aggregate public key from the signers. This would be
        //    used to initialize the contract.
        let aggregate_pk = create_aggregate_public_key(&e, &signer_indices);
        
        // 2. Initialize the contract with the single aggregate key.
        cli.init(&aggregate_pk);

        assert_eq!(cli.get_flag(), false);

        // 3. Create a payload and the corresponding aggregate signature off-chain.
        let payload = BytesN::<32>::random(&e);
        let aggregate_signature = create_aggregate_signature(&e, &payload, &signer_indices);

        // 4. Call the contract. It will verify the signature against the aggregate
        //    public key without knowing who the individual signers were.
        cli.set_flag(&payload, &aggregate_signature);
        assert_eq!(cli.get_flag(), true);
    }

    #[test]
    fn test_invalid_signature_fails() {
        let e = Env::default();
        let cli = client(&e);
    
        // The contract is set up for signers 0 and 2.
        let valid_signer_indices = [0, 2];
        let aggregate_pk = create_aggregate_public_key(&e, &valid_signer_indices);
        cli.init(&aggregate_pk);
    
        let payload = BytesN::<32>::random(&e);
    
        // But the signature is created by a different group (1 and 2).
        let invalid_signer_indices = [1, 2];
        let invalid_signature = create_aggregate_signature(&e, &payload, &invalid_signer_indices);
    
        // The call should fail because the signature doesn't match the aggregate public key.
        let result = cli.try_set_flag(&payload, &invalid_signature);
        assert_eq!(result, Err(Ok(BlsError::InvalidSignature)));
        assert_eq!(cli.get_flag(), false);
    }
}