#![no_std]

use soroban_sdk::{
    bytesn, contract, contracterror, contractimpl, contracttype, vec, Bytes, BytesN, Env, Vec,
    crypto::bls12_381::{G1Affine, G2Affine},
};

#[contract]
pub struct ThresholdAccount;

const DST: &str = "THRESHOLD-BLS-SIG-V1";

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    GroupPk,
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
    pub fn init(env: Env, group_pk: BytesN<96>) {
        env.storage().persistent().set(&DataKey::GroupPk, &group_pk);
        env.storage()
            .instance()
            .set(&DataKey::Dst, &Bytes::from_slice(&env, DST.as_bytes()));
        env.storage().persistent().set(&DataKey::Flag, &false);
    }

    pub fn set_flag(
        env: Env,
        signature_payload: BytesN<32>,
        agg_sig: BytesN<192>,
    ) -> Result<(), BlsError> {
        let bls = env.crypto().bls12_381();
        let pk_g: BytesN<96> = env
            .storage()
            .persistent()
            .get(&DataKey::GroupPk)
            .unwrap();
        let dst: Bytes = env.storage().instance().get(&DataKey::Dst).unwrap();
        let neg_g1 = G1Affine::from_bytes(bytesn!(
            &env,
            0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca
        ));
        let msg_g2 = bls.hash_to_g2(&signature_payload.into(), &dst);
        let vp1: Vec<G1Affine> = vec![&env, G1Affine::from_bytes(pk_g), neg_g1];
        let vp2: Vec<G2Affine> =
            vec![&env, msg_g2, G2Affine::from_bytes(agg_sig)];
        if !bls.pairing_check(vp1, vp2) {
            return Err(BlsError::InvalidSignature);
        }
        env.storage().persistent().set(&DataKey::Flag, &true);
        Ok(())
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
        crypto::bls12_381::{Fr, G1Affine, G2Affine},
        testutils::BytesN as _,
        vec, Bytes, BytesN, Env, Vec,
    };

    use super::ThresholdAccountClient;

    fn client(e: &Env) -> ThresholdAccountClient<'_> {
        ThresholdAccountClient::new(e, &e.register(ThresholdAccount {}, ()))
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

    fn aggregated_pk(env: &Env) -> BytesN<96> {
        let bls = env.crypto().bls12_381();
        let mut acc = G1Affine::from_bytes(BytesN::from_array(env, &KEY_PAIRS[0].pk));
        for kp in KEY_PAIRS.iter().skip(1) {
            let pk = G1Affine::from_bytes(BytesN::from_array(env, &kp.pk));
            acc = bls.g1_add(&acc, &pk);
        }
        acc.to_bytes()
    }

    fn aggregated_sig(env: &Env, msg: &BytesN<32>) -> BytesN<192> {
        let bls = env.crypto().bls12_381();
        let mut sks: Vec<Fr> = vec![env];
        for kp in KEY_PAIRS {
            sks.push_back(Fr::from_bytes(BytesN::from_array(env, &kp.sk)));
        }
        let dst = Bytes::from_slice(env, DST.as_bytes());
        let msg_g2 = bls.hash_to_g2(&msg.clone().into(), &dst);
        let mut msgs: Vec<G2Affine> = vec![env];
        for _ in 0..KEY_PAIRS.len() {
            msgs.push_back(msg_g2.clone());
        }
        bls.g2_msm(msgs, sks).to_bytes()
    }

    #[test]
    fn set_flag_flow() {
        let e = Env::default();
        let cli = client(&e);
        cli.init(&aggregated_pk(&e));
        assert_eq!(cli.get_flag(), false);
        let payload = BytesN::<32>::random(&e);
        let sig = aggregated_sig(&e, &payload);
        cli.set_flag(&payload, &sig);
        assert_eq!(cli.get_flag(), true);
    }
}