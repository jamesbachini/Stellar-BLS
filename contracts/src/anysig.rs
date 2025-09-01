#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, vec, Bytes, BytesN, bytesn, Env, Vec, crypto::bls12_381::{G1Affine, G2Affine},
};

#[contract]
pub struct ThresholdAccount;

const DST: &str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    PublicKeys,
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
    pub fn init(env: Env, public_keys: Vec<BytesN<96>>) {
        env.storage().persistent().set(&DataKey::PublicKeys, &public_keys);
        env.storage().instance().set(&DataKey::Dst, &Bytes::from_slice(&env, DST.as_bytes()));
        env.storage().persistent().set(&DataKey::Flag, &false);
    }

    pub fn set_flag(
        env: Env,
        signature_payload: BytesN<32>,
        signature: BytesN<192>,
    ) -> Result<(), BlsError> {
        let public_keys: Vec<BytesN<96>> = env.storage().persistent().get(&DataKey::PublicKeys).unwrap();
        let bls = env.crypto().bls12_381();
        let dst: Bytes = env.storage().instance().get(&DataKey::Dst).unwrap();
        let neg_g1 = G1Affine::from_bytes(bytesn!(
            &env,
            0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca
        ));
        let msg_g2 = bls.hash_to_g2(&signature_payload.into(), &dst);
        let sig_g2 = G2Affine::from_bytes(signature);
        for pk_bytes in public_keys.iter() {
            let pk_g1 = G1Affine::from_bytes(pk_bytes);
            let vp1: Vec<G1Affine> = vec![&env, pk_g1, neg_g1.clone()];
            let vp2: Vec<G2Affine> = vec![&env, msg_g2.clone(), sig_g2.clone()];
            if bls.pairing_check(vp1, vp2) {
                env.storage().persistent().set(&DataKey::Flag, &true);
                return Ok(());
            }
        }
        Err(BlsError::InvalidSignature)
    }

    pub fn get_flag(env: Env) -> bool {
        env.storage().persistent().get(&DataKey::Flag).unwrap_or(false)
    }

    pub fn reset_flag(env: Env) {
        env.storage().persistent().set(&DataKey::Flag, &false);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    extern crate std;
    extern crate hex_literal;
    use hex_literal::hex;
    use soroban_sdk::{
        crypto::bls12_381::Fr,
        testutils::BytesN as _,
        Bytes, BytesN, Env, Vec,
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

    fn create_signature(env: &Env, msg: &BytesN<32>, signer_index: usize) -> BytesN<192> {
        let bls = env.crypto().bls12_381();
        let dst = Bytes::from_slice(env, DST.as_bytes());
        let msg_g2 = bls.hash_to_g2(&msg.clone().into(), &dst);
        let sk = Fr::from_bytes(BytesN::from_array(env, &KEY_PAIRS[signer_index].sk));
        let sig = bls.g2_mul(&msg_g2, &sk);
        sig.to_bytes()
    }

    #[test]
    fn test_signer0() {
        let e = Env::default();
        let cli = client(&e);
        let all_pks: Vec<BytesN<96>> = vec![
            &e,
            BytesN::from_array(&e, &KEY_PAIRS[0].pk),
            BytesN::from_array(&e, &KEY_PAIRS[1].pk),
            BytesN::from_array(&e, &KEY_PAIRS[2].pk),
        ];
        cli.init(&all_pks);
        assert_eq!(cli.get_flag(), false);
        let payload = BytesN::<32>::random(&e);
        let signature = create_signature(&e, &payload, 0);
        cli.set_flag(&payload, &signature);
        assert_eq!(cli.get_flag(), true);
    }

    #[test]
    fn test_signer1() {
        let e = Env::default();
        let cli = client(&e);
        let all_pks: Vec<BytesN<96>> = vec![
            &e,
            BytesN::from_array(&e, &KEY_PAIRS[0].pk),
            BytesN::from_array(&e, &KEY_PAIRS[1].pk),
            BytesN::from_array(&e, &KEY_PAIRS[2].pk),
        ];
        cli.init(&all_pks);
        assert_eq!(cli.get_flag(), false);  
        let payload = BytesN::<32>::random(&e);
        let signature = create_signature(&e, &payload, 1);
        cli.set_flag(&payload, &signature);
        assert_eq!(cli.get_flag(), true);
    }

    #[test]
    fn test_signer2() {
        let e = Env::default();
        let cli = client(&e);
        let all_pks: Vec<BytesN<96>> = vec![
            &e,
            BytesN::from_array(&e, &KEY_PAIRS[0].pk),
            BytesN::from_array(&e, &KEY_PAIRS[1].pk),
            BytesN::from_array(&e, &KEY_PAIRS[2].pk),
        ];
        cli.init(&all_pks);
        assert_eq!(cli.get_flag(), false);
        let payload = BytesN::<32>::random(&e);
        let signature = create_signature(&e, &payload, 2);
        cli.set_flag(&payload, &signature);
        assert_eq!(cli.get_flag(), true);
    }
}