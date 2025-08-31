#![no_std]

use soroban_sdk::{ contract, contractimpl, contracttype, contracterror, crypto::bls12_381::{G1Affine, G2Affine}, Env, BytesN, Bytes, Vec, bytesn };

#[contract]
pub struct ThresholdBlsDemo;

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    PubKeys,
    Flag,
    Dst,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Err {
    NotEnoughValid = 1,
}

#[contractimpl]
impl ThresholdBlsDemo {
    pub fn init(env: Env, pk1: BytesN<96>, pk2: BytesN<96>, pk3: BytesN<96>, dst: Bytes) {
        let pubkeys = Vec::from_array(&env, [pk1, pk2, pk3]);
        env.storage().persistent().set(&DataKey::PubKeys, &pubkeys);
        env.storage().persistent().set(&DataKey::Dst, &dst);
        env.storage().persistent().set(&DataKey::Flag, &false);
    }

    pub fn authorize(
        env: Env,
        message: BytesN<192>,
        sig1: Option<BytesN<192>>,
        sig2: Option<BytesN<192>>,
    ) -> Result<(), Err> {
        let bls = env.crypto().bls12_381();
        let pubkeys: Vec<BytesN<96>> = env.storage().persistent().get(&DataKey::PubKeys).unwrap();
        let dst: Bytes = env.storage().persistent().get(&DataKey::Dst).unwrap();
        let sigs = [sig1, sig2];
        let mut valid_count = 0u32;
        for i in 0..2 {
            if let Some(sig_bytes) = &sigs[i] {
                let pk_affine = G1Affine::from_bytes(pubkeys.get_unchecked(i as u32));
                let sig_affine = G2Affine::from_bytes(sig_bytes.clone());
                let msg_g2 = bls.hash_to_g2(&Bytes::from_array(&env, &message.to_array()), &dst);
                let neg_g1 = G1Affine::from_bytes(bytesn!(&env,
                    0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca
                ));
                let vp1 = Vec::from_array(&env, [pk_affine, neg_g1]);
                let vp2 = Vec::from_array(&env, [msg_g2.clone(), sig_affine]);
                if bls.pairing_check(vp1, vp2) {
                    valid_count += 1;
                }
            }
        }
        if valid_count >= 2 {
            env.storage().persistent().set(&DataKey::Flag, &true);
            Ok(())
        } else {
            Err(Err::NotEnoughValid)
        }
    }

    pub fn get_flag(env: Env) -> bool {
        env.storage().persistent().get(&DataKey::Flag).unwrap_or(false)
    }
}
