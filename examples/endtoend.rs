#![allow(unused_imports)]
use ark_bls12_381::{G1Affine, G2Affine, g2::Config as G2Config};
use ark_ec::{CurveGroup, PrimeGroup, pairing::Pairing, hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve}};
use ark_ff::{BigInteger, PrimeField};
use ark_ff::fields::field_hashers::DefaultFieldHasher;
use ark_std::{UniformRand, start_timer, end_timer};
use std::env;

use c_ste::{aggregation::{aggregate, decrypt}, bls::{BLSSignature, verify as bls_verify}, committee::{committee_select, epoch_commitment, participate_select}, dealer::{Dealer, Hints, hint_verify}, member::Member, verify::{encrypt, verify}};
use rand::thread_rng;
use sha2::Sha256;

type E = ark_bls12_381::Bls12_381;
type G1 = <E as Pairing>::G1;
type G2 = <E as Pairing>::G2;
type Fr = <E as Pairing>::ScalarField;
type G2Hasher = MapToCurveBasedHasher<G2, DefaultFieldHasher<Sha256, 128>, WBMap<G2Config>>;

fn main() {
    let g2_hasher = G2Hasher::new(b"CSTE_BLS12381_G2_V1").expect("invalid hash-to-G2 parameters");
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: cargo run --example endtoend --release -- sign/encrypt <N> <n> <t>");
        return;
    }

    if args[1] != "sign" && args[1] != "encrypt" {
        eprintln!("Usage: cargo run --example endtoend --release -- sign/encrypt <N> <n> <t>");
        return;
    }

    let total: usize = args[2].parse().expect("invalid N");
    let n: usize = args[3].parse().expect("invalid n");
    let t: usize = args[4].parse().expect("invalid t");

    if n >= total {
        eprintln!("Require N > n");
        return;
    }

    if n < t {
        eprintln!("Require n >= t");
        return;
    }

    let r = t; // r = t is a special case of calculation, and we default r = t for test

    let setup_timer = start_timer!(|| "Dealer setup");
    let (d, secret) = Dealer::<E>::init_fast(total - 1);
    end_timer!(setup_timer);
    
    let member_timer = start_timer!(|| "Generate members");
    let members: Vec<Member<E>> = (0..total).map(|id| Member::<E>::new(id)).collect();
    end_timer!(member_timer);
    
    let hints_timer = start_timer!(|| "Generate hints");
    // let hints: Vec<Hints<E>> = members.iter().map(|mb| mb.hint_gen_naive(&d)).collect();
    // let hints: Vec<Hints<E>> = members.iter().map(|mb| mb.hint_gen_lagrange(&d)).collect();
    let pks: Vec<G1Affine> = members.iter().map(|mb| mb.key.pk.into_affine()).collect();
    // assert!(hints.iter().zip(pks.iter()).all(|(hint, pk)| hint_verify(&d, *pk, hint)));
    end_timer!(hints_timer);
    
    let preprocess_timer = start_timer!(|| "Preprocess");
    // let (ak, ek) = d.preprocess(&pks, &hints);
    let (ak, ek) = d.preprocess_trapdoor(&pks, &secret);
    end_timer!(preprocess_timer);
    
    let e = 12345678; // For example only
    let com_e = committee_select(total, n, e);
    let epoch_commitment_timer = start_timer!(|| "Epoch Commitment");
    let be = epoch_commitment(&d, &com_e);
    end_timer!(epoch_commitment_timer);
    
    let mut rng = thread_rng();
    let msg = E::pairing(G1::generator(), G2::generator()) * Fr::rand(&mut rng);

    if args[1] == "sign" { // c-STS
        let m = Fr::rand(&mut rng).into_bigint().to_bytes_be();
        let mut mm = m.clone();
        mm.extend(e.to_be_bytes());
        
        let sign_timer = start_timer!(|| "Partial Sign");
        let s = participate_select(&com_e, r);
        let sig_s: Vec<BLSSignature<E>> = s.iter().map(
            |&id| members[id].key.sign(&mm, &g2_hasher)
        ).collect();
        // assert!(s.iter().zip(sig_s.iter()).all(|(&id, sig)| bls_verify(members[id].key.pk, &mm, sig, &g2_hasher)));
        end_timer!(sign_timer);

        let verify_sig_timer = start_timer!(|| "Part Verification");
        let sig_s_sig: Vec<G2Affine> = sig_s.iter().zip(s.iter()).filter(|(sig, id)| {
            (**id == 0 || (com_e.contains(id) && ak.v.get(**id).copied().unwrap_or(false)))
                && bls_verify(members[**id].key.pk, &mm, sig, &g2_hasher)
        }).map(|(sig, _)| sig.signature).collect();
        let s: Vec<usize> = std::iter::once(0).chain(sig_s.iter().zip(s.iter()).filter(|(sig, id)| {
            (**id != 0 && com_e.contains(id) && ak.v.get(**id).copied().unwrap_or(false))
                && bls_verify(members[**id].key.pk, &mm, sig, &g2_hasher)
        }).map(|(_, id)| *id)).collect();
        end_timer!(verify_sig_timer);
        
        let aggregate_timer = start_timer!(|| "Aggregation");
        let aggr_sig = aggregate(&d, &ak, &s, &com_e, &sig_s_sig, t);
        end_timer!(aggregate_timer);

        let verify_timer = start_timer!(|| "Verification");
        let res = verify(&d, &ek, &m, t, e, be, aggr_sig, &g2_hasher);
        end_timer!(verify_timer);
        
        assert!(res);
    }
    else { // c-STE
        let encrypt_timer = start_timer!(|| "Encryption");
        let ct = encrypt(&d, &ek, msg, t, e, be, &g2_hasher);
        end_timer!(encrypt_timer);
        
        let mut m = ct.ct1.into_bigint().to_bytes_be();
        m.extend(e.to_be_bytes());
        
        let sign_timer = start_timer!(|| "Partial Sign");
        let s = participate_select(&com_e, r);
        let sig_s: Vec<BLSSignature<E>> = s.iter().map(
            |&id| members[id].key.sign(&m, &g2_hasher)
        ).collect();
        end_timer!(sign_timer);

        let verify_sig_timer = start_timer!(|| "Part Verification");
        let sig_s_sig: Vec<G2Affine> = sig_s.iter().zip(s.iter()).filter(|(sig, id)| {
            (**id == 0 || (com_e.contains(id) && ak.v.get(**id).copied().unwrap_or(false)))
                && bls_verify(members[**id].key.pk, &m, sig, &g2_hasher)
        }).map(|(sig, _)| sig.signature).collect();
        let s: Vec<usize> = std::iter::once(0).chain(sig_s.iter().zip(s.iter()).filter(|(sig, id)| {
            (**id != 0 && com_e.contains(id) && ak.v.get(**id).copied().unwrap_or(false))
                && bls_verify(members[**id].key.pk, &m, sig, &g2_hasher)
        }).map(|(_, id)| *id)).collect();
        end_timer!(verify_sig_timer);
        
        let decrypt_timer = start_timer!(|| "Decryption");
        let msg_decrypt = decrypt(&d, &ak, &ct, &s, &com_e, &sig_s_sig, t);
        end_timer!(decrypt_timer);
        
        assert_eq!(msg, msg_decrypt);
    }
    
}