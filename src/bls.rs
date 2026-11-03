use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, pairing::Pairing, hashing::HashToCurve};
use ark_std::UniformRand;

use rand::thread_rng;

use crate::utils::{self, EqDlProof};

pub struct BLSKey<E: Pairing> {
    pub sk: E::ScalarField,
    pub pk: E::G1,
}

#[derive(Clone)]
pub struct BLSSignature<E: Pairing> {
    pub signature: E::G2Affine,
    pub proof: EqDlProof<E::ScalarField>,
}

impl<E: Pairing> BLSKey<E> {
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let sk = E::ScalarField::rand(&mut rng);
        let pk = E::G1::generator() * sk;
        
        Self {sk, pk}
    }

    pub fn new_dummy_party() -> Self {
        Self {
            sk: E::ScalarField::from(1u64),
            pk: E::G1::generator()
        }
    }
    
    pub fn mul_sk(&self, p: E::G1) -> E::G1 {
        p * self.sk
    }
}

impl<E: Pairing> BLSKey<E> {
    pub fn sign<H: HashToCurve<E::G2>>(&self, msg: &Vec<u8>, hasher: &H) -> BLSSignature<E> {
        let hash_msg = utils::hash_g2::<E, H>(msg, hasher);
        let signature = hash_msg * self.sk;
        let signature_affine = signature.into_affine();
        let proof = utils::eq_dl_prove(
            E::G1::generator(),
            self.pk,
            hash_msg,
            signature_affine.into_group(),
            self.sk,
        );
        BLSSignature {
            signature: signature_affine,
            proof,
        }
    }
}

pub fn verify<E: Pairing, H: HashToCurve<E::G2>>(pk: E::G1, msg: &Vec<u8>, sig: &BLSSignature<E>, hasher: &H) -> bool {
    utils::eq_dl_verify(
        E::G1::generator(),
        pk,
        utils::hash_g2::<E, H>(msg, hasher),
        sig.signature.into_group(),
        sig.proof,
    )
}
