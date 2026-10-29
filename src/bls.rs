use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_std::UniformRand;

use rand::thread_rng;

use crate::utils;

pub struct BLSKey<E: Pairing> {
    sk: E::ScalarField,
    pub pk: E::G1,
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

    pub fn sign(&self, msg: &Vec<u8>) -> E::G2 {
        let hash_msg = utils::hash_g2::<E>(msg);

        hash_msg * self.sk
    }
}

pub fn verify<E: Pairing>(pk: E::G1, msg: &Vec<u8>, sig: E::G2) -> bool {
    let p1 = E::pairing(pk, utils::hash_g2::<E>(msg));
    let p2 = E::pairing(E::G1::generator(), sig);

    p1 == p2
}
