use ark_ec::{CurveGroup, PrimeGroup, pairing::{Pairing, PairingOutput}};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_std::UniformRand;

use rand::thread_rng;

use crate::{aggregation::AggrSig, dealer::{Dealer, EncKey}, utils};

pub struct Ciphertext<E: Pairing> {
    pub ct1: E::ScalarField,
    pub ct2: (E::G1, E::G2, E::G2, E::G2, E::G2, E::G1, E::G2, E::G2, E::G2),
    pub ct3: PairingOutput<E>,
}

pub fn verify<E: Pairing>(d: &Dealer<E>, ek: &EncKey<E>, m: &Vec<u8>, t: usize, e: usize, be: E::G1, aggr: AggrSig<E>) -> bool {
    let mut mm = m.clone();
    mm.extend(e.to_be_bytes());
    let tag = utils::hash_g2::<E>(&mm);

    let p1 = E::multi_pairing([ek.c, aggr.s1, aggr.s2], [aggr.s0, E::G2::generator(), ek.z]);
    let p0 = E::pairing(aggr.s3, d.crs.1[1]);
    let p2 = E::pairing(aggr.s4, E::G2::generator());
    let p3 = E::multi_pairing([aggr.s1, E::G1::generator()], [tag, aggr.s5]);
    let p4 = E::multi_pairing([d.crs.0[t + 1], aggr.s6.into_affine()], [aggr.s0, E::G2::generator()]);
    let p5 = E::multi_pairing([be, aggr.s7], [aggr.s0, ek.z]);
    let p6 = E::multi_pairing([E::G1::generator(), aggr.s8], [aggr.s0, d.crs.1[1] - d.crs.1[0]]);

    p1 + p0 == PairingOutput::<E>::zero() &&
    p0 + p2 == PairingOutput::<E>::zero() &&
    p3 == PairingOutput::<E>::zero() &&
    p4 == PairingOutput::<E>::zero() &&
    p5 == PairingOutput::<E>::zero() &&
    p6 == E::pairing(d.lagrange_basis_commit.0[0], E::G2::generator())
}

pub fn encrypt<E: Pairing>(d: &Dealer<E>, ek: &EncKey<E>, msg: PairingOutput<E>, t: usize, e: usize, be: E::G1) -> Ciphertext<E> {
    let mut rng = thread_rng();
    let s: Vec<E::ScalarField> = (0..6).map(|_| E::ScalarField::rand(&mut rng)).collect();

    let ct1 = E::ScalarField::rand(&mut rng);

    let mut m = ct1.into_bigint().to_bytes_be();
    m.extend(e.to_be_bytes());
    let tag = utils::hash_g2::<E>(&m);

    let ct2 = (
        ek.c * s[0] + d.crs.0[t + 1] * s[3] + be * s[4] + E::G1::generator() * s[5],
        E::G2::generator() * s[0] + tag * s[2],
        ek.z * s[0],
        d.crs.1[1] * (s[0] + s[1]),
        E::G2::generator() * s[1],
        E::G1::generator() * s[2],
        E::G2::generator() * s[3],
        ek.z * s[4],
        (d.crs.1[1] - d.crs.1[0]) * s[5],
    );

    let ct3 = msg + E::pairing(d.lagrange_basis_commit.0[0], E::G2::generator()) * s[5];

    Ciphertext { ct1, ct2, ct3 }
}