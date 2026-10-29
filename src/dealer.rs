use std::iter;

use ark_ec::{CurveGroup, PrimeGroup, ScalarMul, pairing::Pairing};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_ff::Field;
use ark_std::{UniformRand, One, Zero};

use rand::thread_rng;

use crate::utils;

pub struct Dealer<E: Pairing> {
    pub total_plus_1: E::ScalarField,
    pub crs: (Vec<E::G1Affine>, Vec<E::G2Affine>),
    pub lagrange_basis_commit: (Vec<E::G1Affine>, Vec<E::G2Affine>),
    pub w_domain: Vec<E::ScalarField>,
    pub z: E::G2,
}

pub struct Hints<E: Pairing> {
    pub h1: E::G1Affine,
    pub h2: E::G1Affine,
    pub h3: E::G1Affine,
    pub h4: E::G1Affine,
    pub h5: Vec<E::G1>,
}

pub struct AggrKey<E: Pairing> {
    pub ak1: Vec<E::G1Affine>,
    pub ak2: Vec<E::G1Affine>,
    pub ak3: Vec<E::G1Affine>,
    pub ak4: Vec<E::G1Affine>,
    pub ak5: Vec<E::G1Affine>,
}

pub struct EncKey<E: Pairing> {
    pub c: E::G1,
    pub z: E::G2,
}

pub struct Trapdoor<E: Pairing> {
    pub total_plus_1: E::ScalarField,
    pub powers_of_tau: Vec<E::ScalarField>,
    pub lagrange_basis_tau: Vec<E::ScalarField>,
}

impl<E: Pairing> Dealer<E> {
    // We implement this trapdoor init function because the O(N^2) preprocess cannot be improved
    // And we focus on the efficiency of other steps
    pub fn init_fast(total: usize) -> (Self, Trapdoor<E>) {
        assert!(utils::is_a_power_of_two(total + 1));

        let mut rng = thread_rng();
        let tau = E::ScalarField::rand(&mut rng);
        let powers_of_tau: Vec<E::ScalarField> =
            iter::successors(Some(E::ScalarField::one()), |p| Some(*p * tau))
                .take(total + 2)
                .collect();

        let g = E::G1::generator();
        let h = E::G2::generator();

        // N + 1
        let total_plus_1 = E::ScalarField::from(total as u64 + 1);
        // tau^(N+1) - 1
        let tau_power_total_plus_1_minus_1 = powers_of_tau[total + 1] - E::ScalarField::ONE;

        // L_i(X) = w^i/X-w^i * (X^(N+1)-1)/(N+1)
        let const0 = tau_power_total_plus_1_minus_1 / total_plus_1;
        let w_domain = Radix2EvaluationDomain::<E::ScalarField>::new(total + 1).unwrap();
        let lagrange_basis_tau: Vec<E::ScalarField> = w_domain.elements().map(|w| w/(tau-w)*const0).collect();

        (
            Self {
                total_plus_1,
                crs: (g.batch_mul(&powers_of_tau), h.batch_mul(&powers_of_tau)),
                lagrange_basis_commit: (g.batch_mul(&lagrange_basis_tau), h.batch_mul(&lagrange_basis_tau)),
                w_domain: w_domain.elements().collect(),
                z: E::G2::generator() * tau_power_total_plus_1_minus_1,
            },
            Trapdoor {
                total_plus_1,
                powers_of_tau,
                lagrange_basis_tau,
            }
        )
    }

    // The standard O(N^2) preprocess; should not be used in practice without parallelization
    pub fn preprocess(&self, pks: &Vec<E::G1Affine>, hints: &Vec<Hints<E>>) -> (AggrKey<E>, EncKey<E>) {
        let n = hints[0].h5.len();
        let mut ak5 = vec![E::G1::zero(); n];
        for i in 0..n {
            for j in 0..n {
                if i == j { continue; }
                ak5[j] += hints[i].h5[j];
            }
        }

        (
            AggrKey {
                ak1: pks.clone(),
                ak2: hints.iter().map(|hint| hint.h2).collect(),
                ak3: hints.iter().map(|hint| hint.h3).collect(),
                ak4: hints.iter().map(|hint| hint.h4).collect(),
                ak5: ak5.iter().map(|x| x.into_affine()).collect(),
            },
            EncKey {
                c: hints.iter().map(|hint| hint.h1).sum(),
                z: self.z,
            }
        )
    }

    // O(N) preprocess instead of O(N^2) via the trapdoor, for simplicity
    // Note: This function cannot be used in practice, because the trapdoor should not be available after system setup
    // Instead, we should use the result of hint_gen_lagrange from each member and preform the O(N^2) preprocess
    // We use this function only for simplicity in the endtoend example, which focuses on the efficiency of aggregation
    // and we benchmark the efficiency of hint generation and preprocess in hints.rs and preprocess.rs, respectively
    pub fn preprocess_trapdoor(&self, pks: &Vec<E::G1Affine>, td: &Trapdoor<E>) -> (AggrKey<E>, EncKey<E>) {
        let n = pks.len();
        let li_0 = td.total_plus_1.inverse().unwrap();
        let z_tau = td.powers_of_tau[td.powers_of_tau.len()-1] - E::ScalarField::ONE; // tau^(N+1)-1

        let c: <E as Pairing>::G1 = (0..n).map(|i| pks[i] * td.lagrange_basis_tau[i]).sum();

        (
            AggrKey {
                ak1: pks.clone(),
                ak2: (0..n).map(|i| (pks[i] * (td.lagrange_basis_tau[i] - li_0)).into_affine()).collect(),
                ak3: (0..n).map(|i| (pks[i] * ((td.lagrange_basis_tau[i] * td.lagrange_basis_tau[i] - td.lagrange_basis_tau[i]) / z_tau)).into_affine()).collect(),
                ak4: (0..n).map(|i| (pks[i] * ((td.lagrange_basis_tau[i] - li_0) / td.powers_of_tau[1])).into_affine()).collect(),
                ak5: (0..n).map(|i| ((c - pks[i] * td.lagrange_basis_tau[i]) * (td.lagrange_basis_tau[i] / z_tau)).into_affine()).collect(),
            },
            EncKey {
                c,
                z: self.z,
            }
        )
    }
}
