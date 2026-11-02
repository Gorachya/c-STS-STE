use std::iter;

use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, ScalarMul, VariableBaseMSM, pairing::Pairing};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain, DenseUVPolynomial, univariate::DensePolynomial};
use ark_ff::{Field, batch_inversion};
use ark_std::{UniformRand, One, Zero};

use rand::thread_rng;

use crate::utils;

#[derive(Clone)]
pub struct Dealer<E: Pairing> {
    pub total_plus_1: E::ScalarField,
    pub crs: (Vec<E::G1Affine>, Vec<E::G2Affine>),
    pub lagrange_basis_commit: (Vec<E::G1Affine>, Vec<E::G2Affine>),
    pub w_domain: Vec<E::ScalarField>,
    pub z: E::G2,
}

pub struct Hints<E: Pairing> {
    pub id: usize,
    pub h1: E::G1Affine,
    pub h2: E::G1Affine,
    pub h3: E::G1Affine,
    pub h4: E::G1Affine,
    pub h5: Vec<E::G1>,
    pub proof: utils::EqDlProof<E::ScalarField>,
}

pub struct AggrKey<E: Pairing> {
    pub v: Vec<bool>,
    pub ak1: Vec<E::G1Affine>,
    pub ak2: Vec<E::G1Affine>,
    pub ak35: Vec<E::G1Affine>,
    pub ak4: Vec<E::G1Affine>,
}

pub struct EncKey<E: Pairing> {
    pub c: E::G1,
    pub z: E::G2,
}

#[derive(Clone)]
pub struct Trapdoor<E: Pairing> {
    pub total_plus_1: E::ScalarField,
    pub powers_of_tau: Vec<E::ScalarField>,
    pub lagrange_basis_tau: Vec<E::ScalarField>,
}

pub fn hint_verify<E: Pairing>(dealer: &Dealer<E>, pk: E::G1Affine, hint: &Hints<E>) -> bool {
    let id = hint.id;
    let n = dealer.w_domain.len();
    if id >= n {
        return false;
    }

    let inv_n = dealer.total_plus_1.inverse().unwrap();
    let wi_inv = dealer.w_domain[(n - id) % n];
    let li_coeffs: Vec<E::ScalarField> = std::iter::successors(Some(inv_n), |p| Some(*p * wi_inv))
        .take(n)
        .collect();
    let li = DensePolynomial::from_coefficients_vec(li_coeffs);
    let li_commit_g1 = dealer.lagrange_basis_commit.0[id].into_group();
    let li_commit_g2 = dealer.lagrange_basis_commit.1[id].into_group();

    let eq_ok = utils::eq_dl_verify(
        E::G1::generator(),
        pk.into_group(),
        li_commit_g1,
        hint.h1.into_group(),
        hint.proof,
    );
    if !eq_ok {
        return false;
    }

    let mut li_minus_constant_coeffs = li.coeffs.clone();
    li_minus_constant_coeffs[0] -= inv_n;
    let li_minus_constant = DensePolynomial::from_coefficients_vec(li_minus_constant_coeffs);

    let li_div_x_coeffs = li_minus_constant.coeffs.iter().skip(1).copied().collect();
    let li_div_x = DensePolynomial::from_coefficients_vec(li_div_x_coeffs);

    let mut zx_coeffs = vec![E::ScalarField::zero(); n + 1];
    zx_coeffs[0] = -E::ScalarField::ONE;
    zx_coeffs[n] = E::ScalarField::ONE;
    let zx = DensePolynomial::from_coefficients_vec(zx_coeffs);
    let li_squared_minus_li_div_zx = (&li * &li - &li) / &zx;

    let random = E::ScalarField::rand(&mut thread_rng());
    let random_powers: Vec<E::ScalarField> =
        std::iter::successors(Some(E::ScalarField::ONE), |power| Some(*power * random))
            .take(n + 3)
            .collect();
    let mut hint_bases = vec![hint.h1];
    hint_bases.push(hint.h2);
    hint_bases.push(hint.h3);
    hint_bases.push(hint.h4);
    let mut commitment_bases = vec![li_commit_g2.into_affine()];
    commitment_bases.push(commit_g2(dealer, &li_minus_constant).into_affine());
    commitment_bases.push(commit_g2(dealer, &li_squared_minus_li_div_zx).into_affine());
    commitment_bases.push(commit_g2(dealer, &li_div_x).into_affine());

    for j in 0..n {
        if j == id {
            continue;
        }
        let wj_inv = dealer.w_domain[(n - j) % n];
        let lj_coeffs: Vec<E::ScalarField> = std::iter::successors(Some(inv_n), |p| Some(*p * wj_inv))
            .take(n)
            .collect();
        let lj = DensePolynomial::from_coefficients_vec(lj_coeffs);
        let lilj_div_zx = (&li * &lj) / &zx;
        let commitment = commit_g2(dealer, &lilj_div_zx).into_affine();
        hint_bases.push(hint.h5[j].into_affine());
        commitment_bases.push(commitment);
    }

    let batched_hint =
        <E::G1 as VariableBaseMSM>::msm_unchecked(&hint_bases, &random_powers[..hint_bases.len()]);
    let batched_commitment = <E::G2 as VariableBaseMSM>::msm_unchecked(
        &commitment_bases,
        &random_powers[..commitment_bases.len()],
    );
    E::pairing(batched_hint, E::G2::generator()) == E::pairing(pk, batched_commitment)
}

fn commit_g2<E: Pairing>(dealer: &Dealer<E>, polynomial: &DensePolynomial<E::ScalarField>) -> E::G2 {
    <E::G2 as VariableBaseMSM>::msm_unchecked(&dealer.crs.1, &polynomial.coeffs)
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
        let w_domain_elements: Vec<E::ScalarField> = w_domain.elements().collect();
        let mut lagrange_denominators: Vec<E::ScalarField> = w_domain_elements
            .iter()
            .map(|&w| tau - w)
            .collect();
        batch_inversion(&mut lagrange_denominators);
        let lagrange_basis_tau: Vec<E::ScalarField> = w_domain_elements
            .iter()
            .zip(lagrange_denominators.iter())
            .map(|(&w, &inverse)| w * inverse * const0)
            .collect();

        (
            Self {
                total_plus_1,
                crs: (g.batch_mul(&powers_of_tau), h.batch_mul(&powers_of_tau)),
                lagrange_basis_commit: (g.batch_mul(&lagrange_basis_tau), h.batch_mul(&lagrange_basis_tau)),
                w_domain: w_domain_elements,
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
    pub fn preprocess(&self, pks: &Vec<E::G1Affine>, hints: &Vec<Hints<E>>, v: &Vec<bool>) -> (AggrKey<E>, EncKey<E>) {
        assert_eq!(pks.len(), hints.len());
        assert_eq!(pks.len(), v.len());
        let n = hints[0].h5.len();
        let mut ak5 = vec![E::G1::zero(); n];
        for i in 0..n {
            if !v[i] {
                continue;
            }
            for j in 0..n {
                if i == j { continue; }
                ak5[j] += hints[i].h5[j];
            }
        }

        (
            AggrKey {
                v: v.clone(),
                ak1: pks.clone(),
                ak2: hints.iter().zip(v.iter()).map(|(hint, &valid)| if valid { hint.h2 } else { E::G1Affine::zero() }).collect(),
                ak35: (0..n).map(|i| {
                    if !v[i] {
                        E::G1Affine::zero()
                    } else {
                        (hints[i].h3.into_group() + ak5[i]).into_affine()
                    }
                }).collect(),
                ak4: hints.iter().zip(v.iter()).map(|(hint, &valid)| if valid { hint.h4 } else { E::G1Affine::zero() }).collect(),
            },
            EncKey {
                c: hints.iter().zip(v.iter()).filter(|(_, valid)| **valid).map(|(hint, _)| hint.h1).sum(),
                z: self.z,
            }
        )
    }

    // O(N) preprocess instead of O(N^2) via the trapdoor, for simplicity
    // Note: This function cannot be used in practice, because the trapdoor should not be available after system setup
    // Instead, we should use the result of hint_gen_lagrange from each member and perform the O(N^2) preprocess
    // We use this function only for simplicity in the endtoend example, which focuses on the efficiency of aggregation
    // and we benchmark the efficiency of hint generation and preprocess in hints.rs and preprocess.rs, respectively
    pub fn preprocess_trapdoor(&self, pks: &Vec<E::G1Affine>, td: &Trapdoor<E>) -> (AggrKey<E>, EncKey<E>) {
        let n = pks.len();
        let li_0 = td.total_plus_1.inverse().unwrap();
        let z_tau = td.powers_of_tau[td.powers_of_tau.len()-1] - E::ScalarField::ONE; // tau^(N+1)-1

        let c: <E as Pairing>::G1 = (0..n).map(|i| pks[i] * td.lagrange_basis_tau[i]).sum();

        (
            AggrKey {
                v: vec![true; n],
                ak1: pks.clone(),
                ak2: (0..n).map(|i| (pks[i] * (td.lagrange_basis_tau[i] - li_0)).into_affine()).collect(),
                ak35: (0..n).map(|i| {
                    let qz3 = pks[i] * ((td.lagrange_basis_tau[i] * td.lagrange_basis_tau[i] - td.lagrange_basis_tau[i]) / z_tau);
                    let qz5 = (c - pks[i] * td.lagrange_basis_tau[i]) * (td.lagrange_basis_tau[i] / z_tau);
                    (qz3 + qz5).into_affine()
                }).collect(),
                ak4: (0..n).map(|i| (pks[i] * ((td.lagrange_basis_tau[i] - li_0) / td.powers_of_tau[1])).into_affine()).collect(),
            },
            EncKey {
                c,
                z: self.z,
            }
        )
    }
}
