use std::iter;

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM, pairing::Pairing, PrimeGroup};
use ark_ff::{FftField, Field};
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain, univariate::DensePolynomial};
use ark_std::Zero;

use crate::{bls::BLSKey, dealer::{Dealer, Hints}, utils};

pub struct Member<E: Pairing> {
    pub id: usize,
    pub key: BLSKey<E>,
}

impl<E: Pairing> Member<E> {
    pub fn new(id: usize) -> Self {
        if id == 0 {
            return Self {
                id,
                key: BLSKey::<E>::new_dummy_party(),
            }
        }
        Self {
            id,
            key: BLSKey::<E>::new(),
        }
    }

    // Naive O(N * msm(N)) hint generation without access to [L_i(tau)]
    // Not used
    pub fn hint_gen_naive(&self, d: &Dealer<E>) -> Hints<E> {
        let n = d.w_domain.len();
        let inv_n = d.total_plus_1.inverse().unwrap();
        let wi_inv = d.w_domain[(n - self.id) % n];

        // Z(x) = x^n - 1
        let mut zx_coeffs = vec![E::ScalarField::zero(); n + 1];
        zx_coeffs[0] = -E::ScalarField::ONE;
        zx_coeffs[n] = E::ScalarField::ONE;
        let zx = DensePolynomial::from_coefficients_vec(zx_coeffs);

        // L_i(x) = w^i/n * (x^n-1)/(x-w^i)
        //        = 1/n * [x^(n-1)(w^i) + x^(n-2)(w^i)^2 + ... + x(w^i)^(n-1) + (w^i)^n]
        let lag_coeffs: Vec<E::ScalarField> = iter::successors(Some(inv_n), |p| Some(*p * wi_inv)).take(n).collect();
        let li_x = DensePolynomial::from_coefficients_vec(lag_coeffs.clone());
        let li_tau = <E::G1 as VariableBaseMSM>::msm_unchecked(&d.crs.0, &lag_coeffs);

        let h1 = self.key.mul_sk(li_tau);
        let h2 = h1 - self.key.mul_sk(d.crs.0[0] * inv_n);
        
        let h3_x = (&li_x * &li_x - &li_x) / &zx;
        let h3 = self.key.mul_sk(<E::G1 as VariableBaseMSM>::msm_unchecked(&d.crs.0, &h3_x.coeffs));

        let h4 = self.key.mul_sk(<E::G1 as VariableBaseMSM>::msm_unchecked(&d.crs.0, &lag_coeffs[1..]));

        let h5 = (0..n).map(
            |j| {
                let wj_inv = d.w_domain[(n - j) % n];
                let lag_coeffs_j: Vec<E::ScalarField> = iter::successors(Some(inv_n), |p| Some(*p * wj_inv)).take(n).collect();
                let lj_x = DensePolynomial::from_coefficients_vec(lag_coeffs_j);
                let lilj_x = (&li_x * &lj_x) / &zx;
                self.key.mul_sk(<E::G1 as VariableBaseMSM>::msm_unchecked(&d.crs.0, &lilj_x.coeffs))
            }
        ).collect();

        Hints {
            id: self.id,
            h1: h1.into_affine(),
            h2: h2.into_affine(),
            h3: h3.into_affine(),
            h4: h4.into_affine(),
            h5,
            proof: utils::eq_dl_prove(
                E::G1::generator(),
                self.key.pk,
                li_tau,
                h1,
                self.key.sk,
            ),
        }
    }

    // Optimized O(N) hint generation with access to [L_i(tau)]
    // We assume that the dealer has already computed [L_i(tau)]
    pub fn hint_gen_lagrange(&self, d: &Dealer<E>) -> Hints<E> {
        let li_tau = d.lagrange_basis_commit.0[self.id].into_group();
        let inv_total_plus_one = d.total_plus_1.inverse().unwrap();
        let li_0 = E::G1::generator() * inv_total_plus_one;
        let wi = d.w_domain[self.id];
        let n = d.w_domain.len();

        // h1 = [sk * L_i(tau)]_1
        let h1 = self.key.mul_sk(li_tau);

        // h2 = [sk * (L_i(tau)-L_i(0))]_1, and L_i(0) = 1/(N+1) for all i
        let h2 = h1 - self.key.mul_sk(li_0);

        // h5 = [sk * L_i(tau)*L_j(tau)/Z(tau)]_1 for all j
        let cons = -li_tau * inv_total_plus_one;
        let h5: Vec<E::G1> = (0..n).map(
            |j| {
                let wj = d.w_domain[j];
                if j != self.id {
                    self.key.mul_sk(cons + (d.lagrange_basis_commit.0[j] - d.lagrange_basis_commit.0[self.id]) * (wi / (wj-wi) * inv_total_plus_one))
                } else {
                    E::G1::zero()
                }
            }
        ).collect();

        // h3 = [sk * (L_i^2(tau)-L_i(tau))/Z(tau)]_1
        let h3 = -h5.iter().sum::<E::G1>();

        // h4 = [sk * (L_i(tau)-L_i(0))/tau]_1
        let h4 = self.key.mul_sk(
            {
                let q1 = li_tau * d.w_domain[(n-self.id)%n];
                let q2 = d.crs.0[d.crs.0.len()-2] * inv_total_plus_one;
                q1 - q2
            }
        );

        Hints {
            id: self.id,
            h1: h1.into_affine(),
            h2: h2.into_affine(),
            h3: h3.into_affine(),
            h4: h4.into_affine(),
            h5,
            proof: utils::eq_dl_prove(
                E::G1::generator(),
                self.key.pk,
                li_tau,
                h1,
                self.key.sk,
            ),
        }
    }
}

pub fn lagrange_poly<F: FftField>(n: usize, i: usize) -> DensePolynomial<F> {
    assert!(n > 0 && n.is_power_of_two(), "n must be a positive power of two");
    assert!(i < n, "lagrange polynomial index must be less than n");

    let mut evals = vec![];
    for j in 0..n {
        let l_of_x: u64 = if i == j { 1 } else { 0 };
        evals.push(F::from(l_of_x));
    }

    // powers of nth root of unity
    let domain = Radix2EvaluationDomain::<F>::new(n)
        .expect("field does not support a radix-2 evaluation domain of the requested size");
    assert_eq!(domain.size(), n, "evaluation domain size must equal n");
    let eval_form = Evaluations::from_vec_and_domain(evals, domain);
    // interpolated polynomial over the n points
    eval_form.interpolate()
}