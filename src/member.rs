use std::iter;

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM, pairing::Pairing, PrimeGroup};
use ark_ff::{FftField, Field, batch_inversion};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain, univariate::DensePolynomial};
use ark_std::Zero;

use crate::{bls::BLSKey, dealer::{Dealer, Hints}, utils};

fn product_quotient_by_xn_minus_one<F: Field>(lhs: &[F], rhs: &[F], n: usize) -> Vec<F> {
    assert!(n > 0);

    // If (x^n - 1) divides lhs * rhs, then
    // Q(x) = (lhs * rhs) / (x^n - 1).
    // Comparing coefficients gives q_k = coefficient[x^(n+k)] of lhs * rhs.
    let mut quotient = (0..n - 1).map(|k| {
        let degree = n + k;
        let mut coefficient = F::ZERO;
        let first = degree.saturating_sub(rhs.len().saturating_sub(1));
        let last = degree.min(lhs.len().saturating_sub(1));
        for i in first..=last {
            let j = degree - i;
            if j < rhs.len() {
                coefficient += lhs[i] * rhs[j];
            }
        }
        coefficient
    }).collect::<Vec<_>>();
    while quotient.last().is_some_and(|coefficient| coefficient.is_zero()) {
        quotient.pop();
    }
    quotient
}

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

        // L_i(x) = w^i/n * (x^n-1)/(x-w^i)
        //        = 1/n * [x^(n-1)(w^i) + x^(n-2)(w^i)^2 + ... + x(w^i)^(n-1) + (w^i)^n]
        let lag_coeffs: Vec<E::ScalarField> = iter::successors(Some(inv_n), |p| Some(*p * wi_inv)).take(n).collect();
        let li_tau = <E::G1 as VariableBaseMSM>::msm_unchecked(&d.crs.0, &lag_coeffs);

        let h1 = self.key.mul_sk(li_tau);
        let h2 = h1 - self.key.mul_sk(d.crs.0[0] * inv_n);
        
        let h3_coeffs = product_quotient_by_xn_minus_one(&lag_coeffs, &lag_coeffs, n);
        let h3 = self.key.mul_sk(<E::G1 as VariableBaseMSM>::msm_unchecked(&d.crs.0, &h3_coeffs));

        let h4 = self.key.mul_sk(<E::G1 as VariableBaseMSM>::msm_unchecked(&d.crs.0, &lag_coeffs[1..]));

        let h5 = (0..n).map(
            |j| {
                let wj_inv = d.w_domain[(n - j) % n];
                let lag_coeffs_j: Vec<E::ScalarField> = iter::successors(Some(inv_n), |p| Some(*p * wj_inv)).take(n).collect();
                if j == self.id {
                    return h3;
                }
                let lilj_coeffs = product_quotient_by_xn_minus_one(&lag_coeffs, &lag_coeffs_j, n);
                self.key.mul_sk(<E::G1 as VariableBaseMSM>::msm_unchecked(&d.crs.0, &lilj_coeffs))
            }
        ).collect();

        let mut hint_affine = vec![h1, h2, h3, h4];
        let hint_affine = E::G1::normalize_batch(&mut hint_affine);

        Hints {
            id: self.id,
            h1: hint_affine[0],
            h2: hint_affine[1],
            h3: hint_affine[2],
            h4: hint_affine[3],
            h5,
            proof: utils::eq_dl_prove(
                E::G1::generator(),
                self.key.pk,
                li_tau,
                hint_affine[0].into_group(),
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
        let cons = -h1 * inv_total_plus_one;
        let mut differences: Vec<E::ScalarField> = (0..n)
            .filter(|&j| j != self.id)
            .map(|j| d.w_domain[j] - wi)
            .collect();
        batch_inversion(&mut differences);
        let mut inverse_index = 0;
        let wi_over_inv_total_plus_one = self.key.sk * wi * inv_total_plus_one;
        let h5: Vec<E::G1> = (0..n).map(
            |j| {
                if j != self.id {
                    let difference = differences[inverse_index];
                    inverse_index += 1;
                    cons + (d.lagrange_basis_commit.0[j] - d.lagrange_basis_commit.0[self.id]) * (wi_over_inv_total_plus_one * difference)
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

        let mut hint_affine = vec![h1, h2, h3, h4];
        let hint_affine = E::G1::normalize_batch(&mut hint_affine);

        Hints {
            id: self.id,
            h1: hint_affine[0],
            h2: hint_affine[1],
            h3: hint_affine[2],
            h4: hint_affine[3],
            h5,
            proof: utils::eq_dl_prove(
                E::G1::generator(),
                self.key.pk,
                li_tau,
                hint_affine[0].into_group(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_poly::DenseUVPolynomial;
    use std::ops::Div;

    #[test]
    fn xn_minus_one_product_quotient_matches_dense_division() {
        let lhs = DensePolynomial::from_coefficients_slice(&[
            Fr::from(1u64),
            Fr::from(1u64),
            Fr::from(1u64),
        ]);
        let rhs = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-1i64),
            Fr::from(1u64),
        ]);
        let divisor = DensePolynomial::from_coefficients_vec(vec![
            Fr::from(-1i64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(1u64),
        ]);

        let optimized = product_quotient_by_xn_minus_one(&lhs.coeffs, &rhs.coeffs, 3);
        let expected = (&lhs * &rhs).div(&divisor);

        assert_eq!(optimized, expected.coeffs);
    }
}