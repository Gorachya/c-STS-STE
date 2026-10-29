use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_ff::PrimeField;

use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
use sha2::{Digest, Sha256};

// TODO: formal hash to point
pub fn hash_g2<E: Pairing>(m: &Vec<u8>) -> E::G2 {
    let hash = Sha256::digest(&m);
    let r = E::ScalarField::from_le_bytes_mod_order(&hash);

    E::G2::generator() * r
}

pub fn is_a_power_of_two(n: usize) -> bool {
    let mut x = 1;
    while x < n { x *= 2; }
    x == n
}

// Divide-and-conquer is significantly faster than multiply by order
fn poly_on_points_zero_fast<F: PrimeField>(points: &Vec<F>, l: usize, r: usize, start: F) -> DensePolynomial<F> {
    if l == r {
        if l == 0 { return DensePolynomial::from_coefficients_vec(vec![-points[l] * start, start]); }
        else { return DensePolynomial::from_coefficients_vec(vec![-points[l], F::ONE]); }
    }
    let m = (l + r) >> 1;
    let lp = poly_on_points_zero_fast(points, l, m, start);
    let rp = poly_on_points_zero_fast(points, m+1, r, start);
    &lp * &rp
}

// start * prod (x-p) for p in points
pub fn poly_on_points_zero<F: PrimeField>(points: &Vec<F>, start: F) -> DensePolynomial<F> {
    poly_on_points_zero_fast(points, 0, points.len()-1, start)
}