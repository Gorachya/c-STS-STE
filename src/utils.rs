use ark_bls12_381::{Bls12_381, g2::Config as G2Config};
use ark_ec::{
    hashing::{
        curve_maps::wb::WBMap,
        map_to_curve_hasher::MapToCurveBasedHasher,
        HashToCurve,
    },
    pairing::Pairing,
};
use ark_ff::PrimeField;
use ark_ff::fields::field_hashers::DefaultFieldHasher;

use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
use sha2::Sha256;

const HASH_TO_G2_DOMAIN: &[u8] = b"CSTE_G2_V1";

pub trait HashToG2<E: Pairing> {
    fn hash_to_g2(message: &[u8]) -> E::G2;
}

impl HashToG2<Bls12_381> for Bls12_381 {
    fn hash_to_g2(message: &[u8]) -> <Bls12_381 as Pairing>::G2 {
        type G2Hasher = MapToCurveBasedHasher<
            <Bls12_381 as Pairing>::G2,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<G2Config>,
        >;

        let hasher = G2Hasher::new(HASH_TO_G2_DOMAIN).expect("invalid hash-to-G2 parameters");
        hasher.hash(message)
            .expect("failed to hash message to G2")
            .into()
    }
}

pub fn hash_g2<E: Pairing>(m: &[u8]) -> E::G2
where
    E: HashToG2<E>,
{
    E::hash_to_g2(m)
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
    if points.is_empty() {
        return DensePolynomial::from_coefficients_vec(vec![start]);
    }
    poly_on_points_zero_fast(points, 0, points.len()-1, start)
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::Zero;
    use ark_poly::Polynomial;

    use super::{hash_g2, poly_on_points_zero};

    #[test]
    fn empty_points_produce_constant_polynomial() {
        let polynomial = poly_on_points_zero::<Fr>(&Vec::new(), Fr::from(3u64));

        assert_eq!(polynomial.evaluate(&Fr::from(10u64)), Fr::from(3u64));
    }

    #[test]
    fn hash_to_g2_is_deterministic_and_nonzero() {
        let first = hash_g2::<Bls12_381>(b"c-ste hash test");
        let second = hash_g2::<Bls12_381>(b"c-ste hash test");

        assert_eq!(first, second);
        assert!(!first.is_zero());
    }
}