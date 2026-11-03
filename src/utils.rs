use ark_ec::{hashing::HashToCurve, CurveGroup, pairing::Pairing};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug)]
pub struct EqDlProof<F: PrimeField> {
    pub challenge: F,
    pub response: F,
}

fn append_serialized(buffer: &mut Vec<u8>, value: &impl CanonicalSerialize) {
    let mut bytes = Vec::new();
    value.serialize_uncompressed(&mut bytes).expect("group element serialization failed");
    buffer.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buffer.extend_from_slice(&bytes);
}

fn eq_dl_challenge<F, G1, G2>(a: &G1, x: &G1, b: &G2, y: &G2, alpha: &G1, beta: &G2) -> F
where
    F: PrimeField,
    G1: CurveGroup<ScalarField = F>,
    G1::Affine: CanonicalSerialize,
    G2: CurveGroup<ScalarField = F>,
    G2::Affine: CanonicalSerialize,
{
    let mut transcript = b"CSTE_EQ_DL_V1".to_vec();
    let mut g1_points = [a.clone(), x.clone(), alpha.clone()];
    let mut g2_points = [b.clone(), y.clone(), beta.clone()];
    let g1_affine = G1::normalize_batch(&mut g1_points);
    let g2_affine = G2::normalize_batch(&mut g2_points);
    append_serialized(&mut transcript, &g1_affine[0]);
    append_serialized(&mut transcript, &g1_affine[1]);
    append_serialized(&mut transcript, &g2_affine[0]);
    append_serialized(&mut transcript, &g2_affine[1]);
    append_serialized(&mut transcript, &g1_affine[2]);
    append_serialized(&mut transcript, &g2_affine[2]);
    F::from_le_bytes_mod_order(&Sha256::digest(transcript))
}

pub fn eq_dl_prove<F, G1, G2>(a: G1, x: G1, b: G2, y: G2, secret: F) -> EqDlProof<F>
where
    F: PrimeField,
    G1: CurveGroup<ScalarField = F>,
    G1::Affine: CanonicalSerialize,
    G2: CurveGroup<ScalarField = F>,
    G2::Affine: CanonicalSerialize,
{
    let randomness = F::rand(&mut rand::thread_rng());
    let alpha = a * randomness;
    let beta = b * randomness;
    let challenge = eq_dl_challenge(&a, &x, &b, &y, &alpha, &beta);
    EqDlProof {
        challenge,
        response: randomness + challenge * secret,
    }
}

pub fn eq_dl_verify<F, G1, G2>(a: G1, x: G1, b: G2, y: G2, proof: EqDlProof<F>) -> bool
where
    F: PrimeField,
    G1: CurveGroup<ScalarField = F>,
    G1::Affine: CanonicalSerialize,
    G2: CurveGroup<ScalarField = F>,
    G2::Affine: CanonicalSerialize,
{
    let alpha = a * proof.response - x * proof.challenge;
    let beta = b * proof.response - y * proof.challenge;
    proof.challenge == eq_dl_challenge(&a, &x, &b, &y, &alpha, &beta)
}

pub fn hash_g2<E, H>(m: &[u8], hasher: &H) -> E::G2
where
    E: Pairing,
    H: HashToCurve<E::G2>,
{
    hasher.hash(m).expect("failed to hash message to G2").into()
}

pub fn is_a_power_of_two(n: usize) -> bool {
    let mut x = 1;
    while x < n { x *= 2; }
    x == n
}

// Divide-and-conquer is significantly faster than multiply by order
fn poly_on_points_zero_fast<F: PrimeField>(
    points: &Vec<F>, l: usize, r: usize, start: F,
    direct_convolution_threshold: usize,
) -> DensePolynomial<F> {
    if r - l + 1 <= direct_convolution_threshold {
        let segment_start = if l == 0 { start } else { F::ONE };
        let mut coefficients = vec![-points[l] * segment_start, segment_start];
        for point in &points[l + 1..=r] {
            let degree = coefficients.len();
            let trailing = coefficients[degree - 1];
            coefficients.push(F::ZERO);
            for i in (1..degree).rev() {
                coefficients[i] = coefficients[i] * -*point + coefficients[i - 1];
            }
            coefficients[0] = coefficients[0] * -*point;
            coefficients[degree] = trailing;
        }
        return DensePolynomial::from_coefficients_vec(coefficients);
    }

    if l == r {
        if l == 0 { return DensePolynomial::from_coefficients_vec(vec![-points[l] * start, start]); }
        else { return DensePolynomial::from_coefficients_vec(vec![-points[l], F::ONE]); }
    }
    let m = (l + r) >> 1;
    let lp = poly_on_points_zero_fast(points, l, m, start, direct_convolution_threshold);
    let rp = poly_on_points_zero_fast(points, m+1, r, start, direct_convolution_threshold);
    &lp * &rp
}

pub fn poly_product_threshold() -> usize {
    std::env::var("CSTE_POLY_THRESHOLD")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value: &usize| *value > 0)
        .unwrap_or(64)
}

// start * prod (x-p) for p in points
pub fn poly_on_points_zero<F: PrimeField>(points: &Vec<F>, start: F) -> DensePolynomial<F> {
    if points.is_empty() {
        return DensePolynomial::from_coefficients_vec(vec![start]);
    }
    poly_on_points_zero_fast(
        points,
        0,
        points.len() - 1,
        start,
        poly_product_threshold(),
    )
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_bls12_381::g2::Config as G2Config;
    use ark_ec::hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve};
    use ark_ff::fields::field_hashers::DefaultFieldHasher;
    use ark_ff::Zero;
    use ark_poly::Polynomial;
    use sha2::Sha256;

    use super::{hash_g2, poly_on_points_zero};

    #[test]
    fn empty_points_produce_constant_polynomial() {
        let polynomial = poly_on_points_zero::<Fr>(&Vec::new(), Fr::from(3u64));

        assert_eq!(polynomial.evaluate(&Fr::from(10u64)), Fr::from(3u64));
    }

    #[test]
    fn polynomial_product_matches_evaluation_across_direct_threshold() {
        let points = (1u64..=100).map(Fr::from).collect();
        let start = Fr::from(7u64);
        let polynomial = poly_on_points_zero::<Fr>(&points, start);

        for x in [Fr::from(0u64), Fr::from(3u64), Fr::from(101u64)] {
            let expected = (1u64..=100).fold(start, |value, point| {
                value * (x - Fr::from(point))
            });
            assert_eq!(polynomial.evaluate(&x), expected);
        }
    }

    #[test]
    fn hash_to_g2_is_deterministic_and_nonzero() {
        type G2Hasher = MapToCurveBasedHasher<
            <Bls12_381 as ark_ec::pairing::Pairing>::G2,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<G2Config>,
        >;
        let hasher = G2Hasher::new(b"CSTE_BLS12381_G2_V1_TEST")
            .expect("invalid hash-to-G2 parameters");
        let first = hash_g2::<Bls12_381, _>(b"c-ste hash test", &hasher);
        let second = hash_g2::<Bls12_381, _>(b"c-ste hash test", &hasher);

        assert_eq!(first, second);
        assert!(!first.is_zero());
    }
}