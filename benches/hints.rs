use std::hint::black_box;

use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM, pairing::Pairing};
use ark_ff::Field;
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
use ark_std::UniformRand;
use c_ste::{
    dealer::{Dealer, Hints},
    member::Member,
};
use criterion::{Criterion, criterion_group, criterion_main};
use rand::thread_rng;

type E = ark_bls12_381::Bls12_381;

struct PreparedHintVerification<E: Pairing> {
    li_commitment: E::G2Affine,
    li_minus_constant_commitment: E::G2Affine,
    li_squared_minus_li_div_zx_commitment: E::G2Affine,
    li_div_x_commitment: E::G2Affine,
    cross_commitments: Vec<E::G2Affine>,
}

fn commit_g2<E: Pairing>(
    dealer: &Dealer<E>,
    polynomial: &DensePolynomial<E::ScalarField>,
) -> E::G2 {
    <E::G2 as VariableBaseMSM>::msm_unchecked(&dealer.crs.1, &polynomial.coeffs)
}

fn prepare_hint_verification<E: Pairing>(
    dealer: &Dealer<E>,
    _trapdoor: &c_ste::dealer::Trapdoor<E>,
    hint: &Hints<E>,
) -> PreparedHintVerification<E> {
    let id = hint.id;
    let n = dealer.w_domain.len();
    let inv_n = dealer.total_plus_1.inverse().unwrap();
    let wi_inv = dealer.w_domain[(n - id) % n];
    let li_coeffs: Vec<E::ScalarField> =
        std::iter::successors(Some(inv_n), |power| Some(*power * wi_inv))
            .take(n)
            .collect();
    let li_commitment = dealer.lagrange_basis_commit.1[id].into_group();
    let li_minus_constant_commitment =
        li_commitment - E::G2::generator() * inv_n;

    let mut cross_commitments = Vec::with_capacity(n);
    for j in 0..n {
        if j == id {
            cross_commitments.push(E::G2Affine::zero());
            continue;
        }
        let lj_commitment = dealer.lagrange_basis_commit.1[j].into_group();
        let wi = dealer.w_domain[id];
        let wj = dealer.w_domain[j];
        let lilj_commitment =
            (-li_commitment + (lj_commitment - li_commitment) * (wi / (wj - wi))) * inv_n;
        cross_commitments.push(lilj_commitment.into_affine());
    }

    let li_div_x_coeffs = li_coeffs.iter().skip(1).copied().collect();
    let li_div_x = DensePolynomial::from_coefficients_vec(li_div_x_coeffs);
    let li_div_x_commitment = commit_g2(dealer, &li_div_x).into_affine();
    let cross_commitment_sum = cross_commitments
        .iter()
        .filter(|commitment| !commitment.is_zero())
        .map(|commitment| commitment.into_group())
        .sum::<E::G2>();
    let li_squared_minus_li_commitment = (-cross_commitment_sum).into_affine();

    PreparedHintVerification {
        li_commitment: li_commitment.into_affine(),
        li_minus_constant_commitment: li_minus_constant_commitment.into_affine(),
        li_squared_minus_li_div_zx_commitment: li_squared_minus_li_commitment,
        li_div_x_commitment: li_div_x_commitment,
        cross_commitments,
    }
}

fn hint_verify_preprocessed<E: Pairing>(
    dealer: &Dealer<E>,
    pk: E::G1Affine,
    hint: &Hints<E>,
    prepared: &PreparedHintVerification<E>,
) -> bool {
    let id = hint.id;
    let n = dealer.w_domain.len();
    let li_commit_g1 = dealer.lagrange_basis_commit.0[id].into_group();

    let eq_ok = c_ste::utils::eq_dl_verify(
        E::G1::generator(),
        pk.into_group(),
        li_commit_g1,
        hint.h1.into_group(),
        hint.proof,
    );
    if !eq_ok {
        return false;
    }

    let random = E::ScalarField::rand(&mut thread_rng());
    let random_powers: Vec<E::ScalarField> =
        std::iter::successors(Some(E::ScalarField::ONE), |power| Some(*power * random))
            .take(n + 3)
            .collect();

    let mut hint_bases = vec![hint.h1, hint.h2, hint.h3, hint.h4];
    let mut commitment_bases = vec![
        prepared.li_commitment,
        prepared.li_minus_constant_commitment,
        prepared.li_squared_minus_li_div_zx_commitment,
        prepared.li_div_x_commitment,
    ];
    for j in 0..n {
        if j == id {
            continue;
        }
        hint_bases.push(hint.h5[j].into_affine());
        commitment_bases.push(prepared.cross_commitments[j]);
    }

    let batched_hint =
        <E::G1 as VariableBaseMSM>::msm_unchecked(&hint_bases, &random_powers[..hint_bases.len()]);
    let batched_commitment = <E::G2 as VariableBaseMSM>::msm_unchecked(
        &commitment_bases,
        &random_powers[..commitment_bases.len()],
    );
    E::pairing(batched_hint, E::G2::generator()) == E::pairing(pk, batched_commitment)
}

fn bench_hints(c: &mut Criterion) {
    let mut group = c.benchmark_group("single hint generation time");
    group.sample_size(10);

    let (k_end, naive_k_max) = match std::env::var("CSTE_BENCH_MODE").ok().as_deref() {
        Some("fast") => (14, 8),
        _ => (20, 10),
    };
    for k in (6..=k_end).step_by(2) {
        let n = 1 << k;
        let (d, _) = Dealer::<E>::init_fast(n - 1);
        let members: Vec<Member<E>> = (0..n).map(|id| Member::<E>::new(id)).collect();
        
        // hint generation in dyna-hints:
        // O(N) * msm_1(N)
        // Do not recommended for N > 2^10; should not run for N > 2^13
        if k <= naive_k_max {
            group.bench_function(format!("generate hint naive n = {}", n), |b| {
                b.iter(|| {
                    let hint = members[3].hint_gen_naive(&d);
                    let _ = black_box(hint);
                });
            });
        }
        
        // hint generation in c-sts and c-ste:
        // N+3 G1 mul, 3N+1 G1 add
        group.bench_function(format!("generate hint fast n = {}", n), |b| {
            b.iter(|| {
                let hint = members[3].hint_gen_lagrange(&d);
                let _ = black_box(hint);
            });
        });

    }

    group.finish();

    let mut verification_group = c.benchmark_group("single hint verification time");
    verification_group.sample_size(10);
    let k_end = match std::env::var("CSTE_BENCH_MODE").ok().as_deref() {
        Some("fast") => 12,
        _ => 20,
    };
    for k in (6..=k_end).step_by(2) {
        let n = 1 << k;
        let (d, trapdoor) = Dealer::<E>::init_fast(n - 1);
        let members: Vec<Member<E>> = (0..n).map(|id| Member::<E>::new(id)).collect();
        let hint = members[3].hint_gen_lagrange(&d);
        let pk = members[3].key.pk.into_affine();
        let prepared = prepare_hint_verification(&d, &trapdoor, &hint);
        verification_group.bench_function(format!("verify hint n = {}", n), |b| {
            b.iter(|| {
                let valid = hint_verify_preprocessed(&d, pk, &hint, &prepared);
                let _ = black_box(valid);
            });
        });
    }
    verification_group.finish();
}

criterion_group!(benches, bench_hints);
criterion_main!(benches);