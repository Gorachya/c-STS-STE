use std::hint::black_box;

use ark_bls12_381::G1Affine;
use c_ste::utils;
use criterion::{Criterion, criterion_group, criterion_main};
use ark_ec::{CurveGroup, VariableBaseMSM, pairing::Pairing};
use ark_ff::Field;
use ark_std::UniformRand;

use rand::thread_rng;

type E = ark_bls12_381::Bls12_381;
type G1 = <E as Pairing>::G1;
type G2 = <E as Pairing>::G2;
type Fr = <E as Pairing>::ScalarField;

fn bench_epoch_repr(c: &mut Criterion) {
    let mut group = c.benchmark_group("epoch-repr time");

    let mut rng = thread_rng();
    for k in 7..12 {
        let n = 1 << k;
        let g1: Vec<G1Affine> = (0..n).map(|_| G1::rand(&mut rng).into_affine()).collect();
        let g2: Vec<G2> = (0..n).map(|_| G2::rand(&mut rng)).collect();
        let fr: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        // epoch repr in dyna-hints:
        // \sum L_i(tau) for i in Com
        // n G2 sum
        group.bench_function(format!("dyna-hints n = {}", n), |b| {
            b.iter(|| {
                let repr: G2 = g2.iter().sum();
                let _ = black_box(repr);
            });
        });

        // epoch repr in c-sts and c-ste:
        // b_com(X) = \prod (x-wi) for i in Com, compute b_com(tau)
        // n poly-mul and msm_1(n)
        group.bench_function(format!("c-sts n = {}", n), |b| {
            b.iter(|| {
                let b_com = utils::poly_on_points_zero(&fr, Fr::ONE);
                let repr = <G1 as VariableBaseMSM>::msm_unchecked(&g1, &b_com.coeffs);
                let _ = black_box(repr);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_epoch_repr);
criterion_main!(benches);