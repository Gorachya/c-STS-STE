use std::hint::black_box;

use ark_bls12_381::{G1Affine, G2Affine};
use criterion::{Criterion, criterion_group, criterion_main};
use ark_ec::{CurveGroup, VariableBaseMSM, pairing::Pairing};
use ark_std::UniformRand;

use rand::thread_rng;

type E = ark_bls12_381::Bls12_381;
type G1 = <E as Pairing>::G1;
type G2 = <E as Pairing>::G2;
type Fr = <E as Pairing>::ScalarField;

fn bench_preprocess(c: &mut Criterion) {
    let mut group = c.benchmark_group("preprocess estimate time");
    group.sample_size(10);

    let mut rng = thread_rng();

    // hint verification (per party, average): 1 pairing + msm_1(N) + msm_2(N)
    // computing ak and ek (per party, average): N+1 G1 add
    let p1 = G1::rand(&mut rng);
    let p2 = G2::rand(&mut rng);
    group.bench_function(format!("1 pairing"), |b| {
        b.iter(|| {
            let repr = E::pairing(p1, p2);
            let _ = black_box(repr);
        });
    });

    let k_end = match std::env::var("CSTE_BENCH_MODE").ok().as_deref() {
        Some("fast") => 16,
        _ => 20,
    };
    for k in (6..=k_end).step_by(2) {
        let n = 1 << k;
        let g1: Vec<G1Affine> = (0..n).map(|_| G1::rand(&mut rng).into_affine()).collect();
        let g2: Vec<G2Affine> = (0..n).map(|_| G2::rand(&mut rng).into_affine()).collect();
        let fr: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        group.bench_function(format!("g1 msm n = {}", n), |b| {
            b.iter(|| {
                let repr = <G1 as VariableBaseMSM>::msm_unchecked(&g1, &fr);
                let _ = black_box(repr);
            });
        });

        group.bench_function(format!("g2 msm n = {}", n), |b| {
            b.iter(|| {
                let repr = <G2 as VariableBaseMSM>::msm_unchecked(&g2, &fr);
                let _ = black_box(repr);
            });
        });

        group.bench_function(format!("g1 add n = {}", n), |b| {
            b.iter(|| {
                let repr: G1 = g1.iter().sum();
                let _ = black_box(repr);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_preprocess);
criterion_main!(benches);