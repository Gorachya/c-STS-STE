use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use ark_ec::CurveGroup;
use ark_bls12_381::G1Affine;
use rand::thread_rng;
use ark_ec::pairing::Pairing;
use ark_std::UniformRand;

type E = ark_bls12_381::Bls12_381;
type G1 = <E as Pairing>::G1;

fn bench_preprocess(c: &mut Criterion) {
    let mut group = c.benchmark_group("preprocess estimate time");
    group.sample_size(10);

    let mut rng = thread_rng();

    let k_end = match std::env::var("CSTE_BENCH_MODE").ok().as_deref() {
        Some("fast") => 16,
        _ => 20,
    };
    for k in (6..=k_end).step_by(2) {
        let n = 1 << k;
        let g1: Vec<G1Affine> = (0..n + 1).map(|_| G1::rand(&mut rng).into_affine()).collect();

        group.bench_function(format!("g1 add n+1 = {}", n), |b| {
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