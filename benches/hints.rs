use std::hint::black_box;

use ark_ec::CurveGroup;
use c_ste::{dealer::{Dealer, hint_verify}, member::Member};
use criterion::{Criterion, criterion_group, criterion_main};

type E = ark_bls12_381::Bls12_381;

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
        Some("fast") => 14,
        _ => 20,
    };
    for k in (6..=k_end).step_by(2) {
        let n = 1 << k;
        let (d, _) = Dealer::<E>::init_fast(n - 1);
        let members: Vec<Member<E>> = (0..n).map(|id| Member::<E>::new(id)).collect();
        let hint = members[3].hint_gen_lagrange(&d);
        let pk = members[3].key.pk.into_affine();
        verification_group.bench_function(format!("verify hint n = {}", n), |b| {
            b.iter(|| {
                let valid = hint_verify(&d, pk, &hint);
                let _ = black_box(valid);
            });
        });
    }
    verification_group.finish();
}

criterion_group!(benches, bench_hints);
criterion_main!(benches);