use std::hint::black_box;

use ark_bls12_381::Bls12_381;
use c_ste::bls::{BLSKey, verify};
use criterion::{Criterion, criterion_group, criterion_main};

fn bench_bls(c: &mut Criterion) {
    let mut group = c.benchmark_group("bls time");

    // Prepare inputs outside the timed loops.
    let key = BLSKey::<Bls12_381>::new();
    let msg = b"BLS signature benchmark".to_vec();
    let sig = key.sign(&msg);
    assert!(verify::<Bls12_381>(key.pk, &msg, sig));

    group.bench_function("sign", |b| {
        b.iter(|| black_box(black_box(&key).sign(black_box(&msg))));
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            black_box(verify::<Bls12_381>(
                black_box(key.pk),
                black_box(&msg),
                black_box(sig),
            ))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_bls);
criterion_main!(benches);
