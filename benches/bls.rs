use std::hint::black_box;

use ark_bls12_381::{Bls12_381, g2::Config as G2Config};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
};
use ark_ff::fields::field_hashers::DefaultFieldHasher;
use c_ste::bls::{BLSKey, verify};
use criterion::{Criterion, criterion_group, criterion_main};
use sha2::Sha256;

type G2 = <Bls12_381 as Pairing>::G2;
type G2Hasher = MapToCurveBasedHasher<G2, DefaultFieldHasher<Sha256, 128>, WBMap<G2Config>>;

fn bench_bls(c: &mut Criterion) {
    let mut group = c.benchmark_group("bls time");
    let g2_hasher = G2Hasher::new(b"CSTE_BLS12381_G2_V1")
        .expect("invalid hash-to-G2 parameters");

    // Prepare inputs outside the timed loops.
    let key = BLSKey::<Bls12_381>::new();
    let msg = b"BLS signature benchmark".to_vec();
    let sig = key.sign(&msg, &g2_hasher);
    assert!(verify::<Bls12_381, _>(key.pk, &msg, &sig, &g2_hasher));

    group.bench_function("sign", |b| {
        b.iter(|| black_box(black_box(&key).sign(black_box(&msg), &g2_hasher)));
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            black_box(verify::<Bls12_381, _>(
                black_box(key.pk),
                black_box(&msg),
                black_box(&sig),
                black_box(&g2_hasher),
            ))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_bls);
criterion_main!(benches);
