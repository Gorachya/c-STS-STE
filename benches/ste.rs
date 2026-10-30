use std::hint::black_box;

use ark_bls12_381::{
    Bls12_381, G1Affine,
    g2::Config as G2Config,
};
use ark_ec::{
    CurveGroup,
    hashing::{
        curve_maps::wb::WBMap,
        map_to_curve_hasher::MapToCurveBasedHasher,
        HashToCurve,
    },
    pairing::Pairing,
};
use ark_ff::{fields::field_hashers::DefaultFieldHasher, UniformRand};
use c_ste::{
    aggregation::AggrSig,
    dealer::Dealer,
    committee::epoch_commitment,
    verify::encrypt,
};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::thread_rng;
use sha2::Sha256;

type E = Bls12_381;
type G1 = <E as Pairing>::G1;
type G2 = <E as Pairing>::G2;

type G2Hasher = MapToCurveBasedHasher<
    G2,
    DefaultFieldHasher<Sha256, 128>,
    WBMap<G2Config>,
>;

fn hasher() -> G2Hasher {
    G2Hasher::new(b"CSTE_BLS12381_G2_V1")
        .expect("invalid hash-to-G2 parameters")
}

fn bench_decaggr_increment(c: &mut Criterion) {
    let mut rng = thread_rng();

    let ct2 = (
        G1::rand(&mut rng),
        G2::rand(&mut rng),
        G2::rand(&mut rng),
        G2::rand(&mut rng),
        G2::rand(&mut rng),
        G1::rand(&mut rng),
        G2::rand(&mut rng),
        G2::rand(&mut rng),
        G2::rand(&mut rng),
    );
    let aggr: AggrSig<E> = AggrSig {
        s0: G2::rand(&mut rng),
        s1: G1::rand(&mut rng),
        s2: G1::rand(&mut rng),
        s3: G1::rand(&mut rng),
        s4: G1::rand(&mut rng),
        s5: G2::rand(&mut rng),
        s6: G1::rand(&mut rng),
        s7: G1::rand(&mut rng),
        s8: G1::rand(&mut rng),
    };
    let ct3 = E::pairing(G1::rand(&mut rng), G2::rand(&mut rng));

    let mut group = c.benchmark_group("c-ste decaggr increment");
    group.sample_size(10);
    group.bench_function("9-way multi-pairing + subtraction", |b| {
        b.iter(|| {
            let _ = black_box(
                ct3 - E::multi_pairing(
                    [ct2.0, aggr.s1, aggr.s2, aggr.s3, aggr.s4, ct2.5, aggr.s6, aggr.s7, aggr.s8],
                    [aggr.s0, ct2.1, ct2.2, ct2.3, ct2.4, aggr.s5, ct2.6, ct2.7, ct2.8],
                ),
            );
        });
    });
    group.finish();
}

fn bench_encryption(c: &mut Criterion) {
    let (dealer, trapdoor) = Dealer::<E>::init_fast(8191);
    let party_count = dealer.w_domain.len();
    let public_keys = (0..party_count).map(|_| {
        G1::rand(&mut rand::thread_rng()).into_affine()
    }).collect::<Vec<G1Affine>>();
    let (aggregation_key, encryption_key) =
        dealer.preprocess_trapdoor(&public_keys, &trapdoor);

    let mut committee = Vec::with_capacity(4096);
    for id in 0..4096 {
        committee.push(id);
    }
    let epoch_commitment = epoch_commitment(&dealer, &committee);
    let threshold = 2048;
    let epoch = 12345678;
    let message = E::pairing(G1::rand(&mut rand::thread_rng()), G2::rand(&mut rand::thread_rng()));
    let hasher = hasher();

    black_box(&aggregation_key);
    let mut group = c.benchmark_group("c-ste encryption");
    group.sample_size(10);
    group.bench_function("n=4096,t=2048", |b| {
        b.iter(|| {
            black_box(encrypt(
                black_box(&dealer),
                black_box(&encryption_key),
                black_box(message),
                black_box(threshold),
                black_box(epoch),
                black_box(epoch_commitment),
                black_box(&hasher),
            ));
        });
    });
    group.finish();
}

criterion_group!(benches, bench_decaggr_increment, bench_encryption);
criterion_main!(benches);
