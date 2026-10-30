use std::hint::black_box;

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::{
    CurveGroup,
    hashing::{
        curve_maps::wb::WBMap,
        map_to_curve_hasher::MapToCurveBasedHasher,
        HashToCurve,
    },
};
use ark_ff::{fields::field_hashers::DefaultFieldHasher, BigInteger, PrimeField};
use ark_std::UniformRand;
use c_ste::{
    aggregation::{aggregate, AggrSig},
    bls::BLSSignature,
    committee::{committee_select, participate_select},
    dealer::Dealer,
    member::Member,
    verify::verify,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::thread_rng;
use sha2::Sha256;

type E = Bls12_381;
type G1 = <E as ark_ec::pairing::Pairing>::G1;
type G2 = <E as ark_ec::pairing::Pairing>::G2;

struct VerificationFixture {
    dealer: Dealer<E>,
    encryption_key: c_ste::dealer::EncKey<E>,
    epoch_commitment: G1,
    aggregate_signature: AggrSig<E>,
    message: Vec<u8>,
    threshold: usize,
    epoch: usize,
}

fn hasher() -> MapToCurveBasedHasher<
    G2,
    DefaultFieldHasher<Sha256, 128>,
    WBMap<ark_bls12_381::g2::Config>,
> {
    MapToCurveBasedHasher::new(b"CSTE_BLS12381_G2_V1")
        .expect("invalid hash-to-G2 parameters")
}

fn bench_aggregation(c: &mut Criterion) {
    let mut rng = thread_rng();
    let (dealer, trapdoor) = Dealer::<E>::init_fast(8191);
    let party_count = dealer.w_domain.len();

    let members: Vec<Member<E>> = (0..party_count).map(|id| Member::<E>::new(id)).collect();
    let public_keys: Vec<G1Affine> = members.iter().map(|member| member.key.pk.into_affine()).collect();

    let mut group = c.benchmark_group("aggregation time");

    for committee_size in [64usize, 256, 1024, 4096] {
        let committee = committee_select(party_count, committee_size, 12345678);
        let threshold = committee_size / 2;
        let signers = participate_select(&committee, threshold);

        let mut aggregation_key = c_ste::dealer::AggrKey {
            v: vec![false; party_count],
            ak1: public_keys.clone(),
            ak2: (0..party_count).map(|_| G1::rand(&mut rng).into_affine()).collect(),
            ak3: (0..party_count).map(|_| G1::rand(&mut rng).into_affine()).collect(),
            ak4: (0..party_count).map(|_| G1::rand(&mut rng).into_affine()).collect(),
            ak5: (0..party_count).map(|_| G1::rand(&mut rng).into_affine()).collect(),
        };
        for id in &committee {
            aggregation_key.v[*id] = true;
        }

        let signatures = (0..signers.len()).map(|_| {
            G2::rand(&mut rng).into_affine()
        }).collect::<Vec<G2Affine>>();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("n={committee_size},t={threshold}")),
            &committee_size,
            |b, _| {
                b.iter(|| {
                    black_box(aggregate(
                        black_box(&dealer),
                        black_box(&aggregation_key),
                        black_box(&signers),
                        black_box(&committee),
                        black_box(&signatures),
                        black_box(threshold),
                    ));
                });
            },
        );
    }
    group.finish();

    let verification_fixture = make_verification_fixture(
        &dealer,
        &trapdoor,
        &public_keys,
        &members,
    );
    verify_fixture_once(&verification_fixture);

    let mut verify_group = c.benchmark_group("c-sts verification time");
    verify_group.bench_function(
        format!(
            "n={},t={}",
            4096,
            verification_fixture.threshold
        ),
        |b| {
            b.iter(|| {
                let valid = verify(
                    black_box(&verification_fixture.dealer),
                    black_box(&verification_fixture.encryption_key),
                    black_box(&verification_fixture.message),
                    black_box(verification_fixture.threshold),
                    black_box(verification_fixture.epoch),
                    black_box(verification_fixture.epoch_commitment),
                    black_box(verification_fixture.aggregate_signature.clone()),
                    black_box(&hasher()),
                );
                black_box(valid);
            });
        },
    );
    verify_group.finish();
}

fn make_verification_fixture(
    dealer: &Dealer<E>,
    trapdoor: &c_ste::dealer::Trapdoor<E>,
    public_keys: &[G1Affine],
    members: &[Member<E>],
) -> VerificationFixture {
    let hasher = hasher();
    let epoch = 12345678usize;
    let committee_size = 4096usize;
    let committee = committee_select(dealer.w_domain.len(), committee_size, epoch);
    let threshold = committee_size / 2;
    let signers = participate_select(&committee, threshold);
    let epoch_commitment = c_ste::committee::epoch_commitment(dealer, &committee);

    let (aggregation_key, encryption_key) =
        dealer.preprocess_trapdoor(&public_keys.to_vec(), trapdoor);

    let message = Fr::from(123456789u64).into_bigint().to_bytes_be();
    let mut signed_message = message.clone();
    signed_message.extend(epoch.to_be_bytes());

    let signatures: Vec<BLSSignature<E>> = signers
        .iter()
        .map(|id| members[*id].key.sign(&signed_message, &hasher))
        .collect();

    let mut verified_ids = Vec::new();
    let mut verified_signatures = Vec::new();
    for (&id, signature) in signers.iter().zip(signatures.iter()) {
        if id == 0 || (committee.contains(&id) && aggregation_key.v[id]
            && c_ste::bls::verify(members[id].key.pk, &signed_message, signature, &hasher))
        {
            verified_ids.push(id);
            verified_signatures.push(signature.signature);
        }
    }
    assert_eq!(verified_ids.first(), Some(&0));
    assert!(
        verified_ids.len() > threshold,
        "only {} valid signers were collected for threshold {}",
        verified_ids.len() - 1,
        threshold,
    );

    let aggregate_signature = aggregate(
        dealer,
        &aggregation_key,
        &verified_ids,
        &committee,
        &verified_signatures,
        threshold,
    );

    VerificationFixture {
        dealer: dealer.clone(),
        encryption_key,
        epoch_commitment,
        aggregate_signature,
        message,
        threshold,
        epoch,
    }
}

fn verify_fixture_once(fixture: &VerificationFixture) {
    assert!(verify(
        &fixture.dealer,
        &fixture.encryption_key,
        &fixture.message,
        fixture.threshold,
        fixture.epoch,
        fixture.epoch_commitment,
        fixture.aggregate_signature.clone(),
        &hasher(),
    ));
}

criterion_group!(benches, bench_aggregation);
criterion_main!(benches);
