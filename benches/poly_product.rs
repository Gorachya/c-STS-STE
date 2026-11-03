use std::hint::black_box;

use ark_bls12_381::Fr;
use ark_ff::{Field, UniformRand, Zero};
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::thread_rng;

fn divide_and_conquer(points: &[Fr], start: Fr) -> DensePolynomial<Fr> {
    multiply_segment(points, 0, points.len(), start, 1)
}

fn multiply_direct(
    left: &DensePolynomial<Fr>,
    right: &DensePolynomial<Fr>,
) -> DensePolynomial<Fr> {
    let degree_left = left.coeffs.len();
    let degree_right = right.coeffs.len();
    let mut coefficients = vec![Fr::zero(); degree_left + degree_right - 1];

    for i in 0..degree_left {
        for j in 0..degree_right {
            coefficients[i + j] += left.coeffs[i] * right.coeffs[j];
        }
    }

    DensePolynomial::from_coefficients_vec(coefficients)
}

fn direct_product(points: &[Fr], start: Fr) -> DensePolynomial<Fr> {
    let mut product = if points.is_empty() {
        DensePolynomial::from_coefficients_vec(vec![start])
    } else {
        DensePolynomial::from_coefficients_vec(vec![ -points[0] * start, start ])
    };

    for point in points.iter().skip(1) {
        let linear = DensePolynomial::from_coefficients_vec(vec![ -*point, Fr::ONE ]);
        product = multiply_direct(&product, &linear);
    }
    product
}

fn multiply_segment(
    points: &[Fr],
    left: usize,
    right: usize,
    start: Fr,
    threshold: usize,
) -> DensePolynomial<Fr> {
    let count = right - left;
    if count <= threshold {
        return direct_product(&points[left..right], if left == 0 { start } else { Fr::ONE });
    }

    let middle = (left + right) / 2;
    let lp = multiply_segment(points, left, middle, start, threshold);
    let rp = multiply_segment(points, middle, right, start, threshold);
    &lp * &rp
}

fn bench_poly_product(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut group = c.benchmark_group("polynomial product");
    group.sample_size(10);

    const POINT_COUNT: usize = 4096;
    let points: Vec<Fr> = (0..POINT_COUNT).map(|_| Fr::rand(&mut rng)).collect();
    let start = Fr::rand(&mut rng);
    let pure_fft = divide_and_conquer(&points, start);
    assert_eq!(pure_fft.coeffs, direct_product(&points, start).coeffs);

    let mut threshold = 8usize;
    while threshold <= POINT_COUNT {
        let hybrid = multiply_segment(&points, 0, POINT_COUNT, start, threshold);
        assert_eq!(pure_fft.coeffs, hybrid.coeffs);

        group.bench_with_input(
            BenchmarkId::new(format!("hybrid/{POINT_COUNT}/threshold={threshold}"), threshold),
            &threshold,
            |b, &threshold| {
                b.iter(|| {
                    black_box(multiply_segment(
                        black_box(&points),
                        0,
                        POINT_COUNT,
                        black_box(start),
                        threshold,
                    ));
                });
            },
        );
        threshold *= 2;
    }

    group.finish();
}

criterion_group!(benches, bench_poly_product);
criterion_main!(benches);
