use ark_ec::{VariableBaseMSM, pairing::Pairing};
use ark_ff::Field;

use rand::thread_rng;
use rand::{SeedableRng, seq::SliceRandom};
use rand::rngs::StdRng;

use crate::dealer::Dealer;
use crate::utils;

// For example only
pub fn committee_select(total: usize, n: usize, e: usize) -> Vec<usize> {
    assert!(total >= 2, "N must include the dummy party and at least one committee candidate");
    assert!(n < total, "committee size n must be smaller than N");
    let mut v: Vec<usize> = (1..total).collect();

    let mut rng = StdRng::seed_from_u64(e as u64);

    v.shuffle(&mut rng);
    v.truncate(n);
    v
}

// For example only
pub fn participate_select(com: &Vec<usize>, r: usize) -> Vec<usize> {
    let mut rng = thread_rng();

    let mut v = com.clone();
    v.shuffle(&mut rng);
    v.truncate(r);

    // The dummy party 0 is add to the top at here
    assert!(!com.contains(&0));
    v.insert(0, 0);
    v
}

pub fn epoch_commitment<E: Pairing>(d: &Dealer<E>, members: &Vec<usize>) -> E::G1 {
    let mut points: Vec<E::ScalarField> = Vec::with_capacity(members.len() + 1);
    points.push(E::ScalarField::ONE); // dummy party x-1
    points.extend(members.iter().map(|&i| d.w_domain[i]));

    let prod = utils::poly_on_points_zero(&points, E::ScalarField::ONE);
    <E::G1 as VariableBaseMSM>::msm_unchecked(&d.crs.0, &prod.coeffs)
}