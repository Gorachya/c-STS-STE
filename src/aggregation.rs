use ark_ec::{VariableBaseMSM, pairing::{Pairing, PairingOutput}};
use ark_ff::{Field, PrimeField, batch_inversion};

use crate::{dealer::{AggrKey, Dealer}, verify::Ciphertext, utils};
use crate::bls::BLSSignature;

pub struct AggrSig<E: Pairing> {
    pub s0: E::G2,
    pub s1: E::G1,
    pub s2: E::G1,
    pub s3: E::G1,
    pub s4: E::G1,
    pub s5: E::G2,
    pub s6: E::G1,
    pub s7: E::G1,
    pub s8: E::G1,
}

pub fn aggregate<E: Pairing>(d: &Dealer<E>, ak: &AggrKey<E>,
    s: &Vec<usize>, com_e: &Vec<usize>, sig_s: &Vec<BLSSignature<E>>, t: usize) -> AggrSig<E> {

    assert!(s[0] == 0); // We require that the dummy party 0 (and its signature) is at first for simplicity
    let cs: Vec<usize> = com_e.iter().cloned().filter(|id| !s.contains(&id)).collect();
    assert!(com_e.len() == s.len() + cs.len() - 1); // 0

    let w_s: Vec<E::ScalarField> = s.iter().map(|&i| d.w_domain[i]).collect(); // w_s[0] == 1
    let l_s: (Vec<E::G1Affine>, Vec<E::G2Affine>) = (
        s.iter().map(|&i| d.lagrange_basis_commit.0[i]).collect(),
        s.iter().map(|&i| d.lagrange_basis_commit.1[i]).collect(),
    );

    let pk_s: Vec<E::G1Affine> = s.iter().map(|&i| ak.ak1[i]).collect();
    let qz1_s: Vec<E::G1Affine> = s.iter().map(|&i| ak.ak3[i]).collect();
    let qz2_s: Vec<E::G1Affine> = s.iter().map(|&i| ak.ak5[i]).collect();
    let qx_s: Vec<E::G1Affine> = s.iter().map(|&i| ak.ak4[i]).collect();
    let qxt_s: Vec<E::G1Affine> = s.iter().map(|&i| ak.ak2[i]).collect();

    let inv_n_plus_one = d.total_plus_1.inverse().unwrap(); // 1/(N+1)

    // Step 0: B(w^k) (with k = 0)
    // g(1), g'(w^k)
    let g1 = w_s[1..].iter().map(|&wi| E::ScalarField::ONE - wi).fold(E::ScalarField::ONE, |acc, v| acc * v);
    let gd = multi_evaluate::<E::ScalarField>(&w_s[1..].to_vec());

    // B(w^k) = -w^-k * g(1) / (1-w^k) / g'(w^k), but B(1) = 1
    let mut b_s = vec![E::ScalarField::ONE];
    b_s.extend(w_s[1..].iter().zip(gd.iter()).map(|(&w, &g)| g1 / w / (w-E::ScalarField::ONE) / g));
    let b_s_bigint: Vec<<<E as Pairing>::ScalarField as PrimeField>::BigInt>
        = b_s.iter().map(|x| x.into_bigint()).collect();

    // Step 1: B
    let b = <E::G2 as VariableBaseMSM>::msm_bigint(&l_s.1, &b_s_bigint);
    
    // Step 2: aPK
    let apk = <E::G1 as VariableBaseMSM>::msm_bigint(&pk_s, &b_s_bigint) * inv_n_plus_one;

    // Step 3: Qz, Qx, Qxt
    // TODO: combine ak3 and ak5 at preprocess
    let qz1 = <E::G1 as VariableBaseMSM>::msm_bigint(&qz1_s, &b_s_bigint);
    let qz2 = <E::G1 as VariableBaseMSM>::msm_bigint(&qz2_s, &b_s_bigint);
    let qz = qz1 + qz2;
    let qx = <E::G1 as VariableBaseMSM>::msm_bigint(&qx_s, &b_s_bigint);
    let qxt = <E::G1 as VariableBaseMSM>::msm_bigint(&qxt_s, &b_s_bigint);

    // Step 4: sig
    let sig_points: Vec<E::G2Affine> = sig_s.iter().map(|sig| sig.signature).collect();
    let sig = (<E::G2 as VariableBaseMSM>::msm_bigint(&sig_points, &b_s_bigint)) * inv_n_plus_one;

    // Step 5: Bt
    let bt_s: Vec<<<E as Pairing>::ScalarField as PrimeField>::BigInt> = w_s.iter().zip(b_s.iter()).map(
        |(&w, &b)| (w.pow([(t + 1) as u64]) * b).into_bigint()
    ).collect();
    let mut bt = <E::G1 as VariableBaseMSM>::msm_bigint(&l_s.0, &bt_s);
    if sig_s.len() == t + 1 {
        bt += (d.crs.0[d.crs.0.len()-1] - d.crs.0[0]) * g1 * inv_n_plus_one;
    }

    // Step 6: Bb

    // let polys: Vec<DensePolynomial<E::ScalarField>> = cs.iter().map(
    //     |&i| DensePolynomial::from_coefficients_vec(vec![-d.w_domain[i], E::ScalarField::ONE])
    // ).collect();
    // let mut prod = DensePolynomial::from_coefficients_vec(vec![g1 * inv_n_plus_one]);
    // for p in polys {
    //     prod = &prod * &p;
    // }
    // let bb = <E::G1 as VariableBaseMSM>::msm_unchecked(&d.crs.0, &prod.coeffs);

    // Divide-and-Conquer is faster when |Com_e\S| is large (e.g., >= 2^7)
    let points = cs.iter().map(|&i| d.w_domain[i]).collect();
    let bbx = utils::poly_on_points_zero(&points, g1 * inv_n_plus_one);
    let bb = <E::G1 as VariableBaseMSM>::msm_unchecked(&d.crs.0, &bbx.coeffs);

    // Step 7: Q0
    let mut w_inv: Vec<E::ScalarField> = w_s[1..].iter().map(|&w| w - E::ScalarField::ONE).collect();
    batch_inversion(&mut w_inv);
    let mut q0_den = vec![w_inv.iter().sum()];
    q0_den.extend(w_inv);
    let q0_s: Vec<<<E as Pairing>::ScalarField as PrimeField>::BigInt>
        = q0_den.iter().zip(b_s.iter()).map(|(&q, &b)| (q * b).into_bigint()).collect();
    let q0 = <E::G1 as VariableBaseMSM>::msm_bigint(&l_s.0, &q0_s);

    AggrSig {
        s0: b,
        s1: -apk,
        s2: -qz,
        s3: -qx,
        s4: qxt,
        s5: sig,
        s6: -bt,
        s7: -bb,
        s8: -q0,
    }
}

pub fn decrypt<E: Pairing>(d: &Dealer<E>, ak: &AggrKey<E>, ct: &Ciphertext<E>,
    s: &Vec<usize>, com_e: &Vec<usize>, sig_s: &Vec<BLSSignature<E>>, t: usize) -> PairingOutput<E> {

    let aggrs = aggregate(d, ak, s, com_e, sig_s, t);

    ct.ct3 - E::multi_pairing(
        vec![ct.ct2.0, aggrs.s1, aggrs.s2, aggrs.s3, aggrs.s4, ct.ct2.5, aggrs.s6, aggrs.s7, aggrs.s8],
        vec![aggrs.s0, ct.ct2.1, ct.ct2.2, ct.ct2.3, ct.ct2.4, aggrs.s5, ct.ct2.6, ct.ct2.7, ct.ct2.8]
    )
}

// This is faster than some complex O(nlog^2n) algorithm when n is small (e.g., n < 2^15)
fn multi_evaluate<F: PrimeField>(w: &Vec<F>) -> Vec<F> {
    let mut res = vec![F::ONE; w.len()];
    for i in 0..w.len() {
        for j in 0..w.len() {
            if i == j { continue; }
            res[i] *= w[i] - w[j];
        }
    }
    res
}