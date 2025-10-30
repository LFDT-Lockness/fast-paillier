use fast_paillier::{backend::Integer, utils, DecryptionKey};
use rand::Rng;

#[cfg(all(feature = "backend-rug", feature = "backend-num-bigint"))]
mod backend;

#[test]
fn encrypt_decrypt() {
    let mut rng = rand_dev::DevRng::new();
    let dk = random_key_for_tests(&mut rng);
    let ek = dk.encryption_key();

    for _ in 0..50 {
        // Generate plaintext in [-N/2; N/2)
        let plaintext = ek.n().random_below_ref(&mut rng);
        let plaintext = plaintext - (ek.n() / 2u8);
        println!("Plaintext: {plaintext}");

        // Encrypt and decrypt
        let (ciphertext, nonce) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();
        println!("Ciphertext: {ciphertext}");
        println!("Nonce: {nonce}");

        let decrypted = dk.decrypt(&ciphertext).unwrap();
        println!("Decrypted: {decrypted}");

        assert_eq!(plaintext, decrypted);
        println!();
    }

    // Check corner cases

    let lower_bound = -(ek.n() / 2u8);
    let upper_bound = ek.n() / 2u8;

    let corner_cases = [
        lower_bound.clone(),
        lower_bound.clone() + 1,
        upper_bound.clone() - 1,
        upper_bound.clone(),
    ];
    for (i, plaintext) in corner_cases.into_iter().enumerate() {
        println!("Corner case {i}");
        let (ciphertext, _nonce) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();
        let decrypted = dk.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }
}

#[test]
fn doesnt_encrypt_plaintext_out_of_bounds() {
    let mut rng = rand_dev::DevRng::new();
    let dk = random_key_for_tests(&mut rng);
    let ek = dk.encryption_key();

    let lower_bound = -(ek.n() / 2u8);
    let upper_bound = ek.n() / 2u8;

    let cases = [
        lower_bound.clone() - 1,
        lower_bound.clone() - 2,
        upper_bound.clone() + 1,
        upper_bound.clone() + 2,
    ];
    for (i, plaintext) in cases.into_iter().enumerate() {
        println!("Case {i}");
        let _: fast_paillier::Error = ek.encrypt_with_random(&mut rng, &plaintext).unwrap_err();
    }
}

#[test]
fn homorphic_ops() {
    let mut rng = rand_dev::DevRng::new();
    let dk = random_key_for_tests(&mut rng);
    let ek = dk.encryption_key();

    for _ in 0..100 {
        let a = ek.n().random_below_ref(&mut rng);
        let b = ek.n().random_below_ref(&mut rng);
        let a = a - (ek.n() / 2u8);
        let b = b - (ek.n() / 2u8);
        println!("a: {a}");
        println!("b: {b}");

        let (enc_a, _nonce) = ek.encrypt_with_random(&mut rng, &a).unwrap();
        let (enc_b, _nonce) = ek.encrypt_with_random(&mut rng, &b).unwrap();

        // Addition
        {
            let enc_a_plus_b = ek.oadd(&enc_a, &enc_b).unwrap();
            let a_plus_b = dk.decrypt(&enc_a_plus_b).unwrap();
            assert_eq!(a_plus_b, signed_modulo(&(&a + &b), ek.n()));
        }

        // Subtraction
        {
            let enc_a_minus_b = ek.osub(&enc_a, &enc_b).unwrap();
            let a_minus_b = dk.decrypt(&enc_a_minus_b).unwrap();
            assert_eq!(a_minus_b, signed_modulo(&(&a - &b), ek.n()));
        }

        // Negation
        {
            let enc_neg_a = ek.oneg(&enc_a).unwrap();
            let neg_a = dk.decrypt(&enc_neg_a).unwrap();
            assert_eq!(neg_a, signed_modulo(&(-&a), ek.n()));
        }

        // Multiplication
        {
            let enc_a_at_b = ek.omul(&a, &enc_b).unwrap();
            let a_at_b = dk.decrypt(&enc_a_at_b).unwrap();
            assert_eq!(a_at_b, signed_modulo(&(&a * &b), ek.n()));
        }
    }
}

#[test]
fn encryption_with_known_factorization() {
    let mut rng = rand_dev::DevRng::new();
    let dk = random_key_for_tests(&mut rng);
    let ek = dk.encryption_key();

    for i in 0..100 {
        println!("Iteration {i}");
        let x = ek.n().random_below_ref(&mut rng);
        let x = x - ek.half_n();

        let nonce = Integer::sample_in_mult_group_of(&mut rng, ek.n());

        let enc_x1 = ek.encrypt_with(&x, &nonce).unwrap();
        let enc_x2 = dk.encrypt_with(&x, &nonce).unwrap();

        assert_eq!(enc_x1, enc_x2);
    }
}

#[test]
fn factorized_exp_mod_n() {
    let mut rng = rand_dev::DevRng::new();

    let p = Integer::generate_safe_prime(&mut rng, 512);
    let q = Integer::generate_safe_prime(&mut rng, 512);
    let n = &p * &q;
    println!("n: {n}");

    let crt = utils::CrtExp::build_n(&p, &q).unwrap();

    for _ in 0..100 {
        let x: Integer = n.random_below_ref(&mut rng);
        let mut e: Integer = Integer::random_bits(1024, &mut rng);
        if rng.gen::<bool>() {
            e = -e
        }
        let crt_e = crt.prepare_exponent(&e);

        println!();
        println!("x: {x}");
        println!("e: {e}");

        let expected: Integer = x.pow_mod_ref(&e, &n).unwrap();
        let actual = crt.exp(&x, &crt_e).unwrap();
        assert_eq!(expected, actual);
    }
}

#[test]
fn factorized_exp_mod_nn() {
    let mut rng = rand_dev::DevRng::new();

    let p = Integer::generate_safe_prime(&mut rng, 512);
    let q = Integer::generate_safe_prime(&mut rng, 512);
    let nn = (&p * &q).square();
    println!("nn: {nn}");

    let crt = utils::CrtExp::build_nn(&p, &q).unwrap();

    for _ in 0..100 {
        let x = nn.random_below_ref(&mut rng);
        let mut e = Integer::random_bits(1024, &mut rng);
        if rng.gen::<bool>() {
            e = -e
        }
        let crt_e = crt.prepare_exponent(&e);

        println!();
        println!("x: {x}");
        println!("e: {e}");

        let expected: Integer = x.pow_mod_ref(&e, &nn).unwrap();
        let actual = crt.exp(&x, &crt_e).unwrap();
        assert_eq!(expected, actual);
    }
}

/// Takes `x mod n` and maps result to `{-N/2, .., N/2}`
fn signed_modulo(x: &Integer, n: &Integer) -> Integer {
    let x = x.modulo_ref(n);
    unsigned_mod_to_signed(x, n)
}

/// Maps `{0, .., N-1}` to `{-N/2, .., N/2}`
fn unsigned_mod_to_signed(x: Integer, n: &Integer) -> Integer {
    if 2u8 * &x >= *n {
        x - n
    } else {
        x
    }
}

fn random_key_for_tests(rng: &mut impl rand_core::RngCore) -> DecryptionKey {
    let p = Integer::generate_safe_prime(rng, 512);
    let q = Integer::generate_safe_prime(rng, 512);
    DecryptionKey::from_primes(p, q).unwrap()
}
