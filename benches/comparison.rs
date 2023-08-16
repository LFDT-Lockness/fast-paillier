use fast_paillier::utils;
use rug::Integer;

/// Safe 1536 bit prime number in hex encoding
const P: &str = "e84f454a8dd9e923fc85be8ca09278e28c5a3d9419cf118ef56912910f364c5\
                 29d999dba2837e55d413827ccf97a4b6c49addd56f079032164d487fbd22d5e\
                 a9ff0c8fdc6bce1b878a7109f33061874f310ae35ac75db3ac3fd5f49d8b85b\
                 8823f05fc288602abf6a4ef641a3766a44d7ecbceebe3bf144a582639b55658\
                 e93cc57445715ce83c0e7088ec701ded2bcbd2e91a68cb26b1aaddadf99aeef\
                 927fb82459a3805c232e36162cbea024a2fe7485b96eeb278d45016c622261b\
                 3d3aa3";
/// Safe 1536 bit prime number in hex encoding
const Q: &str = "9461f6a273f4bdf08ce0b1071253e0688d622d6b714b407200fa709d964034c\
                 1b84b97057a8dd48904a99e83f1cb4c94d6927ac6424b8028eefe6503336e03\
                 1ff0d7379932b1f6fa457d8a1e4d9436c42df8ba86ad54cc83a708cd6385d4d\
                 5cbf0c62f9f692f04e500726d5d41224e2ec88d48bd3d04c004c9a8e6ce23ee\
                 fb54995d7b4473c021f8a72c06fe3ce6488e6b1b8ad51b635a853121f4285c0\
                 c364aab061aea672cb6dd86cee08b63a5b3f1fc78f1712e1a333b2552471e5a\
                 d8403f";

fn encryption(c: &mut criterion::Criterion) {
    let mut rng = rand_dev::DevRng::new();

    let p = Integer::from_str_radix(P, 16).unwrap();
    let q = Integer::from_str_radix(Q, 16).unwrap();

    let dk: fast_paillier::DecryptionKey = fast_paillier::DecryptionKey::from_primes(p, q).unwrap();
    let ek = dk.encryption_key();

    let mut group = c.benchmark_group("Encrypt");

    let mut generate_inputs = || {
        let x = ek
            .n()
            .clone()
            .random_below(&mut fast_paillier::utils::external_rand(&mut rng))
            - ek.half_n();
        let nonce = fast_paillier::utils::sample_in_mult_group(&mut rng, ek.n());
        (x, nonce)
    };

    group.bench_function("Regular Encrypt", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |(x, nonce)| ek.encrypt_with(&x, &nonce).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
    group.bench_function("Encrypt with known factorization", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |(x, nonce)| dk.encrypt_with(&x, &nonce).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn decryption(c: &mut criterion::Criterion) {
    let mut rng = rand_dev::DevRng::new();

    let p = Integer::from_str_radix(P, 16).unwrap();
    let q = Integer::from_str_radix(Q, 16).unwrap();

    let dk_naive =
        fast_paillier::DecryptionKey::<utils::NaiveExp>::from_primes(p.clone(), q.clone()).unwrap();
    let dk_crt = fast_paillier::DecryptionKey::<utils::CrtExp>::from_primes(p, q).unwrap();
    let ek = dk_naive.encryption_key();

    let mut group = c.benchmark_group("Decrypt");

    let mut generate_inputs = || utils::sample_in_mult_group(&mut rng, ek.nn());

    group.bench_function("Naive Decrypt", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |enc_x| dk_naive.decrypt(&enc_x).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
    group.bench_function("Decrypt with CRT", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |enc_x| dk_crt.decrypt(&enc_x).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion::criterion_group!(benches, encryption, decryption);
criterion::criterion_main!(benches);
