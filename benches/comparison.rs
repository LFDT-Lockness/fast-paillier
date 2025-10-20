use fast_paillier::backend::Integer;

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

    let dk: fast_paillier::DecryptionKey =
        fast_paillier::DecryptionKey::from_primes(p.clone(), q.clone()).unwrap();
    let ek = dk.encryption_key();

    let mut group = c.benchmark_group("Encrypt");

    let mut generate_inputs = || {
        let x = ek.n().random_below_ref(&mut rng) - ek.half_n();
        let nonce = Integer::sample_in_mult_group_of(&mut rng, ek.n());
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

    let p = convert_integer_to_unknown_order(&p);
    let q = convert_integer_to_unknown_order(&q);
    let dk = libpaillier::DecryptionKey::with_primes_unchecked(&p, &q).unwrap();
    let ek: libpaillier::EncryptionKey = (&dk).into();

    let mut generate_inputs = || {
        let (x, nonce) = (generate_inputs)();
        (
            convert_integer_to_unknown_order(&x).to_bytes(),
            convert_integer_to_unknown_order(&nonce),
        )
    };

    group.bench_function("Encrypt libpaillier", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |(x, nonce)| ek.encrypt(x, Some(nonce)).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn decryption(c: &mut criterion::Criterion) {
    let mut rng = rand_dev::DevRng::new();

    let p = Integer::from_str_radix(P, 16).unwrap();
    let q = Integer::from_str_radix(Q, 16).unwrap();

    let dk = fast_paillier::DecryptionKey::from_primes(p.clone(), q.clone()).unwrap();
    let ek = dk.encryption_key();

    let mut group = c.benchmark_group("Decrypt");

    let mut generate_inputs = || Integer::sample_in_mult_group_of(&mut rng, ek.nn());

    group.bench_function("Decrypt with CRT", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |enc_x| dk.decrypt(&enc_x).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });

    let p = convert_integer_to_unknown_order(&p);
    let q = convert_integer_to_unknown_order(&q);
    let dk = libpaillier::DecryptionKey::with_primes_unchecked(&p, &q).unwrap();

    let mut generate_inputs = || {
        let enc_x = (generate_inputs)();
        convert_integer_to_unknown_order(&enc_x)
    };

    group.bench_function("Decrypt libpaillier", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |enc_x| dk.decrypt(&enc_x).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn omul(c: &mut criterion::Criterion) {
    let mut rng = rand_dev::DevRng::new();

    let p = Integer::from_str_radix(P, 16).unwrap();
    let q = Integer::from_str_radix(Q, 16).unwrap();

    let dk = fast_paillier::DecryptionKey::from_primes(p.clone(), q.clone()).unwrap();
    let ek = dk.encryption_key();

    let mut group = c.benchmark_group("OMul");

    let mut generate_inputs = || {
        let scalar = Integer::sample_pm_in_mult_group_of(&mut rng, ek.n());
        let enc_x = Integer::sample_in_mult_group_of(&mut rng, ek.nn());
        (scalar, enc_x)
    };

    group.bench_function("with CRT", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |(scalar, enc_x)| dk.omul(&scalar, &enc_x).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
    group.bench_function("without CRT", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |(scalar, enc_x)| ek.omul(&scalar, &enc_x).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
}

/// Old implementation of safe primes
pub fn naive_safe_prime(rng: &mut impl rand_core::RngCore, bits: u32) -> Integer {
    use fast_paillier::backend::IsPrime;
    loop {
        let mut x = Integer::generate_prime(rng, bits - 1);
        x <<= 1;
        x += 1;

        if let IsPrime::Yes | IsPrime::Probably = x.is_probably_prime(25) {
            return x;
        }
    }
}

fn safe_primes(c: &mut criterion::Criterion) {
    let rng = rand_dev::DevRng::new();

    let mut group = c.benchmark_group("Safe primes");
    for (bits, sample_size) in [(512, 200), (1024, 10), (1536, 10)] {
        let id = |s| format!("{}/{}", bits, s);
        group.sample_size(sample_size);

        group.bench_function(id("Original"), |b| {
            b.iter(|| naive_safe_prime(&mut rng.clone(), bits))
        });
        group.bench_function(id("Current"), |b| {
            b.iter(|| Integer::generate_safe_prime(&mut rng.clone(), bits))
        });
        group.bench_function(id("Trial with sieve of 120 primes"), |b| {
            b.iter(|| {
                fast_paillier::backend::sieve_generate_safe_primes(&mut rng.clone(), bits, 120)
            })
        });
        group.bench_function(id("Trial with sieve of 135 primes"), |b| {
            b.iter(|| {
                fast_paillier::backend::sieve_generate_safe_primes(&mut rng.clone(), bits, 135)
            })
        });
        group.bench_function(id("Trial with sieve of 150 primes"), |b| {
            b.iter(|| {
                fast_paillier::backend::sieve_generate_safe_primes(&mut rng.clone(), bits, 150)
            })
        });
    }
}

criterion::criterion_group!(benches, encryption, decryption, omul, safe_primes,);
criterion::criterion_main!(benches);

fn convert_integer_to_unknown_order(x: &Integer) -> libpaillier::unknown_order::BigNumber {
    let bytes = x.to_bytes_msf();
    libpaillier::unknown_order::BigNumber::from_slice(&bytes)
}
