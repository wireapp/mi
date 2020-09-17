pub use sodiumoxide::randombytes::randombytes;

use crate::capabilities;
use crate::journal;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::sign;
use uuid;

/// This random generator should be used instead of `rand` and the rest
/// anywhere in the code (even in tests). We have a rule that insecure
/// randomness should generally not be used.
///
/// You should call `sodiumoxide::init();` before using `GoodRand`.
pub trait GoodRand {
    fn rand() -> Self;
}

/// Generate a random integer in range [0, n).
pub fn randomnumber(n: u64) -> u64 {
    // We want to avoid modulo bias, so we use the arc4random_uniform
    // implementation (http://stackoverflow.com/a/20051580/615030).
    if n < 2 {
        return 0;
    }
    let min: u64 = n.wrapping_neg() % n; // 2^64 mod n == (2^64 - n) mod n
    let mut r: u64 = GoodRand::rand();
    while r < min {
        r = GoodRand::rand();
    }
    r % n
}

// implementations of GoodRand /////////////////////////////////////////////

impl GoodRand for u8 {
    fn rand() -> u8 {
        randombytes(1)[0]
    }
}

impl GoodRand for u16 {
    fn rand() -> u16 {
        let x = randombytes(2);
        u16::from(x[0]) | (u16::from(x[1]) << 8)
    }
}

impl GoodRand for u32 {
    fn rand() -> u32 {
        let x = randombytes(4);
        u32::from(x[0])
            | (u32::from(x[1]) << 8)
            | (u32::from(x[2]) << 16)
            | (u32::from(x[3]) << 24)
    }
}

impl GoodRand for u64 {
    fn rand() -> u64 {
        let x = randombytes(8);
        u64::from(x[0])
            | (u64::from(x[1]) << 8)
            | (u64::from(x[2]) << 16)
            | (u64::from(x[3]) << 24)
            | (u64::from(x[4]) << 32)
            | (u64::from(x[5]) << 40)
            | (u64::from(x[6]) << 48)
            | (u64::from(x[7]) << 56)
    }
}

#[cfg(target_pointer_width = "32")]
impl GoodRand for usize {
    fn rand() -> usize {
        <u32 as GoodRand>::rand() as usize
    }
}

#[cfg(target_pointer_width = "64")]
impl GoodRand for usize {
    fn rand() -> usize {
        <u64 as GoodRand>::rand() as usize
    }
}

impl GoodRand for sign::PublicKey {
    fn rand() -> sign::PublicKey {
        sign::PublicKey::from_slice(
            randombytes(sign::PUBLICKEYBYTES).as_slice(),
        )
        .unwrap()
    }
}

impl GoodRand for sign::Signature {
    fn rand() -> sign::Signature {
        sign::Signature::from_slice(
            randombytes(sign::SIGNATUREBYTES).as_slice(),
        )
        .unwrap()
    }
}

impl GoodRand for sha256::Digest {
    fn rand() -> sha256::Digest {
        sha256::Digest::from_slice(
            randombytes(sha256::DIGESTBYTES).as_slice(),
        )
        .unwrap()
    }
}

impl GoodRand for uuid::Uuid {
    fn rand() -> uuid::Uuid {
        uuid::Uuid::from_bytes(randombytes(16).as_slice()).unwrap()
    }
}

impl GoodRand for journal::JournalID {
    fn rand() -> journal::JournalID {
        journal::JournalID(GoodRand::rand())
    }
}

impl GoodRand for capabilities::Capabilities {
    fn rand() -> capabilities::Capabilities {
        capabilities::Capabilities(GoodRand::rand())
    }
}

#[test]
fn distribution_test() {
    const ITERATIONS: usize = 1_000_000;
    const SPREAD: u64 = 5;
    const TOLERANCE: f64 = 0.01; // 1 percent
    let mut buckets = vec![0, 0, 0, 0, 0];
    for _ in 0..ITERATIONS {
        let n = randomnumber(SPREAD) as usize;
        buckets[n] += 1;
    }

    for i in 0..SPREAD {
        let deviation: i32 =
            buckets[i as usize] - (ITERATIONS as i32 / SPREAD as i32);
        let relative_deviation =
            deviation.abs() as f64 / (ITERATIONS as f64 / SPREAD as f64);
        assert!(relative_deviation < TOLERANCE);
    }
}
