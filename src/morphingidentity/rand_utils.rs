use sodiumoxide::randombytes::randombytes;

use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::hash::sha256;
use uuid;

/// This random generator should be used instead of `rand` and the rest
/// anywhere in the code (even in tests). We have a rule that insecure
/// randomness should generally not be used.
///
/// You should call `sodiumoxide::init();` before using `GoodRand`.
pub trait GoodRand {
    fn rand() -> Self;
}

impl GoodRand for u8 {
    fn rand() -> u8 {
        randombytes(1)[0]
    }
}

impl GoodRand for u16 {
    fn rand() -> u16 {
        let x = randombytes(2);
        (x[0] as u16) | ((x[1] as u16) << 8)
    }
}

impl GoodRand for u32 {
    fn rand() -> u32 {
        let x = randombytes(4);
        (x[0] as u32) | ((x[1] as u32) << 8) | ((x[2] as u32) << 16)
            | ((x[3] as u32) << 24)
    }
}

impl GoodRand for u64 {
    fn rand() -> u64 {
        let x = randombytes(8);
        (x[0] as u64) | ((x[1] as u64) << 8) | ((x[2] as u64) << 16)
            | ((x[3] as u64) << 24) | ((x[4] as u64) << 32)
            | ((x[5] as u64) << 40) | ((x[6] as u64) << 48)
            | ((x[7] as u64) << 56)
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
        ).unwrap()
    }
}

impl GoodRand for sign::Signature {
    fn rand() -> sign::Signature {
        sign::Signature::from_slice(
            randombytes(sign::SIGNATUREBYTES).as_slice(),
        ).unwrap()
    }
}

impl GoodRand for sha256::Digest {
    fn rand() -> sha256::Digest {
        sha256::Digest::from_slice(
            randombytes(sha256::DIGESTBYTES).as_slice(),
        ).unwrap()
    }
}

impl GoodRand for uuid::Uuid {
    fn rand() -> uuid::Uuid {
        uuid::Uuid::from_bytes(randombytes(16).as_slice()).unwrap()
    }
}
