use sodiumoxide::crypto::sign::{Signature, SIGNATUREBYTES};

pub fn to_u8_32(buf: &[u8]) -> Option<[u8; 32]> {
    if buf.len() < 32 {
        return None;
    }
    let mut array = [0u8; 32];
    for (&x, p) in buf.iter().zip(array.iter_mut()) {
        *p = x;
    }
    Some(array)
}

pub fn to_u8_64(buf: &[u8]) -> Option<[u8; 64]> {
    if buf.len() < 64 {
        return None;
    }
    let mut array = [0u8; 64];
    for (&x, p) in buf.iter().zip(array.iter_mut()) {
        *p = x;
    }
    Some(array)
}

const HEX_DIGITS: &[u8] = b"0123456789abcdef";

pub fn fmt_hex(xs: &[u8]) -> String {
    let mut v = Vec::with_capacity(xs.len() * 2);
    for x in xs {
        v.push(HEX_DIGITS[(x >> 4) as usize]);
        v.push(HEX_DIGITS[(x & 0xf) as usize])
    }
    unsafe { String::from_utf8_unchecked(v) }
}

pub const EMPTYSIGNATURE: Signature = Signature([0; SIGNATUREBYTES]);
