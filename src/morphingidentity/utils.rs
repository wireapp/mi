extern crate cbor;

const HEX_DIGITS: &'static [u8] = b"0123456789abcdef";

pub fn fmt_hex(xs: &[u8]) -> String {
    let mut v = Vec::with_capacity(xs.len() * 2);
    for x in xs {
        v.push(HEX_DIGITS[(x >> 4) as usize]);
        v.push(HEX_DIGITS[(x & 0xf) as usize])
    }
    unsafe { String::from_utf8_unchecked(v) }
}

#[allow(dead_code)]
pub fn injective_concat() -> [u8; 1] {
    [0]
}
