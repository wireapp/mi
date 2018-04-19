extern crate cbor;
use std::io::{Cursor, Read, Write};
use uuid::Uuid;
use cbor::Config;
use cbor::decoder::{DecodeError, DecodeResult, Decoder};
use cbor::encoder::{EncodeError, EncodeResult, Encoder};

pub type EncoderVec = Encoder<Cursor<Vec<u8>>>;
pub type DecoderVec = Decoder<Cursor<Vec<u8>>>;

/// Run a CBOR encoder and get a bytestring.
///
/// `run_encoder` creates a new encoder, passes it to `enc` and then
/// converts the result to a `Vec<u8>`.
pub fn run_encoder(enc: &Fn(&mut EncoderVec) -> EncodeResult) -> Result<Vec<u8>, EncodeError> {
    let mut e = Encoder::new(Cursor::new(Vec::new()));
    enc(&mut e).and(Ok(e.into_writer().into_inner()))
}

/// Run a CBOR decoder on a bytestring.
pub fn run_decoder<T>(
    bytes: Vec<u8>,
    dec: &Fn(&mut DecoderVec) -> DecodeResult<T>,
) -> DecodeResult<T> {
    dec(&mut Decoder::new(Config::default(), Cursor::new(bytes)))
}

/// Decode a UUID (as a 16 byte long bytestring) from CBOR.
pub fn decode_uuid<R: Read>(d: &mut Decoder<R>) -> DecodeResult<Uuid> {
    let b = &d.bytes()?;
    Uuid::from_bytes(b).map_err(|err| DecodeError::Other(From::from(format!("{}", err))))
}

/// Encode a UUID into CBOR.
pub fn encode_uuid<W: Write>(uuid: Uuid, e: &mut Encoder<W>) -> EncodeResult {
    e.bytes(uuid.as_bytes())
}

// Tests ////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_roundtrip() {
        let uuid = Uuid::new_v4();
        let uuid_enc = run_encoder(&|e| encode_uuid(uuid, e)).unwrap();
        let uuid_dec = run_decoder(uuid_enc, &|d| decode_uuid(d)).unwrap();
        assert_eq!(uuid, uuid_dec)
    }
}