extern crate cbor;
use std::io::{Cursor, Read};
use std::error::Error;
use std::fmt;
use uuid::Uuid;
use cbor::Config;
use cbor::decoder::{DecodeError, DecodeResult, Decoder};
use cbor::encoder::{EncodeError, EncodeResult, Encoder};
use sodiumoxide::crypto::sign::{PublicKey, Signature, PUBLICKEYBYTES,
                                SIGNATUREBYTES};
use sodiumoxide::crypto::hash::sha256;

pub type EncoderVec = Encoder<Cursor<Vec<u8>>>;
pub type DecoderVec = Decoder<Cursor<Vec<u8>>>;

/// Run a CBOR encoder and get a bytestring.
///
/// `run_encoder` creates a new encoder, passes it to `enc` and then
/// converts the result to a `Vec<u8>`.
pub fn run_encoder(
    enc: &Fn(&mut EncoderVec) -> EncodeResult,
) -> Result<Vec<u8>, EncodeError> {
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

// Decoding errors /////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum MIDecodeError {
    /// A value (represented as an array) had wrong number of elements. The
    /// error provides: value's type, expected array size, actual array
    /// size.
    InvalidArrayLen(&'static str, usize, usize),
    /// A field was expected in a map, but was not found. The error
    /// provides: field's descriptive name (even if the key for the field is
    /// not a string but e.g. an integer).
    MissingField(&'static str),
    /// A field was encountered twice in a map. The error provides: field's
    /// descriptive name.
    DuplicateField(&'static str),
}

impl From<MIDecodeError> for DecodeError {
    fn from(error: MIDecodeError) -> Self {
        DecodeError::Other(Box::new(error))
    }
}

impl fmt::Display for MIDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            MIDecodeError::InvalidArrayLen(t, e, a) => write!(
                f,
                "Wrong length ({}): expected array of length {}, got {}",
                t, e, a
            ),
            MIDecodeError::MissingField(ref s) => {
                write!(f, "Missing field: {}", s)
            }
            MIDecodeError::DuplicateField(ref s) => {
                write!(f, "Duplicate field: {}", s)
            }
        }
    }
}

impl Error for MIDecodeError {
    fn description(&self) -> &str {
        "MIDecodeError"
    }
}

// Decoders for various types //////////////////////////////////////////////

pub fn decode_uuid<R: Read>(d: &mut Decoder<R>) -> DecodeResult<Uuid> {
    let b = &d.bytes()?;
    Uuid::from_bytes(b).map_err(|_err| {
        MIDecodeError::InvalidArrayLen("Uuid", 16, b.len()).into()
    })
}

pub fn decode_publickey<R: Read>(
    d: &mut Decoder<R>,
) -> DecodeResult<PublicKey> {
    let b = &d.bytes()?;
    PublicKey::from_slice(b).ok_or_else(|| {
        MIDecodeError::InvalidArrayLen("PublicKey", PUBLICKEYBYTES, b.len())
            .into()
    })
}

pub fn decode_signature<R: Read>(
    d: &mut Decoder<R>,
) -> DecodeResult<Signature> {
    let b = &d.bytes()?;
    Signature::from_slice(b).ok_or_else(|| {
        MIDecodeError::InvalidArrayLen("Signature", SIGNATUREBYTES, b.len())
            .into()
    })
}

pub fn decode_hash<R: Read>(
    d: &mut Decoder<R>,
) -> DecodeResult<sha256::Digest> {
    let b = &d.bytes()?;
    sha256::Digest::from_slice(b).ok_or_else(|| {
        MIDecodeError::InvalidArrayLen(
            "sha256::Digest",
            sha256::DIGESTBYTES,
            b.len(),
        ).into()
    })
}

// Helper macros (copied from proteus/internal/util.rs) ////////////////////

macro_rules! to_field {
    ($test: expr, $msg: expr) => {
        match $test {
            Some(val) => val,
            None => return Err(MIDecodeError::MissingField($msg).into())
        }
    }
}

macro_rules! uniq {
    ($msg: expr, $name: ident, $action: expr) => {
        if $name.is_some() {
            return Err(MIDecodeError::DuplicateField($msg).into())
        } else {
            $name = Some($action)
        }
    }
}
