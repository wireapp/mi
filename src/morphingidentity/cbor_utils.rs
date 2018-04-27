extern crate cbor;
use std::io::{Cursor, Read};
use std::error::Error;
use std::fmt;
use uuid::Uuid;
use cbor::Config;
use cbor::decoder::{DecodeError, DecodeResult, Decoder};
use cbor::encoder::{EncodeError, EncodeResult, Encoder};
use cbor::value::Key;
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
    /// Journal version is unsupported.
    UnsupportedJournalVersion {
        found_version: u32,
        max_supported_version: u32,
    },
    /// Journal is empty.
    EmptyJournal,
    /// Unknown operation tag.
    UnknownOperation { found_tag: u32, max_known_tag: u32 },
    /// A value (represented as an array) has wrong number of elements.
    InvalidArrayLength {
        type_name: &'static str,
        expected_length: usize,
        actual_length: usize,
    },
    /// A field was expected in a map, but was not found.
    MissingField {
        field_name: &'static str,
        field_key: Key,
    },
    /// A field was encountered twice in a map.
    DuplicateField {
        field_name: &'static str,
        field_key: Key,
    },
}

impl From<MIDecodeError> for DecodeError {
    fn from(error: MIDecodeError) -> Self {
        DecodeError::Other(Box::new(error))
    }
}

impl fmt::Display for MIDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            MIDecodeError::UnsupportedJournalVersion {
                found_version,
                max_supported_version,
            } => write!(
                f,
                "Unsupported journal version {} (max {} is supported)",
                found_version, max_supported_version
            ),
            MIDecodeError::EmptyJournal => write!(f, "Empty journal"),
            MIDecodeError::UnknownOperation {
                found_tag,
                max_known_tag,
            } => write!(
                f,
                "Unknown tag {} when decoding an 'Operation' (max known is {})",
                found_tag, max_known_tag
            ),
            MIDecodeError::InvalidArrayLength {
                type_name,
                expected_length,
                actual_length,
            } => write!(
                f,
                "Wrong length ({}): expected array of length {}, got {}",
                type_name, expected_length, actual_length
            ),
            MIDecodeError::MissingField {
                field_name,
                ref field_key,
            } => write!(
                f,
                "Missing field: {} (key {:?})",
                field_name, field_key
            ),
            MIDecodeError::DuplicateField {
                field_name,
                ref field_key,
            } => write!(
                f,
                "Duplicate field: {} (key {:?})",
                field_name, field_key
            ),
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
        MIDecodeError::InvalidArrayLength {
            type_name: "Uuid",
            expected_length: 16,
            actual_length: b.len(),
        }.into()
    })
}

pub fn decode_publickey<R: Read>(
    d: &mut Decoder<R>,
) -> DecodeResult<PublicKey> {
    let b = &d.bytes()?;
    PublicKey::from_slice(b).ok_or_else(|| {
        MIDecodeError::InvalidArrayLength {
            type_name: "PublicKey",
            expected_length: PUBLICKEYBYTES,
            actual_length: b.len(),
        }.into()
    })
}

pub fn decode_signature<R: Read>(
    d: &mut Decoder<R>,
) -> DecodeResult<Signature> {
    let b = &d.bytes()?;
    Signature::from_slice(b).ok_or_else(|| {
        MIDecodeError::InvalidArrayLength {
            type_name: "Signature",
            expected_length: SIGNATUREBYTES,
            actual_length: b.len(),
        }.into()
    })
}

pub fn decode_hash<R: Read>(
    d: &mut Decoder<R>,
) -> DecodeResult<sha256::Digest> {
    let b = &d.bytes()?;
    sha256::Digest::from_slice(b).ok_or_else(|| {
        MIDecodeError::InvalidArrayLength {
            type_name: "sha256::Digest",
            expected_length: sha256::DIGESTBYTES,
            actual_length: b.len(),
        }.into()
    })
}

// Helper macros (copied from proteus/internal/util.rs) ////////////////////

macro_rules! to_field {
    ($key: expr, $field: expr, $var: expr) => {
        match $var {
            Some(val) => val,
            None => return Err(MIDecodeError::MissingField {
                field_name: $field,
                field_key: $key,
            }.into())
        }
    }
}

macro_rules! uniq {
    ($key: expr, $field: expr, $var: ident, $decode_action: expr) => {
        if $var.is_some() {
            return Err(MIDecodeError::DuplicateField {
                field_name: $field,
                field_key: $key,
            }.into())
        } else {
            $var = Some($decode_action)
        }
    }
}
