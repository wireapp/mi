extern crate cbor;
use cbor::decoder::{DecodeError, DecodeResult, Decoder};
use cbor::encoder::{EncodeError, EncodeResult, Encoder};
use cbor::value::Key;
use cbor::Config;
use journal::JournalID;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::sign::{
    PublicKey, Signature, PUBLICKEYBYTES, SIGNATUREBYTES,
};
use std::error::Error;
use std::fmt;
use std::io::{Cursor, Read};

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

/// Run a CBOR decoder on a bytestring and ensure that the whole bytestring
/// has been consumed.
pub fn run_decoder_full<T>(
    bytes: Vec<u8>,
    dec: &Fn(&mut DecoderVec) -> DecodeResult<T>,
) -> DecodeResult<T> {
    let len = bytes.len();
    let mut d = Decoder::new(Config::default(), Cursor::new(bytes));
    let res = dec(&mut d)?;
    if d.into_reader().position() as usize == len {
        Ok(res)
    } else {
        Err(MIDecodeError::LeftoverInput.into())
    }
}

// Decoding errors /////////////////////////////////////////////////////////

#[derive(Debug, PartialEq)]
pub enum MIDecodeError {
    /// Journal format version is unsupported.
    UnsupportedJournalVersion {
        found_version: u32,
        max_supported_version: u32,
    },
    /// Journal is empty.
    EmptyJournal,
    /// Entry format version is unsupported.
    UnsupportedEntryVersion {
        found_version: u32,
        max_supported_version: u32,
    },
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
    /// After decoding there is still some input left.
    LeftoverInput,
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
            MIDecodeError::UnsupportedEntryVersion {
                found_version,
                max_supported_version,
            } => write!(
                f,
                "Unsupported entry version {} (max {} is supported)",
                found_version, max_supported_version
            ),
            MIDecodeError::UnknownOperation {
                found_tag,
                max_known_tag,
            } => write!(
                f,
                "Unknown 'Operation' type: {} (max known is {})",
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
            MIDecodeError::LeftoverInput => write!(f, "Leftover input"),
        }
    }
}

impl Error for MIDecodeError {
    fn description(&self) -> &str {
        "MIDecodeError"
    }
}

// Decoding-related utilities //////////////////////////////////////////////

/// Parse the header of an array which *has* to have a specific length.
pub fn ensure_array_length<R: Read>(
    d: &mut Decoder<R>,
    type_name: &'static str,
    expected_length: usize,
) -> DecodeResult<()> {
    let actual_length = d.array()?;
    if actual_length != expected_length {
        return Err(MIDecodeError::InvalidArrayLength {
            type_name,
            expected_length,
            actual_length,
        }.into());
    };
    Ok(())
}

// Decoders for various types //////////////////////////////////////////////

pub fn decode_journal_id<R: Read>(
    d: &mut Decoder<R>,
) -> DecodeResult<JournalID> {
    let b = &d.bytes()?;
    JournalID::from_bytes(b).map_err(|_err| {
        MIDecodeError::InvalidArrayLength {
            type_name: "JournalID",
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
    ($key:expr, $field:expr, $var:expr) => {
        match $var {
            Some(val) => val,
            None => {
                return Err(MIDecodeError::MissingField {
                    field_name: $field,
                    field_key: $key,
                }.into())
            }
        }
    };
}

macro_rules! uniq {
    ($key:expr, $field:expr, $var:ident, $decode_action:expr) => {
        if $var.is_some() {
            return Err(MIDecodeError::DuplicateField {
                field_name: $field,
                field_key: $key,
            }.into());
        } else {
            $var = Some($decode_action)
        }
    };
}
