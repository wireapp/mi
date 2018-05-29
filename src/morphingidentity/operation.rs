use cbor::{DecodeResult, Decoder, EncodeResult, Encoder};
use sodiumoxide::crypto::sign::*;
use std::error::Error;
use std::fmt;
use std::io::{Read, Write};

/// Specific operation done by an entry.
#[derive(PartialEq, Clone, Debug)]
pub enum Operation {
    /// Add a new device to the journal.
    DeviceAdd {
        /// Capabilities of the newly added device.
        capabilities: u32,
        /// Public key of the device that is being added.
        subject: PublicKey,
        /// A signature by the device.
        subject_signature: Signature,
    },

    /// Remove a device from the journal.
    DeviceRemove {
        /// Public key of the device that is being removed.
        subject: PublicKey,
    },

    /// Atomically remove one and add another device.
    DeviceReplace {
        /// Public key of the device that is being removed.
        removed_subject: PublicKey,
        /// Capabilities of the newly added device.
        capabilities: u32,
        /// Public key of the device that is being added.
        added_subject: PublicKey,
        /// A signature by the device.
        added_subject_signature: Signature,
    },

    /// Atomically update the key material of a device.
    DeviceSelfReplace {
        /// New public key that is being added.
        added_subject: PublicKey,
        /// A signature by the device.
        added_subject_signature: Signature,
    },
    // NB. When adding new types, don't forget to:
    //   * update `OPERATIONS`
    //   * update `rand_operation` in unit tests
    //   * add a `TAG_`
}

/// Number of different operations that we have currently.
pub const OPERATIONS: u32 = 4;

/// Tags used for CBOR encoding/decoding
pub const TAG_DEVICE_ADD: u32 = 0;
pub const TAG_DEVICE_REMOVE: u32 = 1;
pub const TAG_DEVICE_REPLACE: u32 = 2;
pub const TAG_DEVICE_SELF_REPLACE: u32 = 3;

impl Operation {
    pub fn set_subject_signature(&mut self, signature: Signature) {
        match *self {
            Operation::DeviceAdd {
                ref mut subject_signature,
                ..
            } => {
                *subject_signature = signature;
            }
            Operation::DeviceRemove { .. } => {}
            Operation::DeviceReplace {
                ref mut added_subject_signature,
                ..
            } => {
                *added_subject_signature = signature;
            }
            Operation::DeviceSelfReplace {
                ref mut added_subject_signature,
                ..
            } => {
                *added_subject_signature = signature;
            }
        }
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult {
        match *self {
            Operation::DeviceAdd {
                capabilities,
                subject,
                subject_signature,
            } => {
                e.array(4)?;
                e.u32(TAG_DEVICE_ADD)?;
                e.u32(capabilities)?;
                e.bytes(&subject[..])?;
                e.bytes(&subject_signature[..])?;
                Ok(())
            }
            Operation::DeviceRemove { subject } => {
                e.array(2)?;
                e.u32(TAG_DEVICE_REMOVE)?;
                e.bytes(&subject[..])?;
                Ok(())
            }
            Operation::DeviceReplace {
                removed_subject,
                capabilities,
                added_subject,
                added_subject_signature,
            } => {
                e.array(5)?;
                e.u32(TAG_DEVICE_REPLACE)?;
                e.bytes(&removed_subject[..])?;
                e.u32(capabilities)?;
                e.bytes(&added_subject[..])?;
                e.bytes(&added_subject_signature[..])?;
                Ok(())
            }
            Operation::DeviceSelfReplace {
                added_subject,
                added_subject_signature,
            } => {
                e.array(3)?;
                e.u32(TAG_DEVICE_SELF_REPLACE)?;
                e.bytes(&added_subject[..])?;
                e.bytes(&added_subject_signature[..])?;
                Ok(())
            }
        }
    }

    pub fn decode<R: Read>(d: &mut Decoder<R>) -> DecodeResult<Operation> {
        use cbor_utils::*;
        let len = d.array()?;
        let tag = d.u32()?;
        match tag {
            TAG_DEVICE_ADD => {
                if len != 4 {
                    return Err(MIDecodeError::InvalidArrayLength {
                        type_name: "Operation::DeviceAdd",
                        expected_length: 4,
                        actual_length: len,
                    }.into());
                }
                Ok(Operation::DeviceAdd {
                    capabilities: d.u32()?,
                    subject: decode_publickey(d)?,
                    subject_signature: decode_signature(d)?,
                })
            }
            TAG_DEVICE_REMOVE => {
                if len != 2 {
                    return Err(MIDecodeError::InvalidArrayLength {
                        type_name: "Operation::DeviceRemove",
                        expected_length: 2,
                        actual_length: len,
                    }.into());
                }
                Ok(Operation::DeviceRemove {
                    subject: decode_publickey(d)?,
                })
            }
            TAG_DEVICE_REPLACE => {
                if len != 5 {
                    return Err(MIDecodeError::InvalidArrayLength {
                        type_name: "Operation::DeviceReplace",
                        expected_length: 5,
                        actual_length: len,
                    }.into());
                }
                Ok(Operation::DeviceReplace {
                    removed_subject: decode_publickey(d)?,
                    capabilities: d.u32()?,
                    added_subject: decode_publickey(d)?,
                    added_subject_signature: decode_signature(d)?,
                })
            }
            TAG_DEVICE_SELF_REPLACE => {
                if len != 3 {
                    return Err(MIDecodeError::InvalidArrayLength {
                        type_name: "Operation::DeviceSelfReplace",
                        expected_length: 3,
                        actual_length: len,
                    }.into());
                }
                Ok(Operation::DeviceSelfReplace {
                    added_subject: decode_publickey(d)?,
                    added_subject_signature: decode_signature(d)?,
                })
            }
            _ => Err(MIDecodeError::UnknownOperation {
                found_tag: tag,
                max_known_tag: OPERATIONS - 1,
            }.into()),
        }
    }
}

// Errors //////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq)]
pub enum OperationError {
    /// *Addition:* there can be at most `device_limit` trusted devices at
    /// any time, and this limit has been exceeded.
    DeviceLimitExceeded { device_limit: u32 },
    /// *Addition or replacement:* a device that is being added to journal
    /// is already trusted by the journal and can't be added again.
    DeviceAlreadyTrusted,
    /// *Removal:* you're trying to remove the last trusted device from the
    /// journal.
    LastDevice,
    /// *Removal or replacement:* you're trying to remove a device that is
    /// not in the journal.
    SubjectNotFound,
}

impl fmt::Display for OperationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            OperationError::DeviceLimitExceeded { device_limit } => write!(
                f,
                "When trying to add a device, trusted device limit \
                 ({} devices) was exceeded",
                device_limit
            ),
            OperationError::DeviceAlreadyTrusted => write!(
                f,
                "The device that is being added (either by a 'DeviceAdd' \
                 or 'DeviceReplace' entry) is trusted already"
            ),
            OperationError::LastDevice => {
                write!(f, "Removing the last trusted device is not allowed")
            }
            OperationError::SubjectNotFound => write!(
                f,
                "Trying to remove or replace a device that is not in \
                 the journal"
            ),
        }
    }
}

impl Error for OperationError {
    fn description(&self) -> &str {
        "OperationError"
    }
}
