use capabilities::*;
use cbor::{DecodeResult, Decoder, EncodeResult, Encoder};
use sodiumoxide::crypto::sign::*;
use std::io::{Read, Write};

/// Specific operation done by an entry.
#[derive(PartialEq, Clone, Debug)]
pub enum Operation {
    JournalInit {
        /// Devices that should be present in the journal, along with their
        /// capabilities.
        devices: Vec<(Capabilities, PublicKey)>,
        // TODO JournalInit with an empty vector should never be allowed. non_empty crate?
        //TODO: create a new type later
    },

    /// Add a new device to the journal.
    DeviceAdd {
        /// Capabilities of the newly added device.
        capabilities: Capabilities,
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
        capabilities: Capabilities,
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
// TODO: use an enum here? Seems error-prone to have separate TAGS and size of amount of TAGS as constants
pub const OPERATIONS: u32 = 5;

/// Tags used for CBOR encoding/decoding
pub const TAG_DEVICE_BULK_ADD: u32 = 0;
pub const TAG_DEVICE_ADD: u32 = 1;
pub const TAG_DEVICE_REMOVE: u32 = 2;
pub const TAG_DEVICE_REPLACE: u32 = 3;
pub const TAG_DEVICE_SELF_REPLACE: u32 = 4;

impl Operation {
    pub fn set_subject_signature(&mut self, signature: Signature) {
        match *self {
            Operation::JournalInit { .. } => {}
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
            Operation::JournalInit { ref devices } => {
                e.array(2)?;
                e.u32(TAG_DEVICE_BULK_ADD)?;
                e.array(devices.len())?;
                for (capabilities, subject) in devices.iter() {
                    e.array(2)?;
                    e.u32(capabilities.0)?;
                    e.bytes(&subject[..])?;
                }
                Ok(())
            }
            Operation::DeviceAdd {
                capabilities,
                subject,
                subject_signature,
            } => {
                e.array(4)?;
                e.u32(TAG_DEVICE_ADD)?;
                e.u32(capabilities.0)?;
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
                e.u32(capabilities.0)?;
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
            TAG_DEVICE_BULK_ADD => {
                check_array_length("Operation::JournalInit", 2, len)?;
                let length = d.array()?;
                let mut devices = Vec::new();
                for _ in 0..length {
                    ensure_array_length(
                        d,
                        "Operation::JournalInit::(Capabilities,PublicKey)",
                        2,
                    )?;
                    let cap = Capabilities(d.u32()?);
                    let subject = decode_publickey(d)?;
                    devices.push((cap, subject));
                }
                Ok(Operation::JournalInit { devices })
            }
            TAG_DEVICE_ADD => {
                check_array_length("Operation::DeviceAdd", 4, len)?;
                Ok(Operation::DeviceAdd {
                    capabilities: Capabilities(d.u32()?),
                    subject: decode_publickey(d)?,
                    subject_signature: decode_signature(d)?,
                })
            }
            TAG_DEVICE_REMOVE => {
                check_array_length("Operation::DeviceRemove", 2, len)?;
                Ok(Operation::DeviceRemove {
                    subject: decode_publickey(d)?,
                })
            }
            TAG_DEVICE_REPLACE => {
                check_array_length("Operation::DeviceReplace", 5, len)?;
                Ok(Operation::DeviceReplace {
                    removed_subject: decode_publickey(d)?,
                    capabilities: Capabilities(d.u32()?),
                    added_subject: decode_publickey(d)?,
                    added_subject_signature: decode_signature(d)?,
                })
            }
            TAG_DEVICE_SELF_REPLACE => {
                check_array_length("Operation::DeviceSelfReplace", 3, len)?;
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
