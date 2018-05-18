use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::hash::sha256::{hash, Digest};
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey, Signature};
use cbor::{Decoder, Encoder, EncodeResult, DecodeResult};
use cbor::value::Key;
use cbor::skip::Skip;
use uuid::Uuid;
use std::io::{Read, Write};

use journal::FullJournal;
use utils::EMPTYSIGNATURE;
use cbor_utils::{run_encoder, run_decoder};

pub const FORMAT_ENTRY_VERSION: u32 = 0;

/// Specific operation done by an entry.
#[derive(PartialEq, Clone, Debug)]
pub enum Operation {

    /// Add a new client to the journal.
    ClientAdd {
        /// Capabilities of the newly added client.
        capabilities: u32,
        /// Public key of the client that is being added.
        subject: PublicKey,
        /// A signature by the client.
        subject_signature: Signature,
    },

    /// Remove a client from the journal.
    ClientRemove {
        /// Public key of the client that is being removed.
        subject: PublicKey,
    },

    /// Atomically remove one and add another client.
    ClientReplace {
        /// Public key of the client that is being removed.
        removed_subject: PublicKey,
        /// Capabilities of the newly added client.
        capabilities: u32,
        /// Public key of the client that is being added.
        added_subject: PublicKey,
        /// A signature by the client.
        added_subject_signature: Signature,
    },

    // NB. When adding new types, don't forget to:
    //   * update `OPERATIONS`
    //   * update `rand_operation` in unit tests
}

/// Number of different operations that we have currently.
pub const OPERATIONS: u32 = 3;

impl Operation {
    pub fn set_subject_signature(&mut self, signature: Signature) {
        match self {
            &mut Operation::ClientAdd { ref mut subject_signature, .. } => {
                *subject_signature = signature;
            },
            &mut Operation::ClientRemove { .. } => { },
            &mut Operation::ClientReplace { ref mut added_subject_signature, .. } => {
                *added_subject_signature = signature;
            },
        }
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult {
        match *self {
            Operation::ClientAdd { capabilities, subject, subject_signature } => {
                e.array(4)?;
                e.u32(0)?;                // tag 0
                e.u32(capabilities)?;
                e.bytes(&subject[..])?;
                e.bytes(&subject_signature[..])?;
                Ok(())
            },
            Operation::ClientRemove { subject } => {
                e.array(2)?;
                e.u32(1)?;                // tag 1
                e.bytes(&subject[..])?;
                Ok(())
            },
            Operation::ClientReplace { removed_subject, capabilities, added_subject, added_subject_signature } => {
                e.array(5)?;
                e.u32(2)?;                // tag 2
                e.bytes(&removed_subject[..])?;
                e.u32(capabilities)?;
                e.bytes(&added_subject[..])?;
                e.bytes(&added_subject_signature[..])?;
                Ok(())
            },
        }
    }

    pub fn decode<R: Read>(d: &mut Decoder<R>) -> DecodeResult<Operation> {
        use cbor_utils::*;

        let len = d.array()?;
        let tag = d.u32()?;
        match tag {
            0 => {
                if len != 4 {
                    return Err(MIDecodeError::InvalidArrayLength {
                        type_name: "Operation::ClientAdd",
                        expected_length: 4,
                        actual_length: len,
                    }.into());
                }
                Ok(Operation::ClientAdd {
                    capabilities: d.u32()?,
                    subject: decode_publickey(d)?,
                    subject_signature: decode_signature(d)?,
                })
            },
            1 => {
                if len != 2 {
                    return Err(MIDecodeError::InvalidArrayLength {
                        type_name: "Operation::ClientRemove",
                        expected_length: 2,
                        actual_length: len,
                    }.into());
                }
                Ok(Operation::ClientRemove {
                    subject: decode_publickey(d)?,
                })
            },
            2 => {
                if len != 5 {
                    return Err(MIDecodeError::InvalidArrayLength {
                        type_name: "Operation::ClientReplace",
                        expected_length: 5,
                        actual_length: len,
                    }.into());
                }
                Ok(Operation::ClientReplace {
                    removed_subject: decode_publickey(d)?,
                    capabilities: d.u32()?,
                    added_subject: decode_publickey(d)?,
                    added_subject_signature: decode_signature(d)?,
                })
            },
            _ => return Err(MIDecodeError::UnknownOperation {
                found_tag: tag,
                max_known_tag: OPERATIONS - 1,
            }.into()),
        }
    }
}

#[repr(u32)]
pub enum CapType {
    AddCap          = 0b001u32,
    RemoveCap       = 0b010u32,
    NonRemovableCap = 0b100u32,
}
#[repr(u32)]
pub enum DeviceType {
    TemporaryDevice = 0u32,
    PermanentDevice = CapType::AddCap as u32 | CapType::RemoveCap as u32,
}

/// Information about a trusted client.
#[derive(PartialEq, Clone, Debug)]
pub struct ClientInfo {
    /// Public key of the client.
    pub key: PublicKey,
    /// Capabilities of the client.
    pub capabilities: u32,
    /// Journal entry which was used to add the client.
    pub entry: JournalEntry,
}

impl ClientInfo {
    /// Can the client authorize addition of other clients?
    pub fn capability_can_add(&self) -> bool {
        (self.capabilities & CapType::AddCap as u32) > 0
    }
    /// Can the client authorize removal of other clients?
    pub fn capability_can_remove(&self) -> bool {
        (self.capabilities & CapType::RemoveCap as u32) > 0
    }
    /// Is it true that the client can not be removed from the journal?
    pub fn capability_cannot_be_removed(&self) -> bool {
        (self.capabilities & CapType::NonRemovableCap as u32) > 0
    }
}

#[derive(PartialEq, Clone, Debug)]
pub struct JournalEntry {
    /// Journal that the entry belongs to.
    pub journal_id: Uuid,

    /// Hash over previous versions.
    pub history_hash: Digest,

    /// Hash over the entry extension.
    pub extension_hash: Digest,

    /// Entry index, starts at 0.
    ///
    /// Also called in some places: `count`, `version`.
    pub index: u32,

    /// Operation done by the entry.
    pub operation: Operation,

    /// Entry creator.
    pub issuer: PublicKey,

    /// Entry creator's signature.
    pub signature: Signature,
}

impl JournalEntry {
    pub fn new(journal_id: Uuid,
               history_hash: Digest,
               index: u32,
               operation: Operation,
               issuer: PublicKey )
               -> JournalEntry {
        JournalEntry {
            journal_id: journal_id,
            history_hash: history_hash,
            extension_hash: hash(&[]),
            index: index,
            operation: operation,
            issuer: issuer,
            signature: EMPTYSIGNATURE,
        }
    }

    /// Sign the entry with the given key.
    ///
    /// We always sign the `partial_hash` of the entry (which does not go
    /// over any signatures contained in the entry).
    pub fn sign(&self, key: &SecretKey) -> Signature {
        sign::sign_detached(&self.partial_hash()[..], key)
    }

    /// Verify some signature of the entry (e.g. issuer's signature or
    /// subject's signature if present).
    ///
    /// Signatures are always verified against the `partial_hash` of the
    /// entry – i.e. any signatures contained in the entry are not
    /// considered parts of the signed message.
    pub fn verify_signature(&self, signee: &PublicKey, signature: &Signature) -> bool {
        sign::verify_detached(signature, self.partial_hash().as_ref(), signee)
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult {
        e.array(2)?;
        e.u32(FORMAT_ENTRY_VERSION)?;
        e.object(7)?;
        e.u8(0)?; e.bytes(self.journal_id.as_bytes())?;
        e.u8(1)?; e.bytes(&self.history_hash[..])?;
        e.u8(2)?; e.bytes(&self.extension_hash[..])?;
        e.u8(3)?; e.u32(self.index)?;
        e.u8(4)?; self.operation.encode(e)?;
        e.u8(5)?; e.bytes(&self.issuer[..])?;
        e.u8(6)?; e.bytes(&self.signature[..])?;
        Ok(())
    }

    pub fn hash(&self) -> Digest {
        hash(&self.as_bytes())
    }

    /// Return a hash of the entry with signatures set to some default
    /// values.
    pub fn partial_hash(&self) -> Digest {
        let mut partial = self.clone();
        partial.signature = EMPTYSIGNATURE;
        partial.operation.set_subject_signature(EMPTYSIGNATURE);
        hash(&partial.as_bytes())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<JournalEntry> {
        ensure_array_length(d, "JournalEntry", 2)?;
        let format_version = d.u32()?;
        if format_version > FORMAT_ENTRY_VERSION {
            return Err(MIDecodeError::UnsupportedEntryVersion {
                found_version: format_version,
                max_supported_version: FORMAT_ENTRY_VERSION,
            }.into());
        }

        let n = d.object()?;
        let mut journal_id        = None;
        let mut history_hash      = None;
        let mut extension_hash    = None;
        let mut index             = None;
        let mut operation         = None;
        let mut issuer            = None;
        let mut signature         = None;

        use cbor_utils::*;
        for _ in 0 .. n {
            let i = d.u8()?;
            let key = Key::u64(i as u64);
            match i {
                0 => uniq!(key, "JournalEntry::journal_id", journal_id, decode_uuid(d)?),
                1 => uniq!(key, "JournalEntry::history_hash", history_hash, decode_hash(d)?),
                2 => uniq!(key, "JournalEntry::extension_hash", extension_hash, decode_hash(d)?),
                3 => uniq!(key, "JournalEntry::index", index, d.u32()?),
                4 => uniq!(key, "JournalEntry::operation", operation, Operation::decode(d)?),
                5 => uniq!(key, "JournalEntry::issuer", issuer, decode_publickey(d)?),
                6 => uniq!(key, "JournalEntry::signature", signature, decode_signature(d)?),
                _ => d.skip()?
            }
        }
        Ok(JournalEntry {
            journal_id:     to_field!(Key::u64(0), "JournalEntry::journal_id", journal_id),
            history_hash:   to_field!(Key::u64(1), "JournalEntry::history_hash", history_hash),
            extension_hash: to_field!(Key::u64(2), "JournalEntry::extension_hash", extension_hash),
            index:          to_field!(Key::u64(3), "JournalEntry::index", index),
            operation:      to_field!(Key::u64(4), "JournalEntry::operation", operation),
            issuer:         to_field!(Key::u64(5), "JournalEntry::issuer", issuer),
            signature:      to_field!(Key::u64(6), "JournalEntry::signature", signature),
        })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        run_encoder(&|mut e| self.encode(&mut e)).unwrap()
    }

    pub fn from_bytes(bs: Vec<u8>) -> DecodeResult<Self> {
        run_decoder(bs, &|mut d| Self::decode(&mut d))
    }
}

pub struct EntryExtension {
    pub format_version: u32,
    pub permanent_count: u32,
    pub permanent_subject_publickeys: Vec<PublicKey>,
}

impl EntryExtension {
    pub fn get_hash(&mut self) -> Digest {
        self.permanent_subject_publickeys.sort();
        hash(&run_encoder(&|e| {
            e.u32(self.format_version)?;
            e.u32(self.permanent_count)?;
            for i in 0..self.permanent_subject_publickeys.len() {
                e.bytes(&self.permanent_subject_publickeys[i][..])?;
            }
            Ok(())
        }).unwrap())
    }

    pub fn create_extension(&self, journal: &FullJournal) -> EntryExtension {
        let trusted_devices = journal.get_trusted_devices();
        let mut permanent_devices: Vec<PublicKey> = Vec::new();
        for key in trusted_devices.keys() {
            permanent_devices.push(key.clone());
        }
        permanent_devices.sort();
        EntryExtension {
            format_version: FORMAT_ENTRY_VERSION,
            permanent_count: permanent_devices.len() as u32,
            permanent_subject_publickeys: permanent_devices,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use sodiumoxide;
    use rand_utils::{GoodRand, randombytes, randomnumber};

    /// Produce a random `Operation`.
    fn rand_operation() -> Operation {
        match <u32 as GoodRand>::rand() % OPERATIONS {
            0 => Operation::ClientAdd {
                capabilities: GoodRand::rand(),
                subject: GoodRand::rand(),
                subject_signature: GoodRand::rand(),
            },
            1 => Operation::ClientRemove {
                subject: GoodRand::rand(),
            },
            2 => Operation::ClientReplace {
                removed_subject: GoodRand::rand(),
                capabilities: GoodRand::rand(),
                added_subject: GoodRand::rand(),
                added_subject_signature: GoodRand::rand(),
            },
            _ => unreachable!(),
        }
    }

    /// Produce a random `JournalEntry`.
    fn rand_journal_entry() -> JournalEntry {
        JournalEntry {
            journal_id: GoodRand::rand(),
            history_hash: GoodRand::rand(),
            extension_hash: GoodRand::rand(),
            index: GoodRand::rand(),
            operation: rand_operation(),
            issuer: GoodRand::rand(),
            signature: GoodRand::rand(),
        }
    }

    #[test]
    /// Test that encoding/decoding operations for `JournalEntry` are
    /// inverses.
    fn journal_entry_roundtrip() {
        sodiumoxide::init();
        for _ in 0..100 {
            let entry = rand_journal_entry();
            assert_eq!(entry, JournalEntry::from_bytes(entry.as_bytes()).unwrap())
        }
    }

    #[test]
    /// Test that decoding random garbage bytes as `JournalEntry` doesn't
    /// work.
    fn journal_entry_garbage() {
        sodiumoxide::init();
        for _ in 0..100 {
            let size = randomnumber(1000) as usize;
            let garbage = randombytes(size);
            assert!(JournalEntry::from_bytes(garbage).is_err());
        }
    }
}
