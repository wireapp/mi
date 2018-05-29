use cbor::skip::Skip;
use cbor::value::Key;
use cbor::{DecodeResult, Decoder, EncodeResult, Encoder};
use sodiumoxide::crypto::hash::sha256::{hash, Digest};
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey, Signature};
use std::io::{Read, Write};

use cbor_utils::{run_decoder_full, run_encoder};
use journal::{FullJournal, JournalID};
use operation::*;
use utils::EMPTYSIGNATURE;

pub const FORMAT_ENTRY_VERSION: u32 = 0;

#[repr(u32)]
#[cfg_attr(rustfmt, rustfmt_skip)]
pub enum CapType {
    AddCap          = 0b0001u32,
    RemoveCap       = 0b0010u32,
    NonRemovableCap = 0b0100u32,
    SelfUpdateCap   = 0b1000u32,
}
#[repr(u32)]
pub enum DeviceType {
    TemporaryDevice = 0u32,
    PermanentDevice = CapType::AddCap as u32
        | CapType::RemoveCap as u32
        | CapType::SelfUpdateCap as u32,
}

/// Information about a trusted device.
#[derive(PartialEq, Clone, Debug)]
pub struct DeviceInfo {
    /// Public key of the device.
    pub key: PublicKey,
    /// Capabilities of the device.
    pub capabilities: u32,
    /// Journal entry which was used to add the device.
    pub entry: JournalEntry,
}

impl DeviceInfo {
    /// Can the device authorize addition of other devices?
    pub fn capability_can_add(&self) -> bool {
        (self.capabilities & CapType::AddCap as u32) > 0
    }
    /// Can the device authorize removal of other devices?
    pub fn capability_can_remove(&self) -> bool {
        (self.capabilities & CapType::RemoveCap as u32) > 0
    }
    /// Is it true that the device can not be removed from the journal?
    pub fn capability_cannot_be_removed(&self) -> bool {
        (self.capabilities & CapType::NonRemovableCap as u32) > 0
    }
    /// Can the device self-update?
    pub fn capability_can_self_update(&self) -> bool {
        (self.capabilities & CapType::SelfUpdateCap as u32) > 0
    }
}

#[derive(PartialEq, Clone, Debug)]
pub struct JournalEntry {
    /// Journal that the entry belongs to.
    pub journal_id: JournalID,

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
    pub fn new(
        journal_id: JournalID,
        history_hash: Digest,
        index: u32,
        operation: Operation,
        issuer: PublicKey,
    ) -> JournalEntry {
        JournalEntry {
            journal_id,
            history_hash,
            extension_hash: hash(&[]),
            index,
            operation,
            issuer,
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
    pub fn verify_signature(
        &self,
        signee: &PublicKey,
        signature: &Signature,
    ) -> bool {
        sign::verify_detached(
            signature,
            self.partial_hash().as_ref(),
            signee,
        )
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult {
        e.array(2)?;
        e.u32(FORMAT_ENTRY_VERSION)?;
        e.object(7)?;
        e.u8(0)?;
        e.bytes(self.journal_id.as_bytes())?;
        e.u8(1)?;
        e.bytes(&self.history_hash[..])?;
        e.u8(2)?;
        e.bytes(&self.extension_hash[..])?;
        e.u8(3)?;
        e.u32(self.index)?;
        e.u8(4)?;
        self.operation.encode(e)?;
        e.u8(5)?;
        e.bytes(&self.issuer[..])?;
        e.u8(6)?;
        e.bytes(&self.signature[..])?;
        Ok(())
    }

    pub fn hash(&self) -> Digest {
        hash(&self.as_bytes())
    }

    /// Return a hash of the entry with signatures set to some default
    /// value.
    pub fn partial_hash(&self) -> Digest {
        let mut partial = self.clone();
        partial.signature = EMPTYSIGNATURE;
        partial.operation.set_subject_signature(EMPTYSIGNATURE);
        hash(&partial.as_bytes())
    }

    pub fn decode<R: Read + Skip>(
        d: &mut Decoder<R>,
    ) -> DecodeResult<JournalEntry> {
        ensure_array_length(d, "JournalEntry", 2)?;
        let format_version = d.u32()?;
        if format_version > FORMAT_ENTRY_VERSION {
            return Err(MIDecodeError::UnsupportedEntryVersion {
                found_version: format_version,
                max_supported_version: FORMAT_ENTRY_VERSION,
            }.into());
        }

        let n = d.object()?;
        let mut journal_id = None;
        let mut history_hash = None;
        let mut extension_hash = None;
        let mut index = None;
        let mut operation = None;
        let mut issuer = None;
        let mut signature = None;

        use cbor_utils::*;
        for _ in 0..n {
            let i = d.u8()?;
            let key = Key::u64(u64::from(i));
            match i {
                0 => uniq!(
                    key,
                    "JournalEntry::journal_id",
                    journal_id,
                    decode_journal_id(d)?
                ),
                1 => uniq!(
                    key,
                    "JournalEntry::history_hash",
                    history_hash,
                    decode_hash(d)?
                ),
                2 => uniq!(
                    key,
                    "JournalEntry::extension_hash",
                    extension_hash,
                    decode_hash(d)?
                ),
                3 => uniq!(key, "JournalEntry::index", index, d.u32()?),
                4 => uniq!(
                    key,
                    "JournalEntry::operation",
                    operation,
                    Operation::decode(d)?
                ),
                5 => uniq!(
                    key,
                    "JournalEntry::issuer",
                    issuer,
                    decode_publickey(d)?
                ),
                6 => uniq!(
                    key,
                    "JournalEntry::signature",
                    signature,
                    decode_signature(d)?
                ),
                _ => d.skip()?,
            }
        }
        Ok(JournalEntry {
            journal_id: to_field!(
                Key::u64(0),
                "JournalEntry::journal_id",
                journal_id
            ),
            history_hash: to_field!(
                Key::u64(1),
                "JournalEntry::history_hash",
                history_hash
            ),
            extension_hash: to_field!(
                Key::u64(2),
                "JournalEntry::extension_hash",
                extension_hash
            ),
            index: to_field!(Key::u64(3), "JournalEntry::index", index),
            operation: to_field!(
                Key::u64(4),
                "JournalEntry::operation",
                operation
            ),
            issuer: to_field!(Key::u64(5), "JournalEntry::issuer", issuer),
            signature: to_field!(
                Key::u64(6),
                "JournalEntry::signature",
                signature
            ),
        })
    }

    /// Encode an entry as CBOR.
    pub fn as_bytes(&self) -> Vec<u8> {
        run_encoder(&|mut e| self.encode(&mut e)).unwrap()
    }

    /// Decode the entry from CBOR.
    pub fn from_bytes(bs: Vec<u8>) -> DecodeResult<Self> {
        run_decoder_full(bs, &|mut d| Self::decode(&mut d))
    }
}

pub struct EntryExtension {
    pub format_version: u32,
    pub permanent_count: u32,
    pub permanent_subject_publickeys: Vec<PublicKey>,
}

impl EntryExtension {
    pub fn hash(&mut self) -> Digest {
        self.permanent_subject_publickeys.sort();
        hash(
            &run_encoder(&|e| {
                e.u32(self.format_version)?;
                e.u32(self.permanent_count)?;
                for i in 0..self.permanent_subject_publickeys.len() {
                    e.bytes(&self.permanent_subject_publickeys[i][..])?;
                }
                Ok(())
            }).unwrap(),
        )
    }

    pub fn create_extension(
        &self,
        journal: &FullJournal,
    ) -> EntryExtension {
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

    use cbor::DecodeError;
    use cbor_utils::MIDecodeError;
    use rand_utils::{randombytes, randomnumber, GoodRand};
    use sodiumoxide;

    /// Produce a random `Operation`.
    fn rand_operation() -> Operation {
        match <u32 as GoodRand>::rand() % OPERATIONS {
            TAG_DEVICE_ADD => Operation::DeviceAdd {
                capabilities: GoodRand::rand(),
                subject: GoodRand::rand(),
                subject_signature: GoodRand::rand(),
            },
            TAG_DEVICE_REMOVE => Operation::DeviceRemove {
                subject: GoodRand::rand(),
            },
            TAG_DEVICE_REPLACE => Operation::DeviceReplace {
                removed_subject: GoodRand::rand(),
                capabilities: GoodRand::rand(),
                added_subject: GoodRand::rand(),
                added_subject_signature: GoodRand::rand(),
            },
            TAG_DEVICE_SELF_REPLACE => Operation::DeviceSelfReplace {
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
            assert_eq!(
                entry,
                JournalEntry::from_bytes(entry.as_bytes()).unwrap()
            )
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

    #[test]
    /// Test that decoding an entry with some bytes appended to it doesn't
    /// work.
    fn journal_entry_remainder() {
        sodiumoxide::init();
        for _ in 0..100 {
            let mut bytes = rand_journal_entry().as_bytes();
            let size = 1 + randomnumber(100) as usize;
            let mut garbage = randombytes(size);
            bytes.append(&mut garbage);
            let res = JournalEntry::from_bytes(bytes);
            let res_str = format!("{:?}", res);
            if let Err(DecodeError::Other(err)) = res {
                if let Ok(mi) = err.downcast::<MIDecodeError>() {
                    if let MIDecodeError::LeftoverInput = *mi {
                        continue;
                    }
                }
            }
            panic!(
                "expected MIDecodeError::LeftoverInput, got {}",
                res_str
            );
        }
    }
}
