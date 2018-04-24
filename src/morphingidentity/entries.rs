use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::hash::sha256::{hash, Digest};
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey, Signature, PUBLICKEYBYTES, SIGNATUREBYTES};
use cbor::{Decoder, Encoder, EncodeResult, DecodeResult};
use cbor::skip::Skip;
use uuid::Uuid;
use std::io::{Read, Write};
use journal::FullJournal;

use cbor_utils::{run_encoder, run_decoder};

const FORMAT_ENTRY_VERSION: u32 = 1;

#[derive(PartialEq, Clone, Debug)]
#[repr(u32)]
pub enum EntryType {
    Add = 1,
    Remove = 0,
}
impl EntryType {
    pub fn from_integer(x: u32) -> EntryType {
        match x {
            x if x == EntryType::Add as u32 => EntryType::Add,
            x if x == EntryType::Remove as u32 => EntryType::Remove,
            _ => EntryType::Remove,
        }
    }
}
#[repr(u32)]
pub enum CapType {
    AddCap = 0b01u32,
    RemoveCap = 0b10u32,
    NonRemovableCap = 0b100u32,
}
#[repr(u32)]
pub enum DeviceType {
    TemporaryDevice = 0u32,
    PermanentDevice = CapType::AddCap as u32 | CapType::RemoveCap as u32,
}

#[derive(PartialEq, Clone, Debug)]
pub struct JournalEntry {
    pub format_version: u32, // version of the data format of an entry
    pub journal_id: Uuid, // version of the current journal ID
    pub history_hash: Digest, // hash over previous versions
    pub extension_hash: Digest, // hash over the entry extension
    pub count: u32, // incremental version number, starts at 0
    pub operation: EntryType, // delete = 0, add = 1
    pub capabilities: u32, // capabilities
    pub subject_publickey: PublicKey, // public key of the device that should be added/removed
    pub issuer_publickey: PublicKey, // public key of the executing device
    pub subject_signature: Signature, // signature of the subject
    pub issuer_signature: Signature, // signature of the issuer
}

const EMPTYPUBLICKEY: PublicKey = PublicKey([0; PUBLICKEYBYTES]);
const EMPTYSIGNATURE: Signature = Signature([0; SIGNATUREBYTES]);

impl JournalEntry {
    pub fn new(format_version: u32,
               journal_id: Uuid,
               history_hash: Digest,
               count: u32,
               operation: EntryType,
               device_type: DeviceType)
               -> JournalEntry {
        JournalEntry {
            format_version: format_version,
            journal_id: journal_id,
            history_hash: history_hash,
            extension_hash: hash(&[]),
            count: count,
            operation: operation,
            capabilities: device_type as u32,
            subject_publickey: EMPTYPUBLICKEY,
            issuer_publickey: EMPTYPUBLICKEY,
            subject_signature: EMPTYSIGNATURE,
            issuer_signature: EMPTYSIGNATURE,
        }
    }
    pub fn set_identities(&mut self, subject_pk: &PublicKey, issuer_pk: &PublicKey) {
        self.subject_publickey = *subject_pk;
        self.issuer_publickey = *issuer_pk;
    }
    pub fn add_subject_signature(&mut self, secretkey: &SecretKey) -> bool {
        if self.operation == EntryType::Remove {
            return false;
        }
        self.subject_signature = sign::sign_detached(&self.partial_hash()[..], secretkey);
        self.verify_subject_signature()
    }
    pub fn add_issuer_signature(&mut self, key: &SecretKey) -> bool {
        self.issuer_signature = sign::sign_detached(&self.partial_hash()[..], key);
        self.verify_issuer_signature()
    }
    pub fn verify_subject_signature(&self) -> bool {
        sign::verify_detached(&self.subject_signature,
                              self.partial_hash().as_ref(),
                              &self.subject_publickey)
    }
    pub fn verify_issuer_signature(&self) -> bool {
        sign::verify_detached(&self.issuer_signature,
                              self.partial_hash().as_ref(),
                              &self.issuer_publickey)
    }
    pub fn capability_can_add(&self) -> bool {
        (self.capabilities & CapType::AddCap as u32) > 0
    }
    pub fn capability_can_remove(&self) -> bool {
        (self.capabilities & CapType::RemoveCap as u32) > 0
    }
    pub fn capability_cannot_be_removed(&self) -> bool {
        (self.capabilities & CapType::NonRemovableCap as u32) > 0
    }
    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult {
        e.object(11)?;
        e.u8(0)?; e.u32(self.format_version)?;
        e.u8(1)?; e.bytes(self.journal_id.as_bytes())?;
        e.u8(2)?; e.bytes(&self.history_hash[..])?;
        e.u8(3)?; e.bytes(&self.extension_hash[..])?;
        e.u8(4)?; e.u32(self.count)?;
        e.u8(5)?; e.u32(self.operation.clone() as u32)?;
        e.u8(6)?; e.u32(self.capabilities as u32)?;
        e.u8(7)?; e.bytes(&self.subject_publickey[..])?;
        e.u8(8)?; e.bytes(&self.issuer_publickey[..])?;
        e.u8(9)?; e.bytes(&self.subject_signature[..])?;
        e.u8(10)?; e.bytes(&self.issuer_signature[..])?;
        Ok(())
    }
    pub fn hash(&self) -> Digest {
        hash(&self.as_bytes())
    }
    /// Return a hash of the entry with signatures set to some default
    /// values.
    pub fn partial_hash(&self) -> Digest {
        let partial = JournalEntry { 
                subject_signature: EMPTYSIGNATURE,
                issuer_signature: EMPTYSIGNATURE,
                .. self.clone() };
        hash(&partial.as_bytes())
    }
    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<JournalEntry> {
        let n = d.object()?;
        let mut format_version    = None;
        let mut journal_id        = None;
        let mut history_hash      = None;
        let mut extension_hash    = None;
        let mut count             = None;
        let mut operation         = None;
        let mut capabilities      = None;
        let mut subject_publickey = None;
        let mut issuer_publickey  = None;
        let mut subject_signature = None;
        let mut issuer_signature  = None;

        use cbor_utils::*;
        for _ in 0 .. n {
            match d.u8()? {
                0 => uniq!("JournalEntry::format_version", format_version, d.u32()?),
                1 => uniq!("JournalEntry::journal_id", journal_id, decode_uuid(d)?),
                2 => uniq!("JournalEntry::history_hash", history_hash, decode_hash(d)?),
                3 => uniq!("JournalEntry::extension_hash", extension_hash, decode_hash(d)?),
                4 => uniq!("JournalEntry::count", count, d.u32()?),
                5 => uniq!("JournalEntry::operation", operation, EntryType::from_integer(d.u32()?)),
                6 => uniq!("JournalEntry::capabilities", capabilities, d.u32()?),
                7 => uniq!("JournalEntry::subject_publickey", subject_publickey, decode_publickey(d)?),
                8 => uniq!("JournalEntry::issuer_publickey", issuer_publickey, decode_publickey(d)?),
                9 => uniq!("JournalEntry::subject_signature", subject_signature, decode_signature(d)?),
                10 => uniq!("JournalEntry::issuer_signature", issuer_signature, decode_signature(d)?),
                _ => d.skip()?
            }
        }
        Ok(JournalEntry {
            format_version:    to_field!(format_version, "JournalEntry::format_version"),
            journal_id:        to_field!(journal_id, "JournalEntry::journal_id"),
            history_hash:      to_field!(history_hash, "JournalEntry::history_hash"),
            extension_hash:    to_field!(extension_hash, "JournalEntry::extension_hash"),
            count:             to_field!(count, "JournalEntry::count"),
            operation:         to_field!(operation, "JournalEntry::operation"),
            capabilities:      to_field!(capabilities, "JournalEntry::capabilities"),
            subject_publickey: to_field!(subject_publickey, "JournalEntry::subject_publickey"),
            issuer_publickey:  to_field!(issuer_publickey, "JournalEntry::issuer_publickey"),
            subject_signature: to_field!(subject_signature, "JournalEntry::subject_signature"),
            issuer_signature:  to_field!(issuer_signature, "JournalEntry::issuer_signature"),
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
    use rand_utils::GoodRand;

    #[test]
    fn journal_entry_roundtrip() {
        sodiumoxide::init();

        let entry = JournalEntry {
            format_version: FORMAT_ENTRY_VERSION,
            journal_id: GoodRand::rand(),
            history_hash: GoodRand::rand(),
            extension_hash: GoodRand::rand(),
            count: GoodRand::rand(),
            operation: EntryType::Add,
            capabilities: GoodRand::rand(),
            subject_publickey: GoodRand::rand(),
            issuer_publickey: GoodRand::rand(),
            subject_signature: GoodRand::rand(),
            issuer_signature: GoodRand::rand(),
        };
        assert_eq!(entry, JournalEntry::from_bytes(entry.as_bytes()).unwrap())
    }
}
