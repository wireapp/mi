use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::hash::sha256::{hash, Digest, DIGESTBYTES};
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey, Signature, SIGNATUREBYTES,
                                         PUBLICKEYBYTES};
use cbor::{Config, Decoder, Encoder, DecodeResult};
use std::io::Cursor;
use ledger::FullLedger;

use utils::{to_u8_32, to_u8_64};

const FORMAT_VERSION: u32 = 1;

#[derive(PartialEq, Clone)]
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

#[derive(Clone)]
#[derive(PartialEq)]
pub struct LedgerEntry {
    pub format_version: u32, // version of the data format of an entry
    pub ledger_id: u32, // version of the current ledger ID
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

impl LedgerEntry {
    pub fn new(format_version: u32,
               ledger_id: u32,
               history_hash: Digest,
               count: u32,
               operation: EntryType,
               device_type: DeviceType)
               -> LedgerEntry {
        let empty_key = PublicKey::from_slice(&[0; sign::PUBLICKEYBYTES]).unwrap();
        let empty_signature = Signature::from_slice(&[0; SIGNATUREBYTES]).unwrap();
        LedgerEntry {
            format_version: format_version,
            ledger_id: ledger_id,
            history_hash: history_hash,
            extension_hash: hash(&[]),
            count: count,
            operation: operation,
            capabilities: device_type as u32,
            subject_publickey: empty_key,
            issuer_publickey: empty_key,
            subject_signature: empty_signature,
            issuer_signature: empty_signature,
        }
    }
    pub fn set_identities(&mut self, subject_pk: &PublicKey, issuer_pk: &PublicKey) {
        self.subject_publickey = subject_pk.clone();
        self.issuer_publickey = issuer_pk.clone();
    }
    pub fn add_subject_signature(&mut self, secretkey: &SecretKey) -> bool {
        if self.operation == EntryType::Remove {
            return false;
        }
        self.subject_signature = sign::sign_detached(&self.partial_hash()[..], &secretkey);
        self.verify_subject_signature()
    }
    pub fn add_issuer_signature(&mut self, key: &SecretKey) -> bool {
        self.issuer_signature = sign::sign_detached(&self.partial_hash()[..], &key);
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
    pub fn encode_unsigned_entry(&self) -> Encoder<Cursor<Vec<u8>>> {
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        e.u32(self.format_version).unwrap();
        e.u32(self.ledger_id).unwrap();
        e.bytes(&self.history_hash[..]).unwrap();
        e.bytes(&self.extension_hash[..]).unwrap();
        e.u32(self.count).unwrap();
        e.u32(self.operation.clone() as u32).unwrap();
        e.u32(self.capabilities.clone() as u32).unwrap();
        e.bytes(&self.subject_publickey[..]).unwrap();
        e.bytes(&self.issuer_publickey[..]).unwrap();
        e
    }
    pub fn encode_signed_entry(&self) -> Encoder<Cursor<Vec<u8>>> {
        let mut e = self.encode_unsigned_entry();
        e.bytes(&self.subject_signature[..]).unwrap();
        e.bytes(&self.issuer_signature[..]).unwrap();
        e
    }
    pub fn partial_hash(&self) -> Digest {
        let e = self.encode_unsigned_entry();
        hash(&e.into_writer().into_inner())
    }
    pub fn complete_hash(&self) -> Digest {
        let e = self.encode_signed_entry();
        hash(&e.into_writer().into_inner())
    }
    pub fn advanced_hash(&self) -> Digest {
        self.complete_hash()
    }
    pub fn encode_as_cbor(&self) -> Vec<u8> {
        self.encode_signed_entry().into_writer().into_inner()
    }
    pub fn new_from_cbor(bytes: Vec<u8>) -> DecodeResult<LedgerEntry> {
        let mut d = Decoder::new(Config::default(), Cursor::new(&bytes[..]));
        Ok(LedgerEntry {
            format_version: d.u32()?,
            ledger_id: d.u32()?,
            history_hash: Digest(to_u8_32(&d.bytes()?[0..DIGESTBYTES]).unwrap()),
            extension_hash: Digest(to_u8_32(&d.bytes()?[0..DIGESTBYTES]).unwrap()),
            count: d.u32()?,
            operation: EntryType::from_integer(d.u32()?),
            capabilities: d.u32()?,
            subject_publickey: PublicKey(to_u8_32(&d.bytes()?[0..PUBLICKEYBYTES]).unwrap()),
            issuer_publickey: PublicKey(to_u8_32(&d.bytes()?[0..PUBLICKEYBYTES]).unwrap()),
            subject_signature: Signature(to_u8_64(&d.bytes()?[0..SIGNATUREBYTES]).unwrap()),
            issuer_signature: Signature(to_u8_64(&d.bytes()?[0..SIGNATUREBYTES]).unwrap()),
        })
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
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        e.u32(self.format_version).unwrap();
        e.u32(self.permanent_count).unwrap();
        for i in 0..self.permanent_subject_publickeys.len() {
            e.bytes(&self.permanent_subject_publickeys[i][..]).unwrap();
        }
        hash(&e.into_writer().into_inner())
    }
    pub fn create_extension(&self, ledger: &FullLedger) -> EntryExtension {
        let trusted_devices = ledger.get_trusted_devices();
        let mut permanent_devices: Vec<PublicKey> = Vec::new();
        for key in trusted_devices.keys() {
            permanent_devices.push(key.clone());
        }
        permanent_devices.sort();
        EntryExtension {
            format_version: FORMAT_VERSION,
            permanent_count: permanent_devices.len() as u32,
            permanent_subject_publickeys: permanent_devices,
        }
    }
}
