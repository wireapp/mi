use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::hash::sha256::{hash, Digest};
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey, Signature, SIGNATUREBYTES};
use cbor::Encoder;
use ledger::FullLedger;

const FORMAT_VERSION: u32 = 1;

#[derive(PartialEq, Clone)]
#[repr(u8)]
pub enum EntryType {
    Add = 1,
    Remove = 0,
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
    pub fn encode_unsigned_entry(&self) -> Encoder<Vec<u8>> {
        let mut e = Encoder::from_memory();
        e.encode(&[self.format_version, self.ledger_id]).unwrap();
        e.encode(&self.history_hash[..]).unwrap();
        e.encode(&self.extension_hash[..]).unwrap();
        e.encode(&[self.count]).unwrap();
        e.encode(&[self.operation.clone() as u8]).unwrap();
        e.encode(&[self.capabilities.clone() as u32]).unwrap();
        e.encode(&self.issuer_publickey[..]).unwrap();
        e.encode(&self.subject_publickey[..]).unwrap();
        e
    }
    pub fn encode_signed_entry(&self) -> Encoder<Vec<u8>> {
        let mut e = self.encode_unsigned_entry();
        e.encode(&self.issuer_signature[..]).unwrap();
        e.encode(&self.subject_signature[..]).unwrap();
        e
    }
    pub fn partial_hash(&self) -> Digest {
        let mut e = self.encode_unsigned_entry();
        hash(e.as_bytes())
    }
    pub fn complete_hash(&self) -> Digest {
        let mut e = self.encode_signed_entry();
        hash(e.as_bytes())
    }
    pub fn advanced_hash(&self) -> Digest {
        self.complete_hash()
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
}

pub struct EntryExtension {
    pub format_version: u32,
    pub permanent_count: u8,
    pub permanent_subject_publickeys: Vec<PublicKey>,
}

impl EntryExtension {
    pub fn get_hash(&mut self) -> Digest {
        self.permanent_subject_publickeys.sort();
        let mut e = Encoder::from_memory();
        e.encode(&[self.format_version]).unwrap();
        e.encode(&[self.permanent_count]).unwrap();
        for i in 0..self.permanent_subject_publickeys.len() {
            e.encode(&self.permanent_subject_publickeys[i][..]).unwrap();
        }
        hash(e.as_bytes())
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
            permanent_count: permanent_devices.len() as u8,
            permanent_subject_publickeys: permanent_devices,
        }
    }
}
