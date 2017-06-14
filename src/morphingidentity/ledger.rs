use entries::{LedgerEntry, EntryType, DeviceType};
use utils::fmt_hex;
use sodiumoxide::crypto::hash::sha256::{hash, Digest};
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey};
use std::collections::HashMap;

const FORMAT_VERSION: u32 = 1;
const MAX_DEVICES: usize = 8;

pub struct FullLedger {
    version: u32,
    ledger_id: u32,
    hash: Digest,
    entries: Vec<LedgerEntry>,
    trusted_devices: HashMap<PublicKey, LedgerEntry>,
}

impl FullLedger {
    pub fn new(_ledger_id: u32,
               issuer_publickey: &PublicKey,
               issuer_sk: &SecretKey)
               -> Option<FullLedger> {
        let mut le: LedgerEntry = LedgerEntry::new(FORMAT_VERSION,
                                                   _ledger_id,
                                                   hash(&[]),
                                                   0,
                                                   EntryType::Add,
                                                   DeviceType::PermanentDevice);
        le.set_identities(issuer_publickey, issuer_publickey);
        if !le.add_issuer_signature(issuer_sk) || !le.add_subject_signature(issuer_sk) {
            return None;
        }
        let mut entries: Vec<LedgerEntry> = Vec::new();
        entries.push(le.clone());
        let mut _trusted_devices: HashMap<PublicKey, LedgerEntry> = HashMap::new();
        _trusted_devices.insert(*issuer_publickey, le);
        Some(FullLedger {
            version: 0,
            ledger_id: _ledger_id,
            entries: entries,
            trusted_devices: _trusted_devices,
            hash: hash(&[]),
        })
    }
    pub fn create_entry(&self,
                        operation: EntryType,
                        device_type: DeviceType,
                        issuer_publickey: &PublicKey,
                        issuer_secretkey: &SecretKey,
                        subject_publickey: &PublicKey)
                        -> Option<LedgerEntry> {
        if (operation == EntryType::Add && self.trusted_devices.len() >= MAX_DEVICES) ||
           (operation == EntryType::Remove && self.trusted_devices.len() < 2) ||
           self.entries.len() >= u32::max_value() as usize || self.entries.is_empty() ||
           !self.trusted_devices.contains_key(issuer_publickey) ||
           (self.trusted_devices.contains_key(subject_publickey) && operation == EntryType::Add) ||
           (!self.trusted_devices.contains_key(subject_publickey) &&
            operation == EntryType::Remove) {
            return None;
        }
        let mut le: LedgerEntry = LedgerEntry::new(FORMAT_VERSION,
                                                   self.ledger_id,
                                                   self.entries.last().unwrap().advanced_hash(),
                                                   self.version + 1,
                                                   operation,
                                                   device_type);
        le.set_identities(subject_publickey, issuer_publickey);
        if !le.add_issuer_signature(issuer_secretkey) {
            return None;
        }
        Some(le)
    }
    pub fn sign_entry_as_subject(&self,
                                 le: &mut LedgerEntry,
                                 subject_secretkey: &SecretKey)
                                 -> bool {
        le.add_subject_signature(subject_secretkey)
    }
    pub fn test_entry(&self, le: &LedgerEntry) -> bool {
        if (le.operation == EntryType::Add && self.trusted_devices.len() >= MAX_DEVICES) ||
           (le.operation == EntryType::Remove && self.trusted_devices.len() < 2) ||
           self.version >= u32::max_value() || le.format_version != FORMAT_VERSION ||
           le.ledger_id != self.ledger_id ||
           &self.entries.last().unwrap().advanced_hash()[..] != &le.history_hash[..] ||
           le.count != (self.version + 1) {
            return false;
        }
        if le.operation == EntryType::Add {
            return self.trusted_devices.contains_key(&le.issuer_publickey) &&
                   le.verify_issuer_signature() &&
                   le.verify_subject_signature() &&
                   !self.trusted_devices.contains_key(&le.subject_publickey);
        } else if le.operation == EntryType::Remove {
            return self.trusted_devices.contains_key(&le.issuer_publickey) &&
                   le.verify_issuer_signature() &&
                   self.trusted_devices.contains_key(&le.subject_publickey);
        }
        false
    }
    pub fn add_entry(&mut self, le: LedgerEntry) -> bool {
        if self.test_entry(&le) {
            self.entries.push(le.clone());
            if le.operation == EntryType::Add {
                self.trusted_devices.insert(le.subject_publickey.clone(), le.clone());
            } else if le.operation == EntryType::Remove {
                self.trusted_devices.remove(&le.subject_publickey);
            }
            self.hash = self.entries.last().unwrap().advanced_hash();
            self.version += 1;
            return true;
        }
        false
    }
    pub fn check_ledger(&mut self) -> bool {
        println!("check_ledger: started");
        let mut trusted_devices: HashMap<PublicKey, LedgerEntry> = HashMap::new();
        if self.entries.is_empty() {
            return false;
        }
        let first_entry: &LedgerEntry = self.entries.first().unwrap();
        if first_entry.operation != EntryType::Add {
            return false;
        }
        if first_entry.subject_publickey != first_entry.issuer_publickey {
            return false;
        }
        if !first_entry.verify_issuer_signature() {
            return false;
        }
        trusted_devices.insert(first_entry.issuer_publickey.clone(), first_entry.clone());
        if self.entries.len() == 1 {
            println!("check_ledger: only 1 device in ledger");
            self.trusted_devices = trusted_devices;
            return true;
        }
        println!("check_ledger: Found {} entries", self.entries.len());
        for i in 1..(self.entries.len()) {
            let le = self.entries.get(i).unwrap();
            if le.ledger_id != self.ledger_id ||
               &self.entries.get(i - 1).unwrap().advanced_hash()[..] != &le.history_hash[..] ||
               le.count != i as u32 {
                if le.count != i as u32 {
                    println!("check_ledger: count mismatch, should be {}, found {}",
                             i,
                             le.count);
                } else if le.ledger_id != self.ledger_id {
                    println!("check_ledger: ID mismatch");
                } else if &self.entries.get(i - 1).unwrap().advanced_hash()[..] != &le.history_hash[..] {
                    println!("check_ledger: hash mismatch, advanced hash from entry {} is \
                              different",
                             &self.entries.get(i - 1).unwrap().count);
                    println!("check_ledger: actual hash: {}",
                             fmt_hex(&self.entries.get(i - 1).unwrap().advanced_hash()[..]));
                    println!("check_ledger: advanced hash: {}",
                             fmt_hex(&le.history_hash[..]));
                }
                return false;
            }
            if le.operation == EntryType::Add {
                if trusted_devices.contains_key(&le.issuer_publickey) &&
                   le.verify_issuer_signature() &&
                   le.verify_subject_signature() &&
                   !trusted_devices.contains_key(&le.subject_publickey) {
                    trusted_devices.insert(le.subject_publickey.clone(), le.clone());
                } else {
                    println!("check_ledger: Entry of type 'Add' error");
                    if !trusted_devices.contains_key(&le.issuer_publickey) {
                        println!("check_ledger: Issuer not trusted");
                    }
                    if !le.verify_issuer_signature() {
                        println!("check_ledger: Issuer signature is wrong");
                    }
                    if !le.verify_subject_signature() {
                        println!("check_ledger: Subject signature is wrong");
                    }
                    if trusted_devices.contains_key(&le.subject_publickey) {
                        println!("check_ledger: Subject is already trusted");
                    }
                    return false;
                }
            } else if le.operation == EntryType::Remove {
                if trusted_devices.contains_key(&le.issuer_publickey) &&
                   le.verify_issuer_signature() &&
                   trusted_devices.contains_key(&le.subject_publickey) {
                    trusted_devices.remove(&le.subject_publickey);
                } else {
                    println!("check_ledger: Entry of type 'Remove' error");
                    return false;
                }
            }
        }
        println!("check_ledger: Found {} valid entries",
                 trusted_devices.len());
        for (pk, l) in &trusted_devices {
            println!("check_ledger: Subject PublicKey: {}, Issuer PublicKey {}, count {}",
                     fmt_hex(&pk[..]),
                     fmt_hex(&l.issuer_publickey[..]),
                     l.count);
        }
        self.trusted_devices = trusted_devices;
        true
    }
    pub fn get_trusted_devices(&self) -> HashMap<PublicKey, LedgerEntry> {
        self.trusted_devices.clone()
    }
    pub fn is_device_trusted(&self, device: &PublicKey) -> bool {
        self.trusted_devices.contains_key(device)
    }
    pub fn get_ledger_version(&self) -> u32 {
        self.version
    }
    pub fn get_ledger_id(&self) -> u32 {
        self.ledger_id
    }
    pub fn get_ledger_hash(&self) -> Digest {
        self.hash
    }
    pub fn get_parent(&self, le: &LedgerEntry) -> Option<&LedgerEntry> {
        let start = le.count as usize;
        let key = &le.issuer_publickey;
        if start == 0 {
            return None;
        }
        for i in 0..start + 1 {
            let l = &self.entries[start - i];
            if &l.subject_publickey[..] == &key[..] && l.operation == EntryType::Add {
                return Some(l);
            }
        }
        None
    }
    pub fn get_entry(&self, index: usize) -> &LedgerEntry {
        &self.entries[index]
    }
    pub fn get_permanent_hash(&self) -> Digest {
        self.entries[0].complete_hash()
    }
}

pub struct ShortLedger {
    version: u32,
    ledger_id: u32,
    hash: Digest,
    entry: LedgerEntry,
    trusted_devices: HashMap<PublicKey, LedgerEntry>,
}

impl ShortLedger {
    pub fn new() {}
    pub fn test_entry(&self, le: &LedgerEntry) -> bool {
        if self.trusted_devices.len() >= MAX_DEVICES || self.version >= u32::max_value() ||
           le.format_version != FORMAT_VERSION || le.ledger_id != self.ledger_id ||
           &self.entry.advanced_hash()[..] == &le.history_hash[..] ||
           le.count != (self.version + 1) {
            return false;
        }
        if le.operation == EntryType::Add {
            return self.trusted_devices.contains_key(&le.issuer_publickey) &&
                   le.verify_issuer_signature() &&
                   le.verify_subject_signature() &&
                   !self.trusted_devices.contains_key(&le.subject_publickey);
        } else if le.operation == EntryType::Remove {
            return self.trusted_devices.contains_key(&le.issuer_publickey) &&
                   le.verify_issuer_signature() &&
                   self.trusted_devices.contains_key(&le.subject_publickey);
        }
        false
    }
    pub fn get_entry(&self) -> LedgerEntry {
        self.entry.clone()
    }
    pub fn add_entry(&mut self, le: LedgerEntry) -> bool {
        if self.test_entry(&le) {
            self.entry = le.clone();
            if le.operation == EntryType::Add {
                self.trusted_devices.insert(le.subject_publickey.clone(), le.clone());
            } else if le.operation == EntryType::Remove {
                self.trusted_devices.remove(&le.subject_publickey);
            }
            self.hash = self.entry.advanced_hash();
            return true;
        }
        false
    }
    pub fn get_trusted(&self) -> HashMap<PublicKey, LedgerEntry> {
        self.trusted_devices.clone()
    }
    pub fn is_device_trusted(&self, device: &PublicKey) -> bool {
        if self.trusted_devices.contains_key(device) {
            return true;
        }
        false
    }
    pub fn get_ledger_version(&self) -> u32 {
        self.version
    }
    pub fn get_ledger_id(&self) -> u32 {
        self.ledger_id
    }
    pub fn get_ledger_hash(&self) -> Digest {
        self.hash
    }
}
