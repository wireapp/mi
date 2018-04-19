use entries::{DeviceType, EntryType, JournalEntry};
use utils::{fmt_hex, run_decoder, unsafe_run_encoder};
use sodiumoxide::crypto::hash::sha256::{hash, Digest};
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey};
use std::collections::HashMap;
use cbor::{DecodeError, DecodeResult};
use uuid::Uuid;

const FORMAT_ENTRY_VERSION: u32 = 1;
const FORMAT_JOURNAL_VERSION: u32 = 1;
const MAX_DEVICES: usize = 8;

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
pub struct UserID(pub u32);

impl From<u32> for UserID {
    fn from(n: u32) -> UserID {
        UserID(n)
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
pub struct JournalID(pub Uuid);

impl From<Uuid> for JournalID {
    fn from(n: Uuid) -> JournalID {
        JournalID(n)
    }
}

#[derive(PartialEq, Clone)]
pub struct FullJournal {
    version: u32,
    journal_id: Uuid,
    hash: Digest,
    entries: Vec<JournalEntry>,
    trusted_devices: HashMap<PublicKey, JournalEntry>,
}

impl FullJournal {
    pub fn new(_journal_id: Uuid,
               issuer_publickey: &PublicKey,
               issuer_sk: &SecretKey)
               -> Option<FullJournal> {
        let mut le: JournalEntry = JournalEntry::new(FORMAT_ENTRY_VERSION,
                                                     _journal_id,
                                                     hash(&[]),
                                                     0,
                                                     EntryType::Add,
                                                     DeviceType::PermanentDevice);
        le.set_identities(issuer_publickey, issuer_publickey);
        if !le.add_issuer_signature(issuer_sk) || !le.add_subject_signature(issuer_sk) {
            return None;
        }
        let mut entries: Vec<JournalEntry> = Vec::new();
        entries.push(le.clone());
        let mut _trusted_devices: HashMap<PublicKey, JournalEntry> = HashMap::new();
        _trusted_devices.insert(*issuer_publickey, le);
        Some(FullJournal {
            version: 0,
            journal_id: _journal_id,
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
                        -> Option<JournalEntry> {
        if (operation == EntryType::Add && self.trusted_devices.len() >= MAX_DEVICES) ||
           (operation == EntryType::Remove && self.trusted_devices.len() < 2) ||
           self.entries.len() >= u32::max_value() as usize || self.entries.is_empty() ||
           !self.trusted_devices.contains_key(issuer_publickey) ||
           (self.trusted_devices.contains_key(subject_publickey) && operation == EntryType::Add) ||
           (!self.trusted_devices.contains_key(subject_publickey) &&
            operation == EntryType::Remove) {
            return None;
        }
        let mut le: JournalEntry = JournalEntry::new(FORMAT_ENTRY_VERSION,
                                                     self.journal_id,
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
    // pub fn create_add_permanent_device() {}
    // pub fn create_add_temporary_device() {}
    // pub fn create_remove_device() {}
    pub fn sign_entry_as_subject(&self,
                                 le: &mut JournalEntry,
                                 subject_secretkey: &SecretKey)
                                 -> bool {
        le.add_subject_signature(subject_secretkey)
    }
    pub fn test_entry(&self, le: &JournalEntry) -> bool {
        if (le.operation == EntryType::Add && self.trusted_devices.len() >= MAX_DEVICES) ||
           (le.operation == EntryType::Remove && self.trusted_devices.len() < 2) ||
           self.version >= (u32::max_value() - 1) ||
           le.format_version != FORMAT_ENTRY_VERSION ||
           le.journal_id != self.journal_id ||
           self.entries.last().unwrap().advanced_hash()[..] != le.history_hash[..] ||
           le.count != (self.version + 1) {
            return false;
        }
        if le.operation == EntryType::Add {
            return self.trusted_devices.contains_key(&le.issuer_publickey) &&
                   le.verify_issuer_signature() &&
                   le.verify_subject_signature() &&
                   !self.trusted_devices.contains_key(&le.subject_publickey) &&
                   self.get_trusted_device(&le.issuer_publickey)
                .unwrap()
                .capability_can_add();
        } else if le.operation == EntryType::Remove {
            return self.trusted_devices.contains_key(&le.issuer_publickey) &&
                   le.verify_issuer_signature() &&
                   self.trusted_devices.contains_key(&le.subject_publickey) &&
                   self.get_trusted_device(&le.issuer_publickey)
                .unwrap()
                .capability_can_remove() &&
                   !self.get_trusted_device(&le.subject_publickey)
                .unwrap()
                .capability_cannot_be_removed();
        }
        false
    }
    pub fn add_entry(&mut self, le: JournalEntry) -> bool {
        if self.test_entry(&le) {
            self.entries.push(le.clone());
            if le.operation == EntryType::Add {
                self.trusted_devices.insert(le.subject_publickey, le);
            } else if le.operation == EntryType::Remove {
                self.trusted_devices.remove(&le.subject_publickey);
            }
            self.hash = self.entries.last().unwrap().advanced_hash();
            self.version += 1;
            return true;
        }
        drop(le);
        false
    }
    pub fn encode_as_cbor(&self) -> Vec<u8> {
        unsafe_run_encoder(&|mut e| {
            let num = self.entries.len();
            println!("Number of entries: {}", num);
            e.u32(FORMAT_JOURNAL_VERSION)?;
            e.u32(num as u32)?;
            for i in 0..num {
                self.entries[i].encode_signed_entry(&mut e)?;
            }
            Ok(())
        })
    }
    pub fn new_from_cbor(bytes: Vec<u8>) -> DecodeResult<FullJournal> {
        run_decoder(bytes, &|mut d| {
            if d.u32()? != FORMAT_JOURNAL_VERSION {
                return Err(DecodeError::UnexpectedBreak);
            }
            let num = d.u32()?;
            let mut journal: FullJournal = FullJournal {
                version: 0,
                journal_id: Uuid::nil(),
                entries: Vec::new(),
                trusted_devices: HashMap::new(),
                hash: hash(&[]),
            };

            if num >= 1 {
                let first_entry = JournalEntry::new_from_cbor(&mut d)?;
                if FullJournal::check_first_entry(&first_entry) {
                    let mut entries: Vec<JournalEntry> = Vec::new();
                    entries.push(first_entry.clone());
                    let mut trusted_devices: HashMap<PublicKey, JournalEntry> = HashMap::new();
                    trusted_devices.insert(first_entry.issuer_publickey, first_entry.clone());
                    journal = FullJournal {
                        version: 0,
                        journal_id: first_entry.journal_id,
                        entries: entries,
                        trusted_devices: trusted_devices,
                        hash: hash(&[]),
                    }
                }
            } else {
                return Err(DecodeError::UnexpectedBreak);
            }

            if num > 1 {
                for _ in 1..num {
                    let e = JournalEntry::new_from_cbor(&mut d)?;
                    journal.add_entry(e);
                }
            }

            Ok(journal)
        })
    }
    fn check_first_entry(entry: &JournalEntry) -> bool {
        if entry.operation != EntryType::Add {
            return false;
        }
        if entry.subject_publickey != entry.issuer_publickey {
            return false;
        }
        if !entry.verify_issuer_signature() {
            return false;
        }
        true
    }
    pub fn check_journal(&mut self) -> bool {
        println!("check_journal: started");
        let mut trusted_devices: HashMap<PublicKey, JournalEntry> = HashMap::new();
        if self.entries.is_empty() {
            return false;
        }
        let first_entry: &JournalEntry = self.entries.first().unwrap();
        if !FullJournal::check_first_entry(first_entry) {
            return false;
        }
        trusted_devices.insert(first_entry.issuer_publickey, first_entry.clone());
        if self.entries.len() == 1 {
            self.trusted_devices = trusted_devices;
            return true;
        }
        println!("check_journal: Found {} entries", self.entries.len());
        for i in 1..(self.entries.len()) {
            let le = &self.entries[i];
            if le.journal_id != self.journal_id ||
               self.entries[i - 1].advanced_hash()[..] != le.history_hash[..] ||
               le.count != i as u32 {
                if le.count != i as u32 {
                    println!("check_journal: count mismatch, should be {}, found {}",
                             i,
                             le.count);
                } else if le.journal_id != self.journal_id {
                    println!("check_journal: ID mismatch");
                } else if self.entries[i - 1].advanced_hash()[..] != le.history_hash[..] {
                    println!("check_journal: hash mismatch, advanced hash from entry {} is \
                              different",
                             &self.entries[i - 1].count);
                    println!("check_journal: actual hash: {}",
                             fmt_hex(&self.entries[i - 1].advanced_hash()[..]));
                    println!("check_journal: advanced hash: {}",
                             fmt_hex(&le.history_hash[..]));
                }
                return false;
            }
            if le.operation == EntryType::Add {
                if trusted_devices.contains_key(&le.issuer_publickey) &&
                   le.verify_issuer_signature() &&
                   le.verify_subject_signature() &&
                   !trusted_devices.contains_key(&le.subject_publickey) &&
                   trusted_devices[&le.issuer_publickey].capability_can_add() {
                    trusted_devices.insert(le.subject_publickey, le.clone());
                } else {
                    println!("check_journal: Entry of type 'Add' error");
                    if !trusted_devices.contains_key(&le.issuer_publickey) {
                        println!("check_journal: Issuer not trusted");
                    }
                    if !le.verify_issuer_signature() {
                        println!("check_journal: Issuer signature is wrong");
                    }
                    if !le.verify_subject_signature() {
                        println!("check_journal: Subject signature is wrong");
                    }
                    if trusted_devices.contains_key(&le.subject_publickey) {
                        println!("check_journal: Subject is already trusted");
                    }
                    return false;
                }
            } else if le.operation == EntryType::Remove {
                if trusted_devices.contains_key(&le.issuer_publickey) &&
                   le.verify_issuer_signature() &&
                   trusted_devices.contains_key(&le.subject_publickey) &&
                   trusted_devices[&le.issuer_publickey].capability_can_remove() &&
                   !trusted_devices[&le.subject_publickey].capability_cannot_be_removed() {
                    trusted_devices.remove(&le.subject_publickey);
                } else {
                    println!("check_journal: Entry of type 'Remove' error");
                    return false;
                }
            }
        }
        println!("check_journal: Found {} trusted devices:",
                 trusted_devices.len());
        for (pk, l) in &trusted_devices {
            println!("check_journal: Subject PublicKey: {}, Issuer PublicKey {}, count {}",
                     fmt_hex(&pk[..]),
                     fmt_hex(&l.issuer_publickey[..]),
                     l.count);
        }
        self.trusted_devices = trusted_devices;
        true
    }
    pub fn get_trusted_device(&self, device: &PublicKey) -> Option<&JournalEntry> {
        self.trusted_devices.get(device)
    }
    pub fn get_trusted_devices(&self) -> HashMap<PublicKey, JournalEntry> {
        self.trusted_devices.clone()
    }
    pub fn is_device_trusted(&self, device: &PublicKey) -> bool {
        self.trusted_devices.contains_key(device)
    }
    pub fn get_journal_version(&self) -> u32 {
        self.version
    }
    pub fn get_journal_id(&self) -> JournalID {
        JournalID(self.journal_id)
    }
    pub fn get_journal_hash(&self) -> Digest {
        self.hash
    }
    pub fn get_parent(&self, le: &JournalEntry) -> Option<&JournalEntry> {
        let start = le.count as usize;
        let key = &le.issuer_publickey;
        if start == 0 {
            return None;
        }
        for i in 0..start + 1 {
            let l = &self.entries[start - i];
            if l.subject_publickey[..] == key[..] && l.operation == EntryType::Add {
                return Some(l);
            }
        }
        None
    }
    pub fn get_entry(&self, index: usize) -> &JournalEntry {
        &self.entries[index]
    }
    pub fn get_permanent_hash(&self) -> Digest {
        self.entries[0].complete_hash()
    }
}

pub struct ShortJournal {
    version: u32,
    journal_id: Uuid,
    hash: Digest,
    entry: JournalEntry,
    trusted_devices: HashMap<PublicKey, JournalEntry>,
}

impl ShortJournal {
    pub fn new() {}
    pub fn test_entry(&self, le: &JournalEntry) -> bool {
        if self.trusted_devices.len() >= MAX_DEVICES || self.version >= (u32::max_value() - 1) ||
           le.format_version != FORMAT_ENTRY_VERSION ||
           le.journal_id != self.journal_id ||
           self.entry.advanced_hash()[..] == le.history_hash[..] ||
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
    pub fn get_entry(&self) -> JournalEntry {
        self.entry.clone()
    }
    pub fn add_entry(&mut self, le: JournalEntry) -> bool {
        if self.test_entry(&le) {
            self.entry = le.clone();
            if le.operation == EntryType::Add {
                self.trusted_devices.insert(le.subject_publickey, le);
            } else if le.operation == EntryType::Remove {
                self.trusted_devices.remove(&le.subject_publickey);
            }
            self.hash = self.entry.advanced_hash();
            return true;
        }
        drop(le);
        false
    }
    pub fn get_trusted(&self) -> HashMap<PublicKey, JournalEntry> {
        self.trusted_devices.clone()
    }
    pub fn is_device_trusted(&self, device: &PublicKey) -> bool {
        if self.trusted_devices.contains_key(device) {
            return true;
        }
        false
    }
    pub fn get_journal_version(&self) -> u32 {
        self.version
    }
    pub fn get_journal_id(&self) -> Uuid {
        self.journal_id
    }
    pub fn get_journal_hash(&self) -> Digest {
        self.hash
    }
}
