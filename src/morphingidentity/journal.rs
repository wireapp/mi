use entries::{DeviceType, Operation, JournalEntry, ClientInfo};
use utils::{fmt_hex, EMPTYSIGNATURE};
use cbor_utils::{run_decoder, run_encoder, MIDecodeError};
use sodiumoxide::crypto::hash::sha256::{hash, Digest};
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey};
use std::collections::HashMap;
use cbor::DecodeResult;
use uuid::Uuid;

const FORMAT_JOURNAL_VERSION: u32 = 0;
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
    journal_id: Uuid,
    hash: Digest,
    entries: Vec<JournalEntry>,
    trusted_devices: HashMap<PublicKey, ClientInfo>,
}

impl FullJournal {
    pub fn new(_journal_id: Uuid,
               issuer_pk: &PublicKey,
               issuer_sk: &SecretKey)
               -> Option<FullJournal> {
        let operation = Operation::ClientAdd {
                subject: *issuer_pk,
                subject_signature: EMPTYSIGNATURE,
                capabilities: DeviceType::PermanentDevice as u32,
            };
        let mut entry = JournalEntry::new(_journal_id,
                                          hash(&[]),
                                          0,
                                          operation,
                                          *issuer_pk);
        let signature = entry.sign(issuer_sk);
        entry.signature = signature;
        entry.operation.set_subject_signature(signature);
        let mut entries: Vec<JournalEntry> = Vec::new();
        entries.push(entry.clone());
        let mut _trusted_devices: HashMap<PublicKey, ClientInfo> = HashMap::new();
        _trusted_devices.insert(*issuer_pk, ClientInfo {
            key: *issuer_pk,
            capabilities: DeviceType::PermanentDevice as u32,
            entry: entry.clone()
        });
        Some(FullJournal {
            journal_id: _journal_id,
            entries: entries,
            trusted_devices: _trusted_devices,
            hash: hash(&[]),
        })
    }
    pub fn create_entry(&self,
                        operation: Operation,
                        issuer_pk: &PublicKey,
                        issuer_sk: &SecretKey)
                        -> Option<JournalEntry> {
        // TODO: separate out this check because it's used in more than one
        // place, I think
        let devices = self.trusted_devices.len();
        match operation {
            Operation::ClientAdd { subject, .. } => {
                if devices >= MAX_DEVICES { return None };
                if self.trusted_devices.contains_key(&subject) { return None };
            },
            Operation::ClientRemove { subject, .. } => {
                if devices < 2 { return None };
                if !self.trusted_devices.contains_key(&subject) { return None };
            },
        }
        if self.entries.len() >= u32::max_value() as usize || self.entries.is_empty() ||
           !self.trusted_devices.contains_key(issuer_pk) {
            return None;
        }
        let last_entry = self.entries.last().unwrap();
        let mut entry = JournalEntry::new(self.journal_id,
                                          last_entry.hash(),
                                          last_entry.index + 1,
                                          operation,
                                          *issuer_pk);
        entry.signature = entry.sign(issuer_sk);
        Some(entry)
    }
    // pub fn create_add_permanent_device() {}
    // pub fn create_add_temporary_device() {}
    // pub fn create_remove_device() {}

    /// Check if given entry can be added to the journal.
    pub fn can_add_entry(&self, entry: &JournalEntry) -> bool {
        let last_entry = self.entries.last().unwrap();
        if last_entry.index == u32::max_value() ||
           entry.journal_id != self.journal_id ||
           last_entry.hash()[..] != entry.history_hash[..] ||
           entry.index != (last_entry.index + 1) {
               return false;
        }
        let devices = self.trusted_devices.len();
        match entry.operation {
            Operation::ClientAdd { .. } if devices >= MAX_DEVICES => false,
            Operation::ClientRemove { .. } if devices < 2 => false,
            Operation::ClientAdd { subject, subject_signature, .. } => {
                let issuer_can_add = match self.get_trusted_device(&entry.issuer) {
                    Some(client) => client.capability_can_add(),
                    None         => false,
                };
                issuer_can_add &&
                  !self.trusted_devices.contains_key(&subject) &&
                  entry.verify_signature(&entry.issuer, &entry.signature) &&
                  entry.verify_signature(&subject, &subject_signature)
            },
            Operation::ClientRemove { subject, .. } => {
                let issuer_can_remove = match self.get_trusted_device(&entry.issuer) {
                    Some(client) => client.capability_can_remove(),
                    None         => false,
                };
                let subject_is_removable = match self.get_trusted_device(&subject) {
                    Some(client) => !client.capability_cannot_be_removed(),
                    None         => false,
                };
                issuer_can_remove && subject_is_removable && 
                  entry.verify_signature(&entry.issuer, &entry.signature)
            },
        }
    }
    pub fn add_entry(&mut self, entry: JournalEntry) -> bool {
        if self.can_add_entry(&entry) {
            self.entries.push(entry.clone());
            match entry.operation {
                Operation::ClientAdd { subject, capabilities, .. } =>
                    self.trusted_devices.insert(subject, ClientInfo {
                        key: subject,
                        capabilities: capabilities,
                        entry: entry,
                    }),
                Operation::ClientRemove { subject, .. } =>
                    self.trusted_devices.remove(&subject),
            };
            self.hash = self.entries.last().unwrap().hash();
            return true;
        }
        drop(entry);
        false
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        run_encoder(&|mut e| {
            let num = self.entries.len();
            println!("Number of entries: {}", num);
            e.array(2)?;
            e.u32(FORMAT_JOURNAL_VERSION)?;
            e.array(num)?;
            for i in 0..num {
                self.entries[i].encode(&mut e)?;
            }
            Ok(())
        }).unwrap()
    }
    pub fn from_bytes(bytes: Vec<u8>) -> DecodeResult<FullJournal> {
        run_decoder(bytes, &|mut d| {
            match d.array()? {
                2 => { },
                n => return Err(MIDecodeError::InvalidArrayLength {
                    type_name: "FullJournal",
                    expected_length: 2,
                    actual_length: n,
                }.into()),
            }
            let version = d.u32()?;
            if version > FORMAT_JOURNAL_VERSION {
                return Err(MIDecodeError::UnsupportedJournalVersion {
                    found_version: version,
                    max_supported_version: FORMAT_JOURNAL_VERSION,
                }.into());
            }
            let num = d.array()?;
            if num < 1 {
                return Err(MIDecodeError::EmptyJournal.into())
            }
            let first_entry = JournalEntry::decode(&mut d)?;
            let client_info = FullJournal::check_first_entry(&first_entry).unwrap();
            let mut trusted_devices = HashMap::new();
            trusted_devices.insert(first_entry.issuer, client_info);
            let mut journal = FullJournal {
                journal_id: first_entry.journal_id,
                entries: vec![first_entry.clone()],
                trusted_devices: trusted_devices,
                hash: first_entry.hash(),
            };
            if num > 1 {
                for _ in 1..num {
                    let e = JournalEntry::decode(&mut d)?;
                    // TODO: either this should check for errors, or we
                    // shouldn't do any error checking in the decoder
                    // (including "empty journal" and "weird root entry")
                    journal.add_entry(e);
                }
            }

            Ok(journal)
        })
    }
    /// Check that the root entry of the journal is what we expect (a
    /// self-signed addition entry). In case it is, return `ClientInfo`
    /// corresponding to the root device.
    fn check_first_entry(entry: &JournalEntry) -> Option<ClientInfo> {
        match entry.operation {
            Operation::ClientAdd { subject, capabilities, .. }
                if subject == entry.issuer &&
                   entry.verify_signature(&entry.issuer, &entry.signature) =>
                       Some(ClientInfo {
                           key: subject,
                           capabilities: capabilities,
                           entry: entry.clone(),
                       }),
            _ => None,
        }
    }
    pub fn check_journal(&mut self) -> bool {
        println!("check_journal: started");
        let mut trusted_devices: HashMap<PublicKey, ClientInfo> = HashMap::new();
        if self.entries.is_empty() {
            return false;
        }
        let first_entry: &JournalEntry = self.entries.first().unwrap();
        match FullJournal::check_first_entry(first_entry) {
            None => return false,
            Some(client_info) => {
                trusted_devices.insert(first_entry.issuer, client_info);
                if self.entries.len() == 1 {
                    self.trusted_devices = trusted_devices;
                    return true;
                }
            }
        }
        println!("check_journal: Found {} entries", self.entries.len());
        for i in 1..(self.entries.len()) {
            let le = &self.entries[i];
            if le.journal_id != self.journal_id ||
               self.entries[i - 1].hash()[..] != le.history_hash[..] ||
               le.index != i as u32 {
                if le.index != i as u32 {
                    println!("check_journal: count mismatch, should be {}, found {}",
                             i,
                             le.index);
                } else if le.journal_id != self.journal_id {
                    println!("check_journal: ID mismatch");
                } else if self.entries[i - 1].hash()[..] != le.history_hash[..] {
                    println!("check_journal: hash mismatch, advanced hash from entry {} is \
                              different",
                             &self.entries[i - 1].index);
                    println!("check_journal: actual hash: {}",
                             fmt_hex(&self.entries[i - 1].hash()[..]));
                    println!("check_journal: advanced hash: {}",
                             fmt_hex(&le.history_hash[..]));
                }
                return false;
            }
            match le.operation {
                Operation::ClientAdd { subject, subject_signature, capabilities, .. } =>
                if trusted_devices.contains_key(&le.issuer) &&
                   !trusted_devices.contains_key(&subject) &&
                   trusted_devices[&le.issuer].capability_can_add() &&
                   le.verify_signature(&le.issuer, &le.signature) &&
                   le.verify_signature(&subject, &subject_signature) {
                       trusted_devices.insert(subject, ClientInfo {
                           key: subject,
                           capabilities: capabilities,
                           entry: le.clone()
                       });
                } else {
                    println!("check_journal: Entry of type 'Add' error");
                    if !trusted_devices.contains_key(&le.issuer) {
                        println!("check_journal: Issuer not trusted");
                    }
                    if !le.verify_signature(&le.issuer, &le.signature) {
                        println!("check_journal: Issuer signature is wrong");
                    }
                    if !le.verify_signature(&subject, &subject_signature) {
                        println!("check_journal: Subject signature is wrong");
                    }
                    if trusted_devices.contains_key(&subject) {
                        println!("check_journal: Subject is already trusted");
                    }
                    return false;
                },
                Operation::ClientRemove { subject, .. } =>
                if trusted_devices.contains_key(&le.issuer) &&
                   trusted_devices.contains_key(&subject) &&
                   trusted_devices[&le.issuer].capability_can_remove() &&
                   !trusted_devices[&subject].capability_cannot_be_removed() &&
                   le.verify_signature(&le.issuer, &le.signature) {
                    trusted_devices.remove(&subject);
                } else {
                    println!("check_journal: Entry of type 'Remove' error");
                    return false;
                },
            }
        }
        println!("check_journal: Found {} trusted devices:",
                 trusted_devices.len());
        for (pk, l) in &trusted_devices {
            println!("check_journal: Subject PublicKey: {}, Issuer PublicKey {}, count {}",
                     fmt_hex(&pk[..]),
                     fmt_hex(&l.entry.issuer[..]),
                     l.entry.index);
        }
        self.trusted_devices = trusted_devices;
        true
    }
    /// Get journal entry corresponding to the addition of a device (if the
    /// device is still in the set of trusted clients).
    pub fn get_trusted_device(&self, device: &PublicKey) -> Option<&ClientInfo> {
        self.trusted_devices.get(device)
    }
    /// Get all trusted clients.
    pub fn get_trusted_devices(&self) -> HashMap<PublicKey, ClientInfo> {
        self.trusted_devices.clone()
    }
    pub fn is_device_trusted(&self, device: &PublicKey) -> bool {
        self.trusted_devices.contains_key(device)
    }
    /// Get journal version (i.e. index of the latest entry, assuming that
    /// the journal is not empty).
    pub fn get_journal_version(&self) -> u32 {
        self.entries.len() as u32 - 1
    }
    pub fn get_journal_id(&self) -> JournalID {
        JournalID(self.journal_id)
    }
    pub fn get_journal_hash(&self) -> Digest {
        self.hash
    }
    pub fn get_parent(&self, le: &JournalEntry) -> Option<&JournalEntry> {
        let start = le.index as usize;
        if start == 0 {
            return None;
        }
        for i in 0..start + 1 {
            let l = &self.entries[start - i];
            match l.operation {
                Operation::ClientAdd { subject, .. } =>
                    if subject == le.issuer { return Some(l) },
                Operation::ClientRemove { .. } =>
                    {},
            };
        }
        None
    }
    pub fn get_entry(&self, index: usize) -> &JournalEntry {
        &self.entries[index]
    }
    pub fn get_permanent_hash(&self) -> Digest {
        self.entries[0].hash()
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
           le.journal_id != self.journal_id ||
           self.entry.hash()[..] == le.history_hash[..] ||
           le.index != (self.version + 1) {
            return false;
        }
        match le.operation {
            Operation::ClientAdd { subject, subject_signature, .. } =>
                self.trusted_devices.contains_key(&le.issuer) &&
                !self.trusted_devices.contains_key(&subject) &&
                le.verify_signature(&le.issuer, &le.signature) &&
                le.verify_signature(&subject, &subject_signature),
            Operation::ClientRemove { subject, .. } =>
                self.trusted_devices.contains_key(&le.issuer) &&
                self.trusted_devices.contains_key(&subject) &&
                le.verify_signature(&le.issuer, &le.signature),
        }
    }
    pub fn get_entry(&self) -> JournalEntry {
        self.entry.clone()
    }
    pub fn add_entry(&mut self, le: JournalEntry) -> bool {
        if self.test_entry(&le) {
            self.entry = le.clone();
            match le.operation {
                Operation::ClientAdd { subject, .. } =>
                    self.trusted_devices.insert(subject, le),
                Operation::ClientRemove { subject, .. } =>
                    self.trusted_devices.remove(&subject),
            };
            self.hash = self.entry.hash();
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
