use cbor::{DecodeError, DecodeResult};
use cbor_utils::{
    ensure_array_length, run_decoder_full, run_encoder, MIDecodeError,
};
use entries::{DeviceInfo, DeviceType, JournalEntry};
use operation::Operation;
use sodiumoxide::crypto::hash::sha256::{hash, Digest};
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey};
use std::collections::HashMap;
use std::error::Error;
use utils::{fmt_hex, EMPTYSIGNATURE};
use uuid::{ParseError, Uuid};
use validator::{Validator, ValidatorError};

pub const FORMAT_JOURNAL_VERSION: u32 = 0;
pub const MAX_DEVICES: usize = 8;

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
pub struct UserID(pub u32);

impl From<u32> for UserID {
    fn from(n: u32) -> UserID {
        UserID(n)
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub struct JournalID(pub Uuid);

impl JournalID {
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
    pub fn from_bytes(b: &[u8]) -> Result<JournalID, ParseError> {
        match Uuid::from_bytes(b) {
            Ok(u) => Ok(JournalID(u)),
            Err(e) => Err(e),
        }
    }
}

impl From<Uuid> for JournalID {
    fn from(n: Uuid) -> JournalID {
        JournalID(n)
    }
}

#[derive(PartialEq, Clone)]
pub struct FullJournal {
    journal_id: JournalID,
    hash: Digest,
    entries: Vec<JournalEntry>,
    trusted_devices: HashMap<PublicKey, DeviceInfo>,
}

impl FullJournal {
    pub fn new(
        _journal_id: JournalID,
        issuer_pk: &PublicKey,
        issuer_sk: &SecretKey,
    ) -> Option<FullJournal> {
        let initial_operation = Operation::DeviceAdd {
            subject: *issuer_pk,
            subject_signature: EMPTYSIGNATURE,
            capabilities: DeviceType::PermanentDevice as u32,
        };
        let mut entry = JournalEntry::new(
            _journal_id,
            hash(&[]),
            0,
            initial_operation,
            *issuer_pk,
        );
        let signature = entry.sign(issuer_sk);
        entry.signature = signature;
        entry.operation.set_subject_signature(signature);
        let mut entries: Vec<JournalEntry> = Vec::new();
        entries.push(entry.clone());
        let mut _trusted_devices: HashMap<PublicKey, DeviceInfo> =
            HashMap::new();
        _trusted_devices.insert(
            *issuer_pk,
            DeviceInfo {
                key: *issuer_pk,
                capabilities: DeviceType::PermanentDevice as u32,
                entry: entry.clone(),
            },
        );
        Some(FullJournal {
            journal_id: _journal_id,
            entries,
            trusted_devices: _trusted_devices,
            hash: hash(&[]),
        })
    }

    /// Create and return a `JournalEntry` without adding it to the
    /// journal.
    pub fn create_entry(
        &self,
        operation: Operation,
        issuer_pk: &PublicKey,
        issuer_sk: &SecretKey,
    ) -> Result<JournalEntry, ValidatorError> {
        let last_entry = self.entries.last().unwrap();
        let mut entry = JournalEntry::new(
            self.journal_id,
            last_entry.hash(),
            last_entry.index + 1,
            operation,
            *issuer_pk,
        );
        entry.signature = entry.sign(issuer_sk);
        match Validator::validate_unsigned_subject_entry(&self, &entry) {
            Ok(()) => Ok(entry),
            Err(e) => Err(e),
        }
    }

    /// Check if given entry can be added to the journal.
    pub fn can_add_entry(
        &self,
        entry: &JournalEntry,
    ) -> Result<(), ValidatorError> {
        Validator::validate_entry(&self, entry)
    }

    pub fn add_entry(
        &mut self,
        entry: JournalEntry,
    ) -> Result<(), ValidatorError> {
        match self.can_add_entry(&entry) {
            Ok(()) => {
                self.entries.push(entry.clone());
                match entry.operation {
                    Operation::DeviceAdd {
                        subject,
                        capabilities,
                        ..
                    } => {
                        self.trusted_devices.insert(
                            subject,
                            DeviceInfo {
                                key: subject,
                                capabilities,
                                entry,
                            },
                        );
                    }
                    Operation::DeviceRemove { subject, .. } => {
                        self.trusted_devices.remove(&subject);
                    }
                    Operation::DeviceReplace {
                        removed_subject,
                        capabilities,
                        added_subject,
                        ..
                    } => {
                        self.trusted_devices.remove(&removed_subject);
                        self.trusted_devices.insert(
                            added_subject,
                            DeviceInfo {
                                key: added_subject,
                                capabilities,
                                entry,
                            },
                        );
                    }
                    Operation::DeviceSelfReplace {
                        added_subject, ..
                    } => {
                        let current_device = self
                            .get_trusted_device(&entry.issuer)
                            .unwrap()
                            .clone();
                        self.trusted_devices.remove(&entry.issuer);
                        self.trusted_devices.insert(
                            added_subject,
                            DeviceInfo {
                                key: added_subject,
                                capabilities: current_device.capabilities,
                                entry,
                            },
                        );
                    }
                };
                self.hash = self.entries.last().unwrap().hash();
                Ok(())
            }
            Err(e) => {
                drop(entry);
                Err(e)
            }
        }
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
        run_decoder_full(bytes, &|mut d| {
            ensure_array_length(d, "FullJournal", 2)?;
            let version = d.u32()?;
            if version > FORMAT_JOURNAL_VERSION {
                return Err(MIDecodeError::UnsupportedJournalVersion {
                    found_version: version,
                    max_supported_version: FORMAT_JOURNAL_VERSION,
                }.into());
            }
            let num = d.array()?;
            if num < 1 {
                return Err(MIDecodeError::EmptyJournal.into());
            }
            let first_entry = JournalEntry::decode(&mut d)?;
            let device_info =
                FullJournal::check_first_entry(&first_entry).unwrap();
            let mut trusted_devices = HashMap::new();
            trusted_devices.insert(first_entry.issuer, device_info);
            let mut journal = FullJournal {
                journal_id: first_entry.journal_id,
                entries: vec![first_entry.clone()],
                trusted_devices,
                hash: first_entry.hash(),
            };
            if num > 1 {
                for _ in 1..num {
                    let e = JournalEntry::decode(&mut d)?;
                    // TODO: either this should check for errors, or we
                    // shouldn't do any error checking in the decoder
                    // (including "empty journal" and "weird root entry")
                    if let Err(e) = journal.add_entry(e) {
                        let e1: Box<
                            Error + Send + Sync,
                        > = From::from(e);
                        return Err(DecodeError::Other(e1));
                    };
                }
            }
            Ok(journal)
        })
    }

    /// Check that the root entry of the journal is what we expect (a
    /// self-signed addition entry). In case it is, return `DeviceInfo`
    /// corresponding to the root device.
    fn check_first_entry(entry: &JournalEntry) -> Option<DeviceInfo> {
        Validator::validate_first_entry(entry)
    }

    /// Verify all invariants of the entire journal.
    pub fn check_journal(&mut self) -> bool {
        println!("check_journal: started");
        let mut trusted_devices: HashMap<PublicKey, DeviceInfo> =
            HashMap::new();
        if self.entries.is_empty() {
            return false;
        }
        let first_entry: &JournalEntry = self.entries.first().unwrap();
        match FullJournal::check_first_entry(first_entry) {
            None => return false,
            Some(device_info) => {
                trusted_devices.insert(first_entry.issuer, device_info);
                if self.entries.len() == 1 {
                    self.trusted_devices = trusted_devices;
                    return true;
                }
            }
        }
        println!("check_journal: Found {} entries", self.entries.len());
        for i in 1..(self.entries.len()) {
            let le = &self.entries[i];
            if le.journal_id != self.journal_id
                || self.entries[i - 1].hash()[..] != le.history_hash[..]
                || le.index != i as u32
            {
                if le.index != i as u32 {
                    println!("check_journal: count mismatch, should be {}, found {}",
                             i,
                             le.index);
                } else if le.journal_id != self.journal_id {
                    println!("check_journal: ID mismatch");
                } else if self.entries[i - 1].hash()[..]
                    != le.history_hash[..]
                {
                    println!("check_journal: hash mismatch, advanced hash from entry {} is \
                              different",
                             &self.entries[i - 1].index);
                    println!(
                        "check_journal: actual hash: {}",
                        fmt_hex(&self.entries[i - 1].hash()[..])
                    );
                    println!(
                        "check_journal: advanced hash: {}",
                        fmt_hex(&le.history_hash[..])
                    );
                }
                return false;
            }

            // TODO: this check probably duplicates code from FullJournal::can_add_entry.  deduplicate!
            let op_add_device = |&subject,
                                 &subject_signature,
                                 &capabilities,
                                 t_d: &mut HashMap<
                PublicKey,
                DeviceInfo,
            >| {
                if t_d.contains_key(&le.issuer)
                    && !t_d.contains_key(&subject)
                    && t_d[&le.issuer].capability_can_add()
                    && le.verify_signature(&le.issuer, &le.signature)
                    && le.verify_signature(&subject, &subject_signature)
                {
                    t_d.insert(
                        subject,
                        DeviceInfo {
                            key: subject,
                            capabilities,
                            entry: le.clone(),
                        },
                    );
                    true
                } else {
                    println!("check_journal (index {}): Entry of type 'Add' error", i);
                    println!("Number of trusted devices: {}", t_d.len());
                    if !t_d.contains_key(&le.issuer) {
                        println!("check_journal: Issuer not trusted");
                    }
                    if !le.verify_signature(&le.issuer, &le.signature) {
                        println!(
                            "check_journal: Issuer signature is wrong"
                        );
                    }
                    if !le.verify_signature(&subject, &subject_signature) {
                        println!(
                            "check_journal: Subject signature is wrong"
                        );
                    }
                    if t_d.contains_key(&subject) {
                        println!(
                            "check_journal: Subject is already trusted"
                        );
                    }
                    false
                }
            };

            let op_remove_device = |&subject,
                                    trusted_devices: &mut HashMap<
                PublicKey,
                DeviceInfo,
            >| {
                if trusted_devices.contains_key(&le.issuer)
                    && trusted_devices.contains_key(&subject)
                    && trusted_devices[&le.issuer].capability_can_remove()
                    && !trusted_devices[&subject]
                        .capability_cannot_be_removed()
                    && le.verify_signature(&le.issuer, &le.signature)
                {
                    trusted_devices.remove(&subject);
                    true
                } else {
                    println!("check_journal: Entry of type 'Remove' error");
                    false
                }
            };

            let op_self_update_device = |&subject,
                                         &subject_signature,
                                         &capabilities,
                                         trusted_devices: &mut HashMap<
                PublicKey,
                DeviceInfo,
            >| {
                if trusted_devices.contains_key(&le.issuer)
                    && !trusted_devices.contains_key(&subject)
                    && le.verify_signature(&le.issuer, &le.signature)
                    && le.verify_signature(&subject, &subject_signature)
                {
                    trusted_devices.insert(
                        subject,
                        DeviceInfo {
                            key: subject,
                            capabilities,
                            entry: le.clone(),
                        },
                    );
                    trusted_devices.remove(&le.issuer);
                    true
                } else {
                    println!("check_journal: Entry of type 'Add' error");
                    if !trusted_devices.contains_key(&le.issuer) {
                        println!("check_journal: Issuer not trusted");
                    }
                    if !le.verify_signature(&le.issuer, &le.signature) {
                        println!(
                            "check_journal: Issuer signature is wrong"
                        );
                    }
                    if !le.verify_signature(&subject, &subject_signature) {
                        println!(
                            "check_journal: Subject signature is wrong"
                        );
                    }
                    if trusted_devices.contains_key(&subject) {
                        println!(
                            "check_journal: Subject is already trusted"
                        );
                    }
                    false
                }
            };

            println!(
                "Current number of trusted devices: {}",
                trusted_devices.len()
            );
            match le.operation {
                Operation::DeviceAdd {
                    subject,
                    subject_signature,
                    capabilities,
                    ..
                } => if !op_add_device(
                    &subject,
                    &subject_signature,
                    &capabilities,
                    &mut trusted_devices,
                ) {
                    return false;
                },
                Operation::DeviceRemove { subject, .. } => {
                    if !op_remove_device(&subject, &mut trusted_devices) {
                        return false;
                    }
                }

                Operation::DeviceReplace {
                    removed_subject,
                    capabilities,
                    added_subject,
                    added_subject_signature,
                    ..
                } => {
                    if !op_remove_device(
                        &removed_subject,
                        &mut trusted_devices,
                    ) {
                        return false;
                    };
                    if !op_add_device(
                        &added_subject,
                        &added_subject_signature,
                        &capabilities,
                        &mut trusted_devices,
                    ) {
                        return false;
                    };
                }
                Operation::DeviceSelfReplace {
                    added_subject,
                    added_subject_signature,
                    ..
                } => {
                    let capabilities = self
                        .get_trusted_device(&le.issuer)
                        .unwrap()
                        .capabilities;
                    if !op_self_update_device(
                        &added_subject,
                        &added_subject_signature,
                        &capabilities,
                        &mut trusted_devices,
                    ) {
                        return false;
                    };
                }
            }
        }
        println!(
            "check_journal: Found {} trusted devices:",
            trusted_devices.len()
        );
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
    /// device is still in the set of trusted devices).
    pub fn get_trusted_device(
        &self,
        device: &PublicKey,
    ) -> Option<&DeviceInfo> {
        self.trusted_devices.get(device)
    }

    /// Get all trusted devices.
    pub fn get_trusted_devices(&self) -> HashMap<PublicKey, DeviceInfo> {
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
        self.journal_id
    }

    pub fn get_journal_hash(&self) -> Digest {
        self.hash
    }

    /// Find the entry that added the signer of a given entry to the journal.
    pub fn get_parent(&self, le: &JournalEntry) -> Option<&JournalEntry> {
        let start = le.index as usize;
        if start == 0 {
            return None;
        }
        for i in 0..start + 1 {
            let l = &self.entries[start - i];
            match l.operation {
                Operation::DeviceAdd { subject, .. } => {
                    if subject == le.issuer {
                        return Some(l);
                    }
                }
                Operation::DeviceRemove { .. } => {}
                Operation::DeviceReplace { added_subject, .. } => {
                    if added_subject == le.issuer {
                        return Some(l);
                    }
                }
                Operation::DeviceSelfReplace { added_subject, .. } => {
                    if added_subject == le.issuer {
                        return Some(l);
                    }
                }
            };
        }
        None
    }

    pub fn get_entry(&self, index: usize) -> &JournalEntry {
        &self.entries[index]
    }

    pub fn get_entries(&self) -> &Vec<JournalEntry> {
        &self.entries
    }

    pub fn get_permanent_hash(&self) -> Digest {
        self.entries[0].hash()
    }
}
