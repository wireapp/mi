use cbor::{DecodeError, DecodeResult};
use cbor_utils::{
    ensure_array_length, run_decoder_full, run_encoder, MIDecodeError,
};
use entries::{DeviceInfo, JournalEntry};
use operation::Operation;
use sodiumoxide::crypto::hash::sha256::{hash, Digest};
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey};
use std::collections::HashMap;
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
        devices: Vec<(u32, PublicKey)>,
    ) -> Result<FullJournal, ValidatorError> {
        let initial_operation = Operation::JournalInit { devices };
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
        FullJournal::new_from_entry(entry)
    }

    pub fn new_from_entry(
        entry: JournalEntry,
    ) -> Result<FullJournal, ValidatorError> {
        Validator::validate_first_entry(&entry)?;
        let mut new_journal: FullJournal = FullJournal {
            journal_id: entry.journal_id,
            entries: Vec::new(),
            trusted_devices: HashMap::new(),
            hash: hash(&[]),
        };

        new_journal.unchecked_add_entry(entry);
        Ok(new_journal)
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
        Validator::validate_unsigned_subject_entry(&self, &entry)?;
        Ok(entry)
    }

    /// Check if given entry can be added to the journal.
    pub fn can_add_entry(
        &self,
        entry: &JournalEntry,
    ) -> Result<(), ValidatorError> {
        Validator::validate_entry(&self, entry)
    }

    /// Add an entry to the journal without validating it.
    fn unchecked_add_entry(&mut self, entry: JournalEntry) {
        self.entries.push(entry.clone());
        self.hash = entry.hash();
        match entry.operation.clone() {
            Operation::JournalInit { devices } => {
                for (capabilities, subject) in devices.iter() {
                    self.trusted_devices.insert(
                        *subject,
                        DeviceInfo {
                            key: *subject,
                            capabilities: *capabilities,
                            entry: entry.clone(),
                        },
                    );
                }
            }
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
            Operation::DeviceSelfReplace { added_subject, .. } => {
                let current_device =
                    self.get_trusted_device(&entry.issuer).unwrap().clone();
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
    }

    pub fn add_entry(
        &mut self,
        entry: JournalEntry,
    ) -> Result<(), ValidatorError> {
        self.can_add_entry(&entry)?;
        self.unchecked_add_entry(entry);
        Ok(())
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

            let mut journal = match FullJournal::new_from_entry(first_entry)
            {
                Ok(j) => j,
                Err(err) => return Err(DecodeError::Other(From::from(err))),
            };

            if num > 1 {
                for _ in 1..num {
                    let e = JournalEntry::decode(&mut d)?;
                    if let Err(e) = journal.add_entry(e) {
                        return Err(DecodeError::Other(From::from(e)));
                    };
                }
            }
            Ok(journal)
        })
    }

    /// Verify all invariants of the entire journal.
    pub fn check_journal(&mut self) -> Result<(), ValidatorError> {
        Validator::validate_journal(&self)
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

    /// Find the entry that added the signer of the given entry to the
    /// journal.
    pub fn get_parent(
        &self,
        entry: &JournalEntry,
    ) -> Option<&JournalEntry> {
        let start = entry.index as usize;
        if start == 0 {
            return None;
        }
        for i in 0..start + 1 {
            let l = &self.entries[start - i];
            match l.operation.clone() {
                Operation::JournalInit { devices } => {
                    for (_, subject) in devices.iter() {
                        if *subject == entry.issuer {
                            return Some(l);
                        }
                    }
                }
                Operation::DeviceAdd { subject, .. } => {
                    if subject == entry.issuer {
                        return Some(l);
                    }
                }
                Operation::DeviceRemove { .. } => {}
                Operation::DeviceReplace { added_subject, .. } => {
                    if added_subject == entry.issuer {
                        return Some(l);
                    }
                }
                Operation::DeviceSelfReplace { added_subject, .. } => {
                    if added_subject == entry.issuer {
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
