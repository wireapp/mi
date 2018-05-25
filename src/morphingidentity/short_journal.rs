use entries::{JournalEntry, Operation};
use journal::*;
use sodiumoxide::crypto::hash::sha256::Digest;
use sodiumoxide::crypto::sign::ed25519::PublicKey;
use std::collections::HashMap;
use uuid::Uuid;

pub struct ShortJournal {
    version: u32,
    journal_id: Uuid,
    hash: Digest,
    entry: JournalEntry,
    trusted_devices: HashMap<PublicKey, JournalEntry>,
}

/// TODO: Review the checks (and simplify by merging with other checks)
/// This is not production-ready.

impl ShortJournal {
    pub fn new() {}
    pub fn can_add_entry(&self, le: &JournalEntry) -> bool {
        if self.trusted_devices.len() >= MAX_DEVICES
            || self.version >= (u32::max_value() - 1)
            || le.journal_id != self.journal_id
            || self.entry.hash()[..] == le.history_hash[..]
            || le.index != (self.version + 1)
        {
            return false;
        }
        match le.operation {
            // TODO code duplication, see TODOs above.
            Operation::DeviceAdd {
                subject,
                subject_signature,
                ..
            } => {
                self.trusted_devices.contains_key(&le.issuer)
                    && !self.trusted_devices.contains_key(&subject)
                    && le.verify_signature(&le.issuer, &le.signature)
                    && le.verify_signature(&subject, &subject_signature)
            }
            Operation::DeviceRemove { subject, .. } => {
                self.trusted_devices.contains_key(&le.issuer)
                    && self.trusted_devices.contains_key(&subject)
                    && le.verify_signature(&le.issuer, &le.signature)
            }
            Operation::DeviceReplace {
                removed_subject,
                added_subject,
                added_subject_signature,
                ..
            } => {
                self.trusted_devices.contains_key(&removed_subject)
                    && self.trusted_devices.contains_key(&le.issuer)
                    && (!self.trusted_devices.contains_key(&added_subject)
                        || added_subject == removed_subject)
                    && le.verify_signature(&le.issuer, &le.signature)
                    && le.verify_signature(
                        &added_subject,
                        &added_subject_signature,
                    )
            }
            Operation::DeviceSelfReplace {
                added_subject,
                added_subject_signature,
                ..
            } => {
                self.trusted_devices.contains_key(&le.issuer)
                    && !self.trusted_devices.contains_key(&added_subject)
                    && le.verify_signature(&le.issuer, &le.signature)
                    && le.verify_signature(
                        &added_subject,
                        &added_subject_signature,
                    )
            }
        }
    }
    pub fn get_entry(&self) -> JournalEntry {
        self.entry.clone()
    }
    pub fn add_entry(&mut self, le: JournalEntry) -> bool {
        if self.can_add_entry(&le) {
            self.entry = le.clone();
            match le.operation {
                Operation::DeviceAdd { subject, .. } => {
                    self.trusted_devices.insert(subject, le);
                }
                Operation::DeviceRemove { subject, .. } => {
                    self.trusted_devices.remove(&subject);
                }
                Operation::DeviceReplace {
                    removed_subject,
                    added_subject,
                    ..
                } => {
                    self.trusted_devices.remove(&removed_subject);
                    self.trusted_devices.insert(added_subject, le);
                }
                Operation::DeviceSelfReplace { added_subject, .. } => {
                    self.trusted_devices.remove(&le.issuer);
                    self.trusted_devices.insert(added_subject, le);
                }
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
        self.trusted_devices.contains_key(device)
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
