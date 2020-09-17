use crate::capabilities::*;
use crate::entries::JournalEntry;
use crate::journal::*;
use crate::operation::Operation;
use crate::validator::{ValidateEntry, Validator};
use sodiumoxide::crypto::hash::sha256::Digest;
use sodiumoxide::crypto::sign::ed25519::PublicKey;
use std::collections::HashMap;

/// A short journal is what you arrive at when you process a journal. You
/// can validate an entry against a short journal, but you can't check that
/// a particular short journal belongs to the given user and hasn't been
/// tampered with.
pub struct ShortJournal {
    version: u32,
    /// Journal ID
    journal_id: JournalID,
    hash: Digest,
    /// The last entry in the journal
    entry: JournalEntry,
    /// The set of devices currently trusted by the journal, along with
    /// entries that were used to add those devices, and device capabilities
    trusted_devices: HashMap<PublicKey, (Capabilities, JournalEntry)>,
}

impl ValidateEntry for ShortJournal {
    fn journal_id(&self) -> JournalID {
        self.journal_id
    }
    fn is_empty(&self) -> bool {
        false
    }
    fn last_index(&self) -> u32 {
        self.entry.index
    }
    fn last_hash(&self) -> Digest {
        self.entry.hash()
    }
    fn trusted_devices_count(&self) -> u32 {
        self.trusted_devices.len() as u32
    }
    fn is_device_trusted(&self, device: &PublicKey) -> bool {
        self.trusted_devices.contains_key(device)
    }
    fn device_capabilities(
        &self,
        device: &PublicKey,
    ) -> Option<Capabilities> {
        self.trusted_devices.get(device).map(|x| x.0)
    }
}

/// TODO: Review the checks (and simplify by merging with other checks)
/// This is not production-ready.

impl ShortJournal {
    pub fn new() {}
    pub fn can_add_entry(&self, le: &JournalEntry) -> bool {
        Validator::validate_entry::<ShortJournal>(&self, le).is_ok()
    }
    pub fn get_entry(&self) -> JournalEntry {
        self.entry.clone()
    }
    pub fn add_entry(&mut self, le: JournalEntry) -> bool {
        if self.can_add_entry(&le) {
            self.entry = le.clone();
            match le.operation {
                Operation::JournalInit { .. } => { unreachable!("can_add_entry should have caught this invalid case (bulk add cannot be a non-first entry)")}
                Operation::DeviceAdd { subject, capabilities, .. } => {
                    self.trusted_devices.insert(subject, (capabilities, le));
                }
                Operation::DeviceRemove { subject, .. } => {
                    self.trusted_devices.remove(&subject);
                }
                Operation::DeviceReplace {
                    removed_subject,
                    added_subject,
                    capabilities,
                    ..
                } => {
                    self.trusted_devices.remove(&removed_subject);
                    self.trusted_devices.insert(added_subject, (capabilities, le));
                }
                Operation::DeviceSelfReplace { added_subject, .. } => {
                    match self.trusted_devices.remove(&le.issuer) {
                        None => { unreachable!("can_add_entry should have caught this invalid case (you can't self-replace a device that wasn't trusted)") }
                        Some((capabilities, _)) => {
                            self.trusted_devices.insert(added_subject, (capabilities, le)); } }
                }
            };
            self.hash = self.entry.hash();
            return true;
        }
        drop(le);
        false
    }
    pub fn is_device_trusted(&self, device: &PublicKey) -> bool {
        self.trusted_devices.contains_key(device)
    }
    pub fn get_journal_version(&self) -> u32 {
        self.version
    }
    pub fn get_journal_id(&self) -> JournalID {
        self.journal_id
    }
    pub fn get_journal_hash(&self) -> Digest {
        self.hash
    }
}
