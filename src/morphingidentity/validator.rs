use entries::{is_permanent, JournalEntry};
use journal::*;
use operation::*;
use sodiumoxide::crypto::sign::ed25519::PublicKey;
use std::collections::HashSet;
use std::error::Error;
use std::fmt;

pub struct Validator {}

impl Validator {
    pub fn validate_entry(
        journal: &FullJournal,
        entry: &JournalEntry,
    ) -> Result<(), ValidatorError> {
        // There needs to be at least 1 entry in the journal
        if journal.get_entries().is_empty() {
            return Err(ValidatorError::EmptyJournal);
        }
        let last_entry = journal.get_entries().last().unwrap();
        // The journal cannot be full
        if last_entry.index == u32::max_value() {
            return Err(ValidatorError::FullJournal);
        }
        // The entry journal ID needs to match the journal ID of the journal
        if entry.journal_id != journal.get_journal_id() {
            return Err(ValidatorError::JournalIdMismatch);
        }
        // The index of the entry needs to match the next index of the journal
        if entry.index != (last_entry.index + 1) {
            return Err(ValidatorError::IndexMismatch);
        }
        // The history hash of the entry needs to match the hash of the journal
        if last_entry.hash()[..] != entry.history_hash[..] {
            return Err(ValidatorError::HashMismatch);
        }
        // Issuer signature needs to be valid
        if !entry.verify_signature(&entry.issuer, &entry.signature) {
            return Err(ValidatorError::IssuerSignatureInvalid);
        }
        match entry.operation {
            Operation::JournalInit { .. } => {
                Err(ValidatorError::InvalidOperation)
            }
            Operation::DeviceAdd { .. } => {
                Self::validate_device_add(journal, entry)
            }
            Operation::DeviceRemove { .. } => {
                Self::validate_device_remove(journal, entry)
            }
            Operation::DeviceReplace { .. } => {
                Self::validate_device_replace(journal, entry)
            }
            Operation::DeviceSelfReplace { .. } => {
                Self::validate_device_self_replace(journal, entry)
            }
        }
    }

    pub fn validate_unsigned_subject_entry(
        journal: &FullJournal,
        entry: &JournalEntry,
    ) -> Result<(), ValidatorError> {
        match Self::validate_entry(journal, entry) {
            Ok(()) => Ok(()),
            Err(e) => match e {
                ValidatorError::SubjectSignatureInvalid => Ok(()),
                _ => Err(e),
            },
        }
    }

    fn validate_device_add(
        journal: &FullJournal,
        entry: &JournalEntry,
    ) -> Result<(), ValidatorError> {
        match entry.operation {
            Operation::DeviceAdd {
                subject,
                subject_signature,
                ..
            } => {
                let trusted_devices = journal.get_trusted_devices();
                // There needs to be an available slot for a new trusted device
                if trusted_devices.len() >= MAX_DEVICES {
                    return Err(ValidatorError::TooManyTrustedDevices {
                        device_limit: MAX_DEVICES,
                    });
                }
                match journal.get_trusted_device(&entry.issuer) {
                    Some(device) => {
                        // Issuer device needs to have the capability to add other devices
                        if !device.capability_can_add() {
                            return Err(ValidatorError::IssuerCannotAdd);
                        }
                    }
                    None => {
                        // Issuer needs to be a trusted device
                        return Err(ValidatorError::IssuerNotFound);
                    }
                };
                // Subject device needs to be new to the journal
                if trusted_devices.contains_key(&subject) {
                    return Err(ValidatorError::SubjectAlreadyExists);
                }
                // Subject sugnature needs to be valid
                if !entry.verify_signature(&subject, &subject_signature) {
                    return Err(ValidatorError::SubjectSignatureInvalid);
                }
                Ok(())
            }
            _ => unreachable!(),
        }
    }

    fn validate_device_remove(
        journal: &FullJournal,
        entry: &JournalEntry,
    ) -> Result<(), ValidatorError> {
        match entry.operation {
            Operation::DeviceRemove { subject, .. } => {
                let trusted_devices = journal.get_trusted_devices();
                // There needs to be at least one device left in the journal
                if trusted_devices.len() <= 1 {
                    return Err(ValidatorError::TooFewTrustedDevices);
                }
                match journal.get_trusted_device(&entry.issuer) {
                    Some(device) => {
                        // Issuer device needs to have the capability to remove other devices
                        if !device.capability_can_remove() {
                            return Err(ValidatorError::IssuerCannotRemove);
                        }
                    }
                    None => {
                        // Issuer needs to be a trusted device
                        return Err(ValidatorError::IssuerNotFound);
                    }
                };
                match journal.get_trusted_device(&subject) {
                    Some(device) => {
                        if device.capability_cannot_be_removed() {
                            // Subject needs to be removable
                            return Err(ValidatorError::SubjectNotRemovable);
                        }
                    }
                    None => {
                        // Subject needs to be a trusted device
                        return Err(ValidatorError::SubjectNotFound);
                    }
                };
                Ok(())
            }
            _ => unreachable!(),
        }
    }

    fn validate_device_replace(
        journal: &FullJournal,
        entry: &JournalEntry,
    ) -> Result<(), ValidatorError> {
        match entry.operation {
            Operation::DeviceReplace {
                removed_subject,
                added_subject,
                added_subject_signature,
                ..
            } => {
                let trusted_devices = journal.get_trusted_devices();
                match journal.get_trusted_device(&entry.issuer) {
                    Some(device) => {
                        // Issuer device needs to have the capability to remove other devices
                        if !device.capability_can_remove() {
                            return Err(ValidatorError::IssuerCannotRemove);
                        }
                        // Issuer device needs to have the capability to add other devices
                        if !device.capability_can_add() {
                            return Err(ValidatorError::IssuerCannotAdd);
                        }
                    }
                    None => {
                        // Issuer needs to be a trusted device
                        return Err(ValidatorError::IssuerNotFound);
                    }
                };
                // Removed subject needs to be removable
                match journal.get_trusted_device(&removed_subject) {
                    Some(device) => {
                        if device.capability_cannot_be_removed() {
                            return Err(ValidatorError::SubjectNotRemovable);
                        }
                    }
                    None => {
                        // Subject needs to be a trusted device
                        return Err(ValidatorError::SubjectNotFound);
                    }
                };
                // Added subject device needs to be new to the journal
                if trusted_devices.contains_key(&added_subject) {
                    return Err(ValidatorError::SubjectAlreadyExists);
                }
                // Added subject signature needs to be valid
                if !entry.verify_signature(
                    &added_subject,
                    &added_subject_signature,
                ) {
                    return Err(ValidatorError::SubjectSignatureInvalid);
                }
                Ok(())
            }
            _ => unreachable!(),
        }
    }

    fn validate_device_self_replace(
        journal: &FullJournal,
        entry: &JournalEntry,
    ) -> Result<(), ValidatorError> {
        match entry.operation {
            Operation::DeviceSelfReplace {
                added_subject,
                added_subject_signature,
                ..
            } => {
                let trusted_devices = journal.get_trusted_devices();
                match journal.get_trusted_device(&entry.issuer) {
                    Some(device) => {
                        // Issuer needs to have the self-update capability
                        if !device.capability_can_self_update() {
                            return Err(
                                ValidatorError::IssuerCannotSelfUpdate,
                            );
                        }
                    }
                    None => {
                        // Issuer needs to be a trusted device
                        return Err(ValidatorError::IssuerNotFound);
                    }
                };
                // Added subject device needs to be new to the journal
                if trusted_devices.contains_key(&added_subject) {
                    return Err(ValidatorError::SubjectAlreadyExists);
                }
                // Added subject signature needs to be valid
                if !entry.verify_signature(
                    &added_subject,
                    &added_subject_signature,
                ) {
                    return Err(ValidatorError::SubjectSignatureInvalid);
                }
                Ok(())
            }
            _ => unreachable!(),
        }
    }

    /// invariants:
    /// * the entry must be JournalInit
    /// * there should be [1..MAX_DEVICES] in total
    /// * issuer has to be one of devices that are being added
    /// * issuer has to be added with capabilities that permit device addition
    /// * the set of devices must not contain any duplicates
    pub fn validate_journal_init(
        entry: &JournalEntry,
    ) -> Result<(), ValidatorError> {
        match entry.operation.clone() {
            Operation::JournalInit { devices, .. } => {
                if entry.index != 0 {
                    return Err(ValidatorError::InvalidJournalInit);
                }
                let subjects: HashSet<PublicKey> =
                    devices.iter().map(|(_, s)| *s).collect();
                // issuer has to be one of devices that are being added
                if !subjects.contains(&entry.issuer) {
                    return Err(ValidatorError::InvalidJournalInit);
                }
                let issuer_device =
                    devices.iter().find(|(_, s)| *s == entry.issuer);
                match issuer_device {
                    None => return Err(ValidatorError::InvalidJournalInit),
                    // issuer has to be added with capabilities that permit device addition
                    Some((capabilities, _)) => {
                        if !is_permanent(*capabilities) {
                            return Err(ValidatorError::InvalidJournalInit);
                        }
                    }
                }
                // the set of devices must not contain any duplicates
                if subjects.len() != devices.len() {
                    return Err(ValidatorError::InvalidJournalInit);
                }
            }
            _ => return Err(ValidatorError::InvalidOperation),
        }
        if !entry.verify_signature(&entry.issuer, &entry.signature) {
            return Err(ValidatorError::IssuerSignatureInvalid);
        }
        Ok(())
    }

    pub fn validate_journal(
        journal: &FullJournal,
    ) -> Result<(), ValidatorError> {
        let entries = journal.get_entries();
        if entries.is_empty() {
            return Err(ValidatorError::EmptyJournal);
        }
        // Check the first entry
        let first_entry: &JournalEntry = entries.first().unwrap();
        let mut new_journal: FullJournal =
            FullJournal::new_from_entry(first_entry.clone())?;
        // Check all other entries
        for je in entries.iter().skip(1) {
            match new_journal.add_entry(je.clone()) {
                Err(e) => {
                    println!("{}", e);
                    return Err(e);
                }
                Ok(()) => {}
            };
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum ValidatorError {
    /// *All operations:* The journal is empty and needs a first entry.
    EmptyJournal,
    /// *All operations:* The journal is full and cannot be extended.
    FullJournal,
    /// *All operations:* The entry's `journal_id` does not match the journal's `journal_id`.
    JournalIdMismatch,
    /// *All operations:* The entry's `index` does not match the journal's `index`.
    IndexMismatch,
    /// *All operations:* The entry's `history_hash` does not match the journal's `hash`.
    HashMismatch,
    /// *Removal or replacement:* The subject is not in the journal.
    SubjectNotFound,
    /// *Addition or replacement:* The subject is already trusted by the journal.
    SubjectAlreadyExists,
    /// *All operations:* The issuer is not trusted.
    IssuerNotFound,
    /// *Addition or replacement:* The issuer is not trusted.
    IssuerCannotAdd,
    /// *Addition or replacement:* The issuer cannot remove other devices.
    IssuerCannotRemove,
    /// *Removal or replacement:* The subject is not removable.
    SubjectNotRemovable,
    /// *Addition:* There can be at most `device_limit` trusted devices at
    /// any time, and this limit has been exceeded.
    TooManyTrustedDevices { device_limit: usize },
    /// *Removal:* The last trusted device cannot be removed from the journal.
    TooFewTrustedDevices,
    /// *All operations:* The issuer's signature is not valid.
    IssuerSignatureInvalid,
    /// *Add, Replacement or self-update:* The subject's signature is not valid.
    SubjectSignatureInvalid,
    /// *Self-update:* The issuer is not allowed to self-update.
    IssuerCannotSelfUpdate,
    /// *All operations:* Invalid operation (e.g. `JournalInit` is not the
    /// first entry, or the first entry is not `JournalInit`)
    InvalidOperation,
    /// *Journal init:* something is wrong.
    InvalidJournalInit,
}

impl fmt::Display for ValidatorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            ValidatorError::EmptyJournal => write!(f, "The journal is empty and needs a first entry."),
            ValidatorError::FullJournal => write!(f, "The journal is full and cannot be extended."),
            ValidatorError::JournalIdMismatch => write!(f, "The entry's `journal_id` does not match the journal's `journal_id`."),
            ValidatorError::IndexMismatch => write!(f, "The entry's `index` does not match the journal's `index`."),
            ValidatorError::HashMismatch => write!(f, "The entry's `history_hash` does not match the journal's `hash`."),
            ValidatorError::SubjectNotFound => write!(f, "The subject is not in the journal."),
            ValidatorError::SubjectAlreadyExists => write!(f, "The subject is already trusted by the journal."),
            ValidatorError::IssuerNotFound => write!(f, "The issuer is not trusted."),
            ValidatorError::IssuerCannotAdd => write!(f, "The issuer is not trusted."),
            ValidatorError::IssuerCannotRemove => write!(f, "The issuer cannot remove other devices."),
            ValidatorError::SubjectNotRemovable => write!(f, "The subject is not removable."),
            ValidatorError::TooManyTrustedDevices { device_limit } => {
                write!(f, "There can be at most {} trusted devices at any time, and this limit has been exceeded.", device_limit)
            }
            ValidatorError::TooFewTrustedDevices => write!(f, "The last trusted device cannot be removed from the journal."),
            ValidatorError::IssuerSignatureInvalid => write!(f, "The issuer's signature is not valid."),
            ValidatorError::SubjectSignatureInvalid => write!(f, "The subject's signature is not valid."),
            ValidatorError::IssuerCannotSelfUpdate => write!(f, "The issuer is not allowed to self-update."),
            ValidatorError::InvalidOperation => write!(f, "Invalid operation."),
            ValidatorError::InvalidJournalInit => write!(f, "Something is wrong about JournalInit."),
        }
    }
}

impl Error for ValidatorError {
    fn description(&self) -> &str {
        "ValidatorError"
    }
}
