use entries::{DeviceInfo, JournalEntry};
use journal::*;
use operation::*;

pub struct Validator {}

impl Validator {
    pub fn validate_entry(
        journal: &FullJournal,
        entry: &JournalEntry,
    ) -> bool {
        let last_entry = journal.get_entries().last().unwrap();
        if last_entry.index == u32::max_value()
            || entry.journal_id != journal.get_journal_id()
            || last_entry.hash()[..] != entry.history_hash[..]
            || entry.index != (last_entry.index + 1)
        {
            return false;
        }
        match entry.operation {
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
    pub fn validate_first_entry(
        entry: &JournalEntry,
    ) -> Option<DeviceInfo> {
        match entry.operation {
            Operation::DeviceAdd {
                subject,
                capabilities,
                ..
            } if subject == entry.issuer
                && entry
                    .verify_signature(&entry.issuer, &entry.signature) =>
            {
                Some(DeviceInfo {
                    key: subject,
                    capabilities,
                    entry: entry.clone(),
                })
            }
            _ => None,
        }
    }
    pub fn validate_journal() {}
    fn validate_device_add(
        journal: &FullJournal,
        entry: &JournalEntry,
    ) -> bool {
        match entry.operation {
            Operation::DeviceAdd {
                subject,
                subject_signature,
                ..
            } => {
                let trusted_devices = journal.get_trusted_devices();
                let too_many_trusted_devices =
                    trusted_devices.len() >= MAX_DEVICES;
                let issuer_can_add =
                    match journal.get_trusted_device(&entry.issuer) {
                        Some(device) => device.capability_can_add(),
                        None => false,
                    };
                !too_many_trusted_devices
                    && issuer_can_add
                    && !trusted_devices.contains_key(&subject)
                    && entry
                        .verify_signature(&entry.issuer, &entry.signature)
                    && entry.verify_signature(&subject, &subject_signature)
            }
            _ => false,
        }
    }
    fn validate_device_remove(
        journal: &FullJournal,
        entry: &JournalEntry,
    ) -> bool {
        match entry.operation {
            Operation::DeviceRemove { subject, .. } => {
                let trusted_devices = journal.get_trusted_devices();
                let too_few_trusted_devices = trusted_devices.len() <= 1;
                let issuer_can_remove =
                    match journal.get_trusted_device(&entry.issuer) {
                        Some(device) => device.capability_can_remove(),
                        None => false,
                    };
                let subject_is_removable = match journal
                    .get_trusted_device(&subject)
                {
                    Some(device) => !device.capability_cannot_be_removed(),
                    None => false,
                };
                !too_few_trusted_devices
                    && issuer_can_remove
                    && subject_is_removable
                    && entry
                        .verify_signature(&entry.issuer, &entry.signature)
            }
            _ => false,
        }
    }
    fn validate_device_replace(
        journal: &FullJournal,
        entry: &JournalEntry,
    ) -> bool {
        match entry.operation {
            Operation::DeviceReplace {
                removed_subject,
                added_subject,
                added_subject_signature,
                ..
            } => {
                let trusted_devices = journal.get_trusted_devices();
                let issuer_can_replace =
                    match journal.get_trusted_device(&entry.issuer) {
                        Some(device) => {
                            device.capability_can_remove()
                                && device.capability_can_add()
                        }
                        None => false,
                    };
                let removed_subject_is_removable = match journal
                    .get_trusted_device(&removed_subject)
                {
                    Some(device) => !device.capability_cannot_be_removed(),
                    None => false,
                };
                let added_subject_is_new =
                    !trusted_devices.contains_key(&added_subject);
                issuer_can_replace
                    && removed_subject_is_removable
                    && added_subject_is_new
                    && entry
                        .verify_signature(&entry.issuer, &entry.signature)
                    && entry.verify_signature(
                        &added_subject,
                        &added_subject_signature,
                    )
            }
            _ => false,
        }
    }
    fn validate_device_self_replace(
        journal: &FullJournal,
        entry: &JournalEntry,
    ) -> bool {
        match entry.operation {
            Operation::DeviceSelfReplace {
                added_subject,
                added_subject_signature,
                ..
            } => {
                let trusted_devices = journal.get_trusted_devices();
                let issuer_can_self_update =
                    match journal.get_trusted_device(&entry.issuer) {
                        Some(device) => device.capability_can_self_update(),
                        None => false,
                    };
                let added_subject_is_new =
                    !trusted_devices.contains_key(&added_subject);
                issuer_can_self_update && added_subject_is_new
                    && entry
                        .verify_signature(&entry.issuer, &entry.signature)
                    && entry.verify_signature(
                        &added_subject,
                        &added_subject_signature,
                    )
            }
            _ => false,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ValidatorError {
    /// *Addition:* there can be at most `device_limit` trusted devices at
    /// any time, and this limit has been exceeded.
    DeviceLimitExceeded { device_limit: u32 },
    /// *Addition or replacement:* a device that is being added to journal
    /// is already trusted by the journal and can't be added again.
    DeviceAlreadyTrusted,
    /// *Removal:* you're trying to remove the last trusted device from the
    /// journal.
    LastDevice,
    /// *Removal or replacement:* you're trying to remove a device that is
    /// not in the journal.
    SubjectNotFound,
}
