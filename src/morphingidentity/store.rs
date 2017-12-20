use entries::{JournalEntry, EntryType, DeviceType};
use journal::{FullJournal, JournalID, UserID};
use std::collections::HashMap;

pub struct JournalStore {
    pub journal_ids: HashMap<UserID, JournalID>,
    pub journals: HashMap<JournalID, FullJournal>,
}

impl JournalStore {
    pub fn get_journal_by_journal_id(&self, j: &JournalID) -> Option<&FullJournal> {
        self.journals.get(j)
    }
    pub fn get_journal_by_user_id(&self, u: &UserID) -> Option<&FullJournal> {
        self.journals.get(self.journal_ids.get(u)?)
    }
}
