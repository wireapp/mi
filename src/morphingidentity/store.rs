use entries::{JournalEntry, EntryType, DeviceType};
use journal::{FullJournal, JournalID, UserID};
use std::collections::HashMap;

pub struct JournalStore {
    pub journal_id_by_user_id: HashMap<UserID, JournalID>,
    pub journal_by_journal_id: HashMap<JournalID, FullJournal>,
}

impl JournalStore {
    pub fn new() -> JournalStore {
        JournalStore {
            journal_id_by_user_id: HashMap::new(),
            journal_by_journal_id: HashMap::new(),
        }
    }
    pub fn get_journal_by_journal_id(&self, j: &JournalID) -> Option<&FullJournal> {
        self.journal_by_journal_id.get(j)
    }
    pub fn get_journal_by_user_id(&self, u: &UserID) -> Option<&FullJournal> {
        self.journal_by_journal_id.get(self.journal_id_by_user_id.get(u)?)
    }
    // pub fn insert_or_replace_journal(&mut self, u: UserID, j: &FullJournal) -> bool {
    // match self.journal_id_by_user_id.insert(u, j.get_journal_id()) {
    // Some(x) => self.journal_by_journal_id.remove(&x),
    // };
    // self.journal_by_journal_id.insert(j.get_journal_id(), j.clone());
    // true
    // }
    //
}
