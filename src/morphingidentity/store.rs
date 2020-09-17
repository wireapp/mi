use crate::journal::{FullJournal, JournalID, UserID};
use std::collections::HashMap;

#[derive(Default)]
pub struct JournalStore {
    pub journal_id_by_user_id: HashMap<UserID, JournalID>,
    pub journal_by_journal_id: HashMap<JournalID, FullJournal>,
}

impl JournalStore {
    pub fn new() -> JournalStore {
        Default::default()
    }
    pub fn get_journal_by_journal_id(
        &self,
        j: JournalID,
    ) -> Option<&FullJournal> {
        self.journal_by_journal_id.get(&j)
    }
    pub fn get_journal_by_user_id(
        &self,
        u: UserID,
    ) -> Option<&FullJournal> {
        self.journal_by_journal_id
            .get(self.journal_id_by_user_id.get(&u)?)
    }
    pub fn insert_or_replace_journal(
        &mut self,
        u: UserID,
        j: &FullJournal,
    ) -> Option<FullJournal> {
        if let Some(x) =
            self.journal_id_by_user_id.insert(u, j.get_journal_id())
        {
            self.journal_by_journal_id.remove(&x);
        };
        self.journal_by_journal_id
            .insert(j.get_journal_id(), j.clone())
    }
    pub fn remove_journal_by_user_id(
        &mut self,
        u: UserID,
    ) -> Option<FullJournal> {
        match self.journal_id_by_user_id.remove(&u) {
            Some(x) => self.journal_by_journal_id.remove(&x),
            None => None,
        }
    }
    pub fn remove_orphaned_journals(&mut self) {
        JournalStore::retain_valid_journals(
            &self.journal_id_by_user_id,
            &mut self.journal_by_journal_id,
        );
    }
    fn retain_valid_journals(
        h1: &HashMap<UserID, JournalID>,
        h2: &mut HashMap<JournalID, FullJournal>,
    ) {
        h2.retain(|&k, _| h1.values().any(|x| *x == k));
    }
}
