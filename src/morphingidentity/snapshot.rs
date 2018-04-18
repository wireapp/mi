use sodiumoxide::crypto::hash::sha256::Digest;

/// A snapshot of journal state at some specific moment of time. This
/// information is all that is needed to check that somebody:
///
///   * has the right journal ID (e.g. the actual current journal of
///     a user, and not one of previous journals),
///
///   * has the latest version of the journal,
///
///   * and the journal hasn't been corrupted or altered.
///
pub struct Snapshot {
    /// Journal ID
    pub journal_id: u32,
    /// Index of the latest entry
    pub count: u32,
    /// Complete hash of the latest entry (computed as taking the hash of the bytestring
    /// that the entry encodes to)
    pub advanced_hash: Digest,
}
