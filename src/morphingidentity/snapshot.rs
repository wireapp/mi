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
/// However, a snapshot doesn't contain any entries and it's impossible to
/// validate an entry against a snapshot.
pub struct Snapshot {
    /// Journal ID
    pub journal_id: u32,
    /// Index of the latest entry
    pub index: u32,
    /// Complete hash of the latest entry (computed as taking the hash of the bytestring
    /// that the entry encodes to)
    pub advanced_hash: Digest,
}

/// The Distribution Tag is included in the Proteus message envelope to
/// force journal updates on the receiving end.
pub struct DistributionTag {
    pub journal_snapshot: Snapshot,
}
