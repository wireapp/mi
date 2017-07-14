use sodiumoxide::crypto::hash::sha256::Digest;

pub struct DistributionTag {
    pub journal_id: u32,
    pub count: u32,
    pub advanced_hash: Digest,
}
