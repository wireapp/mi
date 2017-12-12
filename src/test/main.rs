extern crate sodiumoxide;
extern crate cbor;

extern crate morphingidentity;

use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::hash;
use sodiumoxide::randombytes::randombytes;

use morphingidentity::entries::{EntryType, JournalEntry, DeviceType};
use morphingidentity::journal::FullJournal;

// use std::result::{Ok, Err};

const MAX_DEVICES: usize = 8;

fn init() {
    sodiumoxide::init();
}

macro_rules! random_usize {
    () => (randombytes(1)[0] as usize)
}

#[allow(unused_macros)]
macro_rules! random_u8 {
    () => (randombytes(1)[0])
}

macro_rules! random_u32 {
    () => (((randombytes(1)[0] as u32) << 24 |
    (randombytes(1)[0] as u32) << 16 |
    (randombytes(1)[0] as u32) << 8 |
    randombytes(1)[0] as u32))
}

// This is the main function
#[allow(dead_code)]
fn main() {
    init();

    // Some tests
    let mut je: JournalEntry = JournalEntry::new(1,
                                                 1,
                                                 hash::sha256::hash(&[]),
                                                 0,
                                                 EntryType::Add,
                                                 DeviceType::PermanentDevice);
    assert_eq!(morphingidentity::utils::fmt_hex(&je.history_hash[..]),
               "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    let (issuer_pk, issuer_sk) = sign::gen_keypair();
    let (subject_pk, subject_sk) = sign::gen_keypair();

    je.issuer_publickey = issuer_pk;
    je.subject_publickey = subject_pk;

    assert!(je.add_issuer_signature(&issuer_sk));
    assert!(je.add_subject_signature(&subject_sk));

    let encoded = je.encode_as_cbor();

    let decoded = JournalEntry::new_from_cbor(encoded.clone()).unwrap();


    let dec = decoded.clone();
    let reenc = dec.encode_as_cbor();

    let invalid_entry = je.clone();

    assert_eq!(encoded, reenc);

    println!("Length of journal entry: {}", encoded.len());


    // ---------------   Example usage

    // Create a new journal with journal ID 1000 and a first entry
    let mut full_journal = FullJournal::new(1000, &issuer_pk, &issuer_sk).unwrap();

    // Check if the journal is valid
    assert!(full_journal.check_journal());

    // Test if a random entry can be added to the journal
    assert!(!full_journal.test_entry(&invalid_entry));

    // Get the journal version (number of entries in the journal)
    assert_eq!(full_journal.get_journal_version(), 0);

    // Get the history hash of the journal
    println!("Journal history hash: {}",
             morphingidentity::utils::fmt_hex(&full_journal.get_journal_hash()[..]));

    // Prepare a new entry by adding a device
    let mut second_entry = full_journal.create_entry(EntryType::Add,
                      DeviceType::PermanentDevice,
                      &issuer_pk,
                      &issuer_sk,
                      &subject_pk)
        .unwrap();

    // Test some properties of the new entry
    assert_eq!(second_entry.journal_id, 1000);
    assert_eq!(second_entry.count, 1);

    // Test if the new entry can be added to the journal
    // (the subject's signature is missing at this point)
    assert!(!full_journal.test_entry(&second_entry));

    // Have the subject sign the new entry (only needed when adding a device)
    assert!(full_journal.sign_entry_as_subject(&mut second_entry, &subject_sk));

    // Testing again now that the signature is there
    assert!(full_journal.test_entry(&second_entry));

    // Adding the new entry to the journal
    assert!(full_journal.add_entry(second_entry.clone()));

    // Testing if the journal is still valid after that
    assert!(full_journal.check_journal());

    // Testing if the new device is now trusted
    assert!(full_journal.is_device_trusted(&subject_pk));

    // Checking that the journal version has been incremented
    assert_eq!(full_journal.get_journal_version(), 1);

    // The hash should also have changed now
    println!("Journal hash: {}",
             morphingidentity::utils::fmt_hex(&full_journal.get_journal_hash()[..]));

    // Adding the same entry again shouldn't work
    assert!(!full_journal.add_entry(second_entry));

    // Display all trusted devices in the journal
    for (pk, j) in full_journal.get_trusted_devices() {
        println!("Subject PublicKey: {}, Issuer PublicKey {}, count {}",
                 morphingidentity::utils::fmt_hex(&pk[..]),
                 morphingidentity::utils::fmt_hex(&j.issuer_publickey[..]),
                 j.count);
    }

    // Preparing a new entry to remove the second device
    let mut third_entry = full_journal.create_entry(EntryType::Remove,
                      DeviceType::PermanentDevice,
                      &issuer_pk,
                      &issuer_sk,
                      &subject_pk)
        .unwrap();

    // Checking count is correct
    assert_eq!(third_entry.count, 2);

    // Checking the new entry can be added to the journal
    assert!(full_journal.test_entry(&third_entry));

    // Signing an entry of type 'Remove' as the subject makes no sense
    assert!(!full_journal.sign_entry_as_subject(&mut third_entry, &subject_sk));

    // Add the third entry to the journal
    assert!(full_journal.add_entry(third_entry.clone()));

    // Check if the journal is still valid after that
    assert!(full_journal.check_journal());

    // The journal hash should have changed
    println!("Journal hash: {}",
             morphingidentity::utils::fmt_hex(&full_journal.get_journal_hash()[..]));

    // Adding the third entry again shouldn't work
    assert!(!full_journal.add_entry(third_entry));

    // Checking if the second device is not trusted anymore
    assert!(!full_journal.is_device_trusted(&subject_pk));

    // Display the list of trusted devices
    for (pk, j) in full_journal.get_trusted_devices() {
        println!("Subject PublicKey: {}, Issuer PublicKey {}, count {}",
                 morphingidentity::utils::fmt_hex(&pk[..]),
                 morphingidentity::utils::fmt_hex(&j.issuer_publickey[..]),
                 j.count);
    }

    // -------------- Fuzzing
    // Building a long journal with random entries to do some fuzzing

    println!("-------- Random journal ---------");
    println!("Generating {} entries", ITER);

    const DEVICES: usize = 8;
    const ITER: u32 = 1000;

    let mut sec_keys = Vec::new();
    let mut pub_keys = Vec::new();

    for _i in 0..DEVICES {
        let (p_key, s_key) = sign::gen_keypair();
        sec_keys.push(s_key);
        pub_keys.push(p_key);
    }

    let mut rl = FullJournal::new(random_u32!(), &pub_keys[0], &sec_keys[0]).unwrap();

    for _i in 0..ITER - 1 {
        let trusted = rl.get_trusted_devices().clone();
        let mut issuer;
        let mut counter;
        let mut iss_pk = &sign::ed25519::PublicKey::from_slice(&[0; sign::PUBLICKEYBYTES]).unwrap();
        let mut iss_sk;
        let mut sub_pk;
        let mut sub_sk;
        let mut operation;
        loop {
            let mut c = random_usize!() % (trusted.len() as usize);
            counter = 0;
            for (_k, e) in &trusted {
                issuer = e;
                iss_pk = &issuer.subject_publickey;
                if counter == c {
                    break;
                }
                counter += 1;
            }
            let mut index = 0;
            for i in 0..pub_keys.len() {
                if &pub_keys[i][..] == &iss_pk[..] {
                    index = i;
                    break;
                }
            }
            iss_sk = &sec_keys[index];
            c = random_usize!() % DEVICES;
            sub_sk = &sec_keys[c];
            sub_pk = &pub_keys[c];

            if trusted.contains_key(sub_pk) {
                operation = EntryType::Remove;
            } else {
                operation = EntryType::Add;
            }
            if (operation == EntryType::Add && trusted.len() < MAX_DEVICES) ||
               (operation == EntryType::Remove && trusted.len() > 1) {
                break;
            }
        }

        match rl.create_entry(operation.clone(),
                              DeviceType::PermanentDevice,
                              iss_pk,
                              iss_sk,
                              sub_pk) {
            None => {
                println!("Couldn't create new entry. Number of trusted devices: {}",
                         trusted.len());
                continue;
            }
            Some(mut new_entry) => {
                if new_entry.operation == EntryType::Add {
                    rl.sign_entry_as_subject(&mut new_entry, sub_sk);
                }
                assert!(rl.test_entry(&new_entry));
                assert!(rl.add_entry(new_entry));
            }
        }
    }
    println!("Permanent hash: {}",
             morphingidentity::utils::fmt_hex(&rl.get_permanent_hash()[..]));
    for (pk, j) in &rl.get_trusted_devices() {
        println!("Trusted devices: Subject PublicKey: {}, Issuer PublicKey {}, count {}",
                 morphingidentity::utils::fmt_hex(&pk[..]),
                 morphingidentity::utils::fmt_hex(&j.issuer_publickey[..]),
                 j.count);
        let mut pe = j;
        print!("Parent(s): ");
        loop {
            match rl.get_parent(pe) {
                Some(x) => {
                    pe = x;
                    if pe.count == 0 {
                        println!("root.");
                        break;
                    } else {
                        print!("{}, ", pe.count);
                    }
                }
                None => break,
            }
        }
    }
    assert!(rl.check_journal());
}
