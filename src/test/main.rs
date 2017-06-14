extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate cbor;

extern crate morphingidentity;

use cbor::{Decoder, Encoder};
use rustc_serialize::json::ToJson;

use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::hash;
use sodiumoxide::randombytes::randombytes;

// use morphingidentity::ledger::Ledger;
use morphingidentity::entries::{EntryType, LedgerEntry, DeviceType};
use morphingidentity::ledger::FullLedger;

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

    let data1 = vec![1, 2, 3];
    let data2 = vec![4, 5, 6];

    let mut e = Encoder::from_memory();
    e.encode(&data1).unwrap();
    e.encode(&data2).unwrap();

    let mut d = Decoder::from_bytes(e.as_bytes());
    // let items: Vec<u8> = d.decode().collect::<Result<_, _>>().unwrap();

    // assert_eq!(items, data);

    let cbordata = d.items().next().unwrap().unwrap();
    let jsondata = cbordata.to_json();

    println!("Hex: {}", morphingidentity::utils::fmt_hex(&e.as_bytes()));

    println!("JSON: {}", jsondata);

    // Example
    let mut le: LedgerEntry = LedgerEntry::new(1,
                                               1,
                                               hash::sha256::hash(&[]),
                                               0,
                                               EntryType::Add,
                                               DeviceType::PermanentDevice);
    assert_eq!(morphingidentity::utils::fmt_hex(&le.history_hash[..]),
               "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    let (issuer_pk, issuer_sk) = sign::gen_keypair();
    let (subject_pk, subject_sk) = sign::gen_keypair();

    le.issuer_publickey = issuer_pk;
    le.subject_publickey = subject_pk;

    assert!(le.add_issuer_signature(&issuer_sk));
    assert!(le.add_subject_signature(&subject_sk));

    // ---------------   Example usage

    // Create a new ledger with ledger ID 1000 and a first entry
    let mut full_ledger = FullLedger::new(1000, &issuer_pk, &issuer_sk).unwrap();

    // Check if the ledger is valid
    assert!(full_ledger.check_ledger());

    // Test if a random entry can be added to the ledger
    assert!(!full_ledger.test_entry(&le));

    // Get the ledger version (number of entries in the ledger)
    assert_eq!(full_ledger.get_ledger_version(), 0);

    // Get the history hash of the ledger
    println!("Ledger history hash: {}",
             morphingidentity::utils::fmt_hex(&full_ledger.get_ledger_hash()[..]));

    // Prepare a new entry by adding a device
    let mut second_entry = full_ledger.create_entry(EntryType::Add,
                      DeviceType::PermanentDevice,
                      &issuer_pk,
                      &issuer_sk,
                      &subject_pk)
        .unwrap();

    // Test some properties of the new entry
    assert_eq!(second_entry.ledger_id, 1000);
    assert_eq!(second_entry.count, 1);

    // Test if the new entry can be added to the ledger
    // (the subject's signature is missing at this point)
    assert!(!full_ledger.test_entry(&second_entry));

    // Have the subject sign the new entry (only needed when adding a device)
    assert!(full_ledger.sign_entry_as_subject(&mut second_entry, &subject_sk));

    // Testing again now that the signature is there
    assert!(full_ledger.test_entry(&second_entry));

    // Adding the new entry to the ledger
    assert!(full_ledger.add_entry(second_entry.clone()));

    // Testing if the ledger is still valid after that
    assert!(full_ledger.check_ledger());

    // Testing if the new device is now trusted
    assert!(full_ledger.is_device_trusted(&subject_pk));

    // Checking that the ledger version has been incremented
    assert_eq!(full_ledger.get_ledger_version(), 1);

    // The hash should also have changed now
    println!("Ledger hash: {}",
             morphingidentity::utils::fmt_hex(&full_ledger.get_ledger_hash()[..]));

    // Adding the same entry again shouldn't work
    assert!(!full_ledger.add_entry(second_entry));

    // Display all trusted devices in the ledger
    for (pk, l) in full_ledger.get_trusted_devices() {
        println!("Subject PublicKey: {}, Issuer PublicKey {}, count {}",
                 morphingidentity::utils::fmt_hex(&pk[..]),
                 morphingidentity::utils::fmt_hex(&l.issuer_publickey[..]),
                 l.count);
    }

    // Preparing a new entry to remove the second device
    let mut third_entry = full_ledger.create_entry(EntryType::Remove,
                      DeviceType::PermanentDevice,
                      &issuer_pk,
                      &issuer_sk,
                      &subject_pk)
        .unwrap();

    // Checking count is correct
    assert_eq!(third_entry.count, 2);

    // Checking the new entry can be added to the ledger
    assert!(full_ledger.test_entry(&third_entry));

    // Signing an entry of type 'Remove' as the subject makes no sense
    assert!(!full_ledger.sign_entry_as_subject(&mut third_entry, &subject_sk));

    // Add the third entry to the ledger
    assert!(full_ledger.add_entry(third_entry.clone()));

    // Check if the ledger is still valid after that
    assert!(full_ledger.check_ledger());

    // The ledger hash should have changed
    println!("Ledger hash: {}",
             morphingidentity::utils::fmt_hex(&full_ledger.get_ledger_hash()[..]));

    // Adding the third entry again shouldn't work
    assert!(!full_ledger.add_entry(third_entry));

    // Checking if the second device is not trusted anymore
    assert!(!full_ledger.is_device_trusted(&subject_pk));

    // Display the list of trusted devices
    for (pk, l) in full_ledger.get_trusted_devices() {
        println!("Subject PublicKey: {}, Issuer PublicKey {}, count {}",
                 morphingidentity::utils::fmt_hex(&pk[..]),
                 morphingidentity::utils::fmt_hex(&l.issuer_publickey[..]),
                 l.count);
    }

    // -------------- Random ledger
    // Building a long ledger with random entries

    println!("-------- Random ledger ---------");

    const DEVICES: usize = 8;
    const ITER: u32 = 10000;

    let mut sec_keys = Vec::new();
    let mut pub_keys = Vec::new();

    for _i in 0..DEVICES {
        let (p_key, s_key) = sign::gen_keypair();
        sec_keys.push(s_key);
        pub_keys.push(p_key);
    }

    let mut rl = FullLedger::new(random_u32!(), &pub_keys[0], &sec_keys[0]).unwrap();

    for _i in 0..ITER {
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
                assert!(rl.add_entry(new_entry));
            }
        }
    }
    println!("Permanent hash: {}",
             morphingidentity::utils::fmt_hex(&rl.get_permanent_hash()[..]));
    for (pk, l) in &rl.get_trusted_devices() {
        println!("Trusted devices: Subject PublicKey: {}, Issuer PublicKey {}, count {}",
                 morphingidentity::utils::fmt_hex(&pk[..]),
                 morphingidentity::utils::fmt_hex(&l.issuer_publickey[..]),
                 l.count);
        let mut pe = l;
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
    assert!(rl.check_ledger());
}
