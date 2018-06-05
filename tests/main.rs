extern crate cbor;
extern crate morphingidentity;
extern crate sodiumoxide;
extern crate uuid;

use morphingidentity::entries::*;
use morphingidentity::journal::*;
use morphingidentity::operation::*;
use morphingidentity::rand_utils::{randomnumber, GoodRand};
use morphingidentity::utils::EMPTYSIGNATURE;
use morphingidentity::validator::*;
use sodiumoxide::crypto::{hash, sign};
use uuid::Uuid;

/// Test that an entry can be created and signed.
#[test]
fn entry_test() {
    sodiumoxide::init();
    let (issuer_pk, issuer_sk) = sign::gen_keypair();
    let (subject_pk, subject_sk) = sign::gen_keypair();
    let operation = Operation::DeviceAdd {
        subject: subject_pk,
        subject_signature: EMPTYSIGNATURE,
        capabilities: DeviceType::PermanentDevice as u32,
    };
    let mut je = JournalEntry::new(
        JournalID(Uuid::nil()),
        hash::sha256::hash(&[]),
        0,
        operation,
        issuer_pk,
    );
    assert_eq!(
        morphingidentity::utils::fmt_hex(&je.history_hash[..]),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let issuer_signature = je.sign(&issuer_sk);
    let subject_signature = je.sign(&subject_sk);
    je.signature = issuer_signature;
    je.operation.set_subject_signature(subject_signature);

    assert!(je.verify_signature(&issuer_pk, &issuer_signature));
    assert!(je.verify_signature(&subject_pk, &subject_signature));
}

/// Test that a journal can be created and an entry can be added to it.
#[test]
fn entry_addition_test() {
    sodiumoxide::init();
    let id = GoodRand::rand();

    // Generate keys for two devices: Issuer and Subject.
    let (issuer_pk, issuer_sk) = sign::gen_keypair();
    let (subject_pk, subject_sk) = sign::gen_keypair();

    // Create a new journal with random journal ID and one entry self-signed
    // by Issuer
    let devices = vec![(DeviceType::PermanentDevice as u32, issuer_pk)];
    let mut full_journal =
        FullJournal::new(id, &issuer_pk, &issuer_sk, devices).unwrap();

    // Check if the journal is valid
    assert!(full_journal.check_journal().is_ok());

    // Get the journal version (number of entries in the journal)
    assert_eq!(full_journal.get_journal_version(), 0);

    // Get the history hash of the journal
    println!(
        "Journal history hash: {}",
        morphingidentity::utils::fmt_hex(
            &full_journal.get_journal_hash()[..]
        )
    );

    // Add a device (Subject) and do some tests
    // Prepare the new entry
    let second_operation = Operation::DeviceAdd {
        subject: subject_pk,
        subject_signature: EMPTYSIGNATURE,
        capabilities: DeviceType::PermanentDevice as u32,
    };
    let mut second_entry = full_journal
        .create_entry(second_operation, &issuer_pk, &issuer_sk)
        .unwrap();

    // Test some properties of the new entry
    assert_eq!(second_entry.journal_id, id);
    assert_eq!(second_entry.index, 1);

    // Test if the new entry can't be added to the journal
    // (the subject's signature is missing at this point)
    assert_eq!(
        full_journal.can_add_entry(&second_entry).unwrap_err(),
        ValidatorError::SubjectSignatureInvalid
    );

    // Have the subject sign the new entry (only needed when adding a device)
    let second_subject_signature = second_entry.sign(&subject_sk);
    second_entry
        .operation
        .set_subject_signature(second_subject_signature);

    // Testing again now that the signature is there
    assert!(full_journal.can_add_entry(&second_entry).is_ok());

    // Adding the new entry to the journal
    assert!(full_journal.add_entry(second_entry.clone()).is_ok());

    // Testing if the journal is still valid after that
    assert!(full_journal.check_journal().is_ok());

    // Testing if the new device is now trusted
    assert!(full_journal.is_device_trusted(&subject_pk));

    // Checking that the journal version has been incremented
    assert_eq!(full_journal.get_journal_version(), 1);

    // The hash should also have changed now
    println!(
        "Journal hash: {}",
        morphingidentity::utils::fmt_hex(
            &full_journal.get_journal_hash()[..]
        )
    );

    // Adding the same entry again shouldn't work
    assert!(full_journal.add_entry(second_entry).is_err());

    // Display all trusted devices in the journal
    for (pk, j) in full_journal.get_trusted_devices() {
        println!(
            "Subject PublicKey: {}, Issuer PublicKey {}, count {}",
            morphingidentity::utils::fmt_hex(&pk[..]),
            morphingidentity::utils::fmt_hex(&j.entry.issuer[..]),
            j.entry.index
        );
    }

    // Remove Subject and do more tests /////////////////////////////////////

    // Preparing a new entry to remove the second device
    let third_operation = Operation::DeviceRemove {
        subject: subject_pk,
    };
    let third_entry = full_journal
        .create_entry(third_operation, &issuer_pk, &issuer_sk)
        .unwrap();

    // Checking count is correct
    assert_eq!(third_entry.index, 2);

    // Checking the new entry can be added to the journal
    assert!(full_journal.can_add_entry(&third_entry).is_ok());

    // Add the third entry to the journal
    assert!(full_journal.add_entry(third_entry.clone()).is_ok());

    // Check if the journal is still valid after that
    assert!(full_journal.check_journal().is_ok());

    // The journal hash should have changed
    println!(
        "Journal hash: {}",
        morphingidentity::utils::fmt_hex(
            &full_journal.get_journal_hash()[..]
        )
    );

    // Adding the third entry again shouldn't work
    assert!(!full_journal.add_entry(third_entry).is_ok());

    // Checking if the second device is not trusted anymore
    assert!(!full_journal.is_device_trusted(&subject_pk));

    // Display the list of trusted devices
    for (pk, j) in full_journal.get_trusted_devices() {
        println!(
            "Subject PublicKey: {}, Issuer PublicKey {}, count {}",
            morphingidentity::utils::fmt_hex(&pk[..]),
            morphingidentity::utils::fmt_hex(&j.entry.issuer[..]),
            j.entry.index
        );
    }
}

/// Build a long journal with random entries and do some fuzzing
#[test]
fn fuzz_testing() {
    sodiumoxide::init();
    println!("Generating {} entries", ITER);

    const DEVICES: usize = 8;
    const ITER: u32 = 1_000;

    let mut sec_keys = Vec::new();
    let mut pub_keys = Vec::new();

    // Create a pool of devices we can add and remove
    for _i in 0..DEVICES {
        let (p_key, s_key) = sign::gen_keypair();
        sec_keys.push(s_key);
        pub_keys.push(p_key);
    }

    let devices = vec![(DeviceType::PermanentDevice as u32, pub_keys[0])];
    let mut random_journal =
        FullJournal::new(GoodRand::rand(), &pub_keys[0], &sec_keys[0], devices)
            .unwrap();

    for _i in 0..ITER - 1 {
        let trusted = random_journal.get_trusted_devices().clone();
        let mut issuer;
        let mut counter;
        let mut iss_pk = &sign::PublicKey([0; sign::PUBLICKEYBYTES]);
        let mut iss_sk;

        // This generates an (almost) random entry and tries to add it to the journal.
        loop {
            // Pick a trusted issuer.
            let mut c = randomnumber(trusted.len() as u64) as usize;
            counter = 0;
            for e in trusted.values() {
                if counter == c {
                    issuer = e;
                    iss_pk = &issuer.key;
                    break;
                }
                counter += 1;
            }

            // find index into pub_keys, sec_keys.
            let found_index = pub_keys
                .iter()
                .enumerate()
                .find(|&p| p.1[..] == iss_pk[..])
                .unwrap();

            // Construct a random operation
            iss_sk = &sec_keys[found_index.0];

            // Pick a random operation
            let next_operation_index =
                randomnumber(OPERATIONS as u64) as u32;

            match next_operation_index {
                TAG_DEVICE_BULK_ADD => {
                    continue;
                }
                TAG_DEVICE_ADD => {
                    // Adding a new device from the pool
                    let mut inner_counter = 0;
                    loop {
                        let subject_index =
                            randomnumber(DEVICES as u64) as usize;
                        let subject_secret_key = &sec_keys[subject_index];
                        let subject_public_key = &pub_keys[subject_index];

                        let next_operation = Operation::DeviceAdd {
                            subject: *subject_public_key,
                            subject_signature: EMPTYSIGNATURE,
                            capabilities: DeviceType::PermanentDevice
                                as u32,
                        };

                        match random_journal.create_entry(
                            next_operation.clone(),
                            iss_pk,
                            iss_sk,
                        ) {
                            Err(_) => {
                                // We picked the wrong subject or operation
                                inner_counter += 1;
                                if inner_counter > 100 {
                                    break;
                                } else {
                                    continue;
                                }
                            }
                            Ok(mut new_entry) => {
                                let subject_signature =
                                    new_entry.sign(subject_secret_key);
                                new_entry.operation.set_subject_signature(
                                    subject_signature,
                                );
                                assert!(
                                    random_journal
                                        .can_add_entry(&new_entry)
                                        .is_ok()
                                );
                                assert!(
                                    random_journal
                                        .add_entry(new_entry)
                                        .is_ok()
                                );
                                counter += 1;
                                break;
                            }
                        };
                    }
                }
                TAG_DEVICE_REMOVE => {
                    let mut inner_counter = 0;
                    loop {
                        // Removing a trusted device
                        let subject_index =
                            randomnumber(DEVICES as u64) as usize;
                        let subject_public_key = &pub_keys[subject_index];

                        let next_operation = Operation::DeviceRemove {
                            subject: *subject_public_key,
                        };

                        match random_journal.create_entry(
                            next_operation.clone(),
                            iss_pk,
                            iss_sk,
                        ) {
                            Err(_) => {
                                // We picked the wrong subject or operation
                                inner_counter += 1;
                                if inner_counter > 100 {
                                    break;
                                } else {
                                    continue;
                                }
                            }
                            Ok(new_entry) => {
                                assert!(
                                    random_journal
                                        .can_add_entry(&new_entry)
                                        .is_ok()
                                );
                                assert!(
                                    random_journal
                                        .add_entry(new_entry)
                                        .is_ok()
                                );
                                counter += 1;
                                break;
                            }
                        };
                    }
                }
                TAG_DEVICE_REPLACE => {
                    let mut inner_counter = 0;
                    loop {
                        // Replacing an existing trusted device
                        let added_subject_index =
                            randomnumber(DEVICES as u64) as usize;
                        let added_subject_secret_key =
                            &sec_keys[added_subject_index];
                        let added_subject_public_key =
                            &pub_keys[added_subject_index];
                        let removed_subject_index =
                            randomnumber(DEVICES as u64) as usize;
                        let removed_subject_public_key =
                            &pub_keys[removed_subject_index];

                        let next_operation = Operation::DeviceReplace {
                            added_subject: *added_subject_public_key,
                            removed_subject: *removed_subject_public_key,
                            added_subject_signature: EMPTYSIGNATURE,
                            capabilities: DeviceType::PermanentDevice
                                as u32,
                        };

                        match random_journal.create_entry(
                            next_operation.clone(),
                            iss_pk,
                            iss_sk,
                        ) {
                            Err(_) => {
                                // We picked the wrong subject or operation
                                inner_counter += 1;
                                if inner_counter > 100 {
                                    break;
                                } else {
                                    continue;
                                }
                            }
                            Ok(mut new_entry) => {
                                let added_subject_signature = new_entry
                                    .sign(added_subject_secret_key);
                                new_entry.operation.set_subject_signature(
                                    added_subject_signature,
                                );
                                assert!(
                                    random_journal
                                        .can_add_entry(&new_entry)
                                        .is_ok()
                                );
                                assert!(
                                    random_journal
                                        .add_entry(new_entry)
                                        .is_ok()
                                );
                                counter += 1;
                                break;
                            }
                        };
                    }
                }
                TAG_DEVICE_SELF_REPLACE => {
                    let mut inner_counter = 0;
                    loop {
                        // Self-replacing an existing trusted device
                        let added_subject_index =
                            randomnumber(DEVICES as u64) as usize;
                        let added_subject_secret_key =
                            &sec_keys[added_subject_index];
                        let added_subject_public_key =
                            &pub_keys[added_subject_index];

                        let next_operation = Operation::DeviceSelfReplace {
                            added_subject: *added_subject_public_key,
                            added_subject_signature: EMPTYSIGNATURE,
                        };

                        match random_journal.create_entry(
                            next_operation.clone(),
                            iss_pk,
                            iss_sk,
                        ) {
                            Err(_) => {
                                // We picked the wrong subject or operation
                                inner_counter += 1;
                                if inner_counter > 100 {
                                    break;
                                } else {
                                    continue;
                                }
                            }
                            Ok(mut new_entry) => {
                                let added_subject_signature = new_entry
                                    .sign(added_subject_secret_key);
                                new_entry.operation.set_subject_signature(
                                    added_subject_signature,
                                );
                                assert!(
                                    random_journal
                                        .can_add_entry(&new_entry)
                                        .is_ok()
                                );
                                assert!(
                                    random_journal
                                        .add_entry(new_entry)
                                        .is_ok()
                                );
                                counter += 1;
                                break;
                            }
                        };
                    }
                }
                _ => unreachable!(),
            };
            if counter > 0 {
                break;
            }
        }
    }

    println!(
        "Permanent hash: {}",
        morphingidentity::utils::fmt_hex(
            &random_journal.get_permanent_hash()[..]
        )
    );
    for (pk, j) in &random_journal.get_trusted_devices() {
        println!("Trusted devices: Subject PublicKey: {}, Issuer PublicKey {}, count {}",
                 morphingidentity::utils::fmt_hex(&pk[..]),
                 morphingidentity::utils::fmt_hex(&j.entry.issuer[..]),
                 j.entry.index);
        let mut pe = j.entry.clone();
        print!("Parent(s): ");
        while let Some(x) = random_journal.get_parent(&pe) {
            pe = (*x).clone();
            if pe.index == 0 {
                println!("root.");
                break;
            } else {
                print!("{}, ", pe.index);
            }
        }
    }
    assert!(random_journal.check_journal().is_ok());
}
