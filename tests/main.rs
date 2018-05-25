extern crate cbor;
extern crate morphingidentity;
extern crate sodiumoxide;
extern crate uuid;

use morphingidentity::entries::{
    DeviceType, JournalEntry, Operation, OPERATIONS,
};
use morphingidentity::journal::FullJournal;
use morphingidentity::rand_utils::{randomnumber, GoodRand};
use morphingidentity::utils::EMPTYSIGNATURE;
use sodiumoxide::crypto::hash;
use sodiumoxide::crypto::sign;
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
        Uuid::nil(),
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
    let mut full_journal =
        FullJournal::new(id, &issuer_pk, &issuer_sk).unwrap();

    // Check if the journal is valid
    assert!(full_journal.check_journal());

    // Test if a random entry can be added to the journal
    // assert!(!full_journal.test_entry(&invalid_entry));

    // Get the journal version (number of entries in the journal)
    assert_eq!(full_journal.get_journal_version(), 0);

    // Get the history hash of the journal
    println!(
        "Journal history hash: {}",
        morphingidentity::utils::fmt_hex(
            &full_journal.get_journal_hash()[..]
        )
    );

    // Add a device (Subject) and do some tests /////////////////////////////

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
    assert!(!full_journal.can_add_entry(&second_entry));

    // Have the subject sign the new entry (only needed when adding a device)
    let second_subject_signature = second_entry.sign(&subject_sk);
    second_entry
        .operation
        .set_subject_signature(second_subject_signature);

    // Testing again now that the signature is there
    assert!(full_journal.can_add_entry(&second_entry));

    // Adding the new entry to the journal
    assert!(full_journal.add_entry(second_entry.clone()));

    // Testing if the journal is still valid after that
    assert!(full_journal.check_journal());

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
    assert!(!full_journal.add_entry(second_entry));

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
    assert!(full_journal.can_add_entry(&third_entry));

    // Add the third entry to the journal
    assert!(full_journal.add_entry(third_entry.clone()));

    // Check if the journal is still valid after that
    assert!(full_journal.check_journal());

    // The journal hash should have changed
    println!(
        "Journal hash: {}",
        morphingidentity::utils::fmt_hex(
            &full_journal.get_journal_hash()[..]
        )
    );

    // Adding the third entry again shouldn't work
    assert!(!full_journal.add_entry(third_entry));

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
    println!("-------- Random journal ---------");
    println!("Generating {} entries", ITER);

    const DEVICES: usize = 8;
    const ITER: u32 = 10;

    let mut sec_keys = Vec::new();
    let mut pub_keys = Vec::new();

    // Create a pool of devices we can add and remove
    for _i in 0..DEVICES {
        let (p_key, s_key) = sign::gen_keypair();
        sec_keys.push(s_key);
        pub_keys.push(p_key);
    }

    let mut random_journal =
        FullJournal::new(GoodRand::rand(), &pub_keys[0], &sec_keys[0])
            .unwrap();

    for _i in 0..ITER - 1 {
        let trusted = random_journal.get_trusted_devices().clone();
        let mut issuer;
        let mut counter;
        let mut iss_pk = &sign::PublicKey([0; sign::PUBLICKEYBYTES]);
        let mut iss_sk;

        // Let's generate an entry that makes sense: either it's an entry
        // that adds a device which isn't in journal yet (assuming that the
        // journal isn't full), or it's an entry that removes a device which
        // is in the journal already (assuming that the journal won't become
        // empty).  Thirdly, if there are at least two devices, one of them
        // can replace another with a new one.
        loop {
            // pick a trusted issuer.
            let mut c = randomnumber(trusted.len() as u64) as usize;
            //<usize as GoodRand>::rand() % (trusted.len() as usize);
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

            // construct a random, sound operation.
            iss_sk = &sec_keys[found_index.0];

            // Pick a random operation
            let next_operation_index = randomnumber(OPERATIONS as u64);

            match next_operation_index {
                0 => {
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
                                );
                                assert!(
                                    random_journal.add_entry(new_entry)
                                );
                                counter += 1;
                                println!("Adding a new device");
                                break;
                            }
                        };
                    }
                }
                1 => {
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
                            Ok(mut new_entry) => {
                                assert!(
                                    random_journal
                                        .can_add_entry(&new_entry)
                                );
                                assert!(
                                    random_journal.add_entry(new_entry)
                                );
                                counter += 1;
                                println!("Removing a device");
                                break;
                            }
                        };
                    }
                }
                2 => {
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
                                );
                                assert!(
                                    random_journal.add_entry(new_entry)
                                );
                                counter += 1;
                                println!("Replacing a device");
                                break;
                            }
                        };
                    }
                }
                3 => {
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
                                );
                                assert!(
                                    random_journal.add_entry(new_entry)
                                );
                                counter += 1;
                                println!("Self-replacing a device");
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
            /*
            if (randomnumber(OPERATIONS as u64)) == 0 &&
                trusted.contains_key(sub_pk) && trusted.len() > 1 &&  // TODO: should be `trusted.len() >= 1`!
                trusted.len() < MAX_DEVICES
            {
                loop {
                    let c2 = randomnumber(DEVICES as u64) as usize;
                    if c2 != c {
                        continue; // device cannot replace itself.  TODO: should be allowed!
                    }
                    for e in trusted.values() {
                        if pub_keys[c2][..] == e.key[..] {
                            continue; // has been added before.
                        }
                    }
                    sub_added_pk = &pub_keys[c2];
                    break;
                }

                operation = Operation::DeviceReplace {
                    removed_subject: *sub_pk,
                    capabilities: DeviceType::PermanentDevice as u32,
                    added_subject: *sub_added_pk,
                    added_subject_signature: EMPTYSIGNATURE,
                };
                break; // found it!
            }
            if trusted.contains_key(sub_pk) && trusted.len() > 1 {
                operation = Operation::DeviceRemove { subject: *sub_pk };
                break; // found it!
            }
            if !trusted.contains_key(sub_pk) && trusted.len() < MAX_DEVICES
            {
                operation = Operation::DeviceAdd {
                    subject: *sub_pk,
                    subject_signature: EMPTYSIGNATURE,
                    capabilities: DeviceType::PermanentDevice as u32,
                };
                break; // found it!
            }
            // otherwise we restart the search
        }

        match rl.create_entry(operation.clone(), iss_pk, iss_sk) {
            Err(e) => {
                panic!("Couldn't create new entry: {}", e);
            }
            Ok(mut new_entry) => {
                let subject_signature = new_entry.sign(sub_sk);
                new_entry
                    .operation
                    .set_subject_signature(subject_signature);
                assert!(rl.can_add_entry(&new_entry));
                assert!(rl.add_entry(new_entry));
            }
            */
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
        // loop {
        // match rl.get_parent(pe) {
        // Some(x) => {
        // pe = x;
        // if pe.count == 0 {
        // println!("root.");
        // break;
        // } else {
        // print!("{}, ", pe.count);
        // }
        // }
        // None => break,
        // }
        // }
        //
    }
    assert!(random_journal.check_journal());
}
