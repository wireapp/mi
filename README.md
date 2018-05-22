# mi: Morphing Identity
[![Build Status](https://travis-ci.com/wireapp/mi.svg?token=yQKzqnxU1mGjzkqxzVxi&branch=master)](https://travis-ci.com/wireapp/mi)

## Building

You need `libsodium` to be installed. After that, just do

    $ cargo build

## Running tests

To run all tests:

    $ cargo test

To run just some specific test:

    $ cargo test <test name>

To get output from integration tests:

    $ cargo test -- --nocapture
