
default: compile

.PHONY: compile
compile:
	cargo build

.PHONY: fmt
fmt: 
	rustup component add rustfmt-preview --toolchain nightly
	cargo +nightly fmt
