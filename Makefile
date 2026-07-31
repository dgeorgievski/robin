.PHONY: setup test lint run wasm-check interop

setup:
	rustc --version
	cargo --version
	cargo fetch --locked

test:
	cargo test --locked --all-targets

lint:
	cargo fmt --all -- --check
	cargo clippy --locked --all-targets --all-features -- -D warnings

run:
	cargo run --locked --example resolve_fixture

wasm-check:
	PATH=$$HOME/.cargo/bin:$$PATH rustup run stable cargo check --locked --target wasm32-unknown-unknown --features wasm --no-default-features

interop:
	bash scripts/interop.sh
