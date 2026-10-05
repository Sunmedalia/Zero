.PHONY: build install run tui test check acceptance clean

build:
	cargo build --release --locked

install:
	cargo install --path . --locked

run tui:
	cargo run --release -- $(ARGS)

test:
	cargo test --locked

check:
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings
	cargo test --locked
	cargo build --locked --release

# Local Debian and Kali samples; no network during acceptance.
# Override with ZERO_TEST_IMAGE / ZERO_TEST_SYMBOLS / ZERO_KALI_IMAGE / ZERO_KALI_SYMBOLS.
acceptance:
	cargo test --locked --release --test acceptance -- --ignored

clean:
	cargo clean
