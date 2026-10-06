.PHONY: build install run tui test check acceptance windows-acceptance tui-acceptance clean

build:
	cargo build --release --locked

install:
	cargo install --path . --locked

run tui:
	cargo run --release --bin zero -- $(ARGS)

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

# Public Server 2003, Windows 7/10/11 RAW and crash/minidump samples; exact local ISFs.
windows-acceptance:
	cargo test --locked --release --test windows_acceptance -- --ignored

# Offline resource selection -> plugin activation through the TUI state machine.
tui-acceptance:
	cargo test --locked --release --lib offline_tui_resources_to_analysis_acceptance -- --ignored --nocapture
