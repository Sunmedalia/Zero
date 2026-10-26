.PHONY: build install run tui test ui-install ui-build ui-test check acceptance windows-acceptance tui-acceptance screenshots clean

build:
	cargo build --release --locked

install:
	cargo install --path . --locked

# Compatibility aliases for the native interface.
ui-install:
	cargo fetch --locked

ui-build:
	cargo build --locked --bin zero

ui-test:
	cargo test --locked --lib tui::

run tui:
	cargo run --release --bin zero -- $(ARGS)

test:
	cargo test --locked

check:
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings
	cargo test --locked
	cargo build --locked --release
	python3 scripts/windows_compatibility.py --check

# Local Debian and Kali samples; no network during acceptance.
# Override with ZERO_TEST_IMAGE / ZERO_TEST_SYMBOLS / ZERO_KALI_IMAGE / ZERO_KALI_SYMBOLS.
acceptance:
	cargo test --locked --release --test acceptance -- --ignored

clean:
	cargo clean

# Public Server 2003, Windows 7/10/11 RAW and crash/minidump samples; exact local ISFs.
windows-acceptance:
	cargo test --locked --release --test windows_acceptance -- --ignored

# Offline resource selection -> analysis through the real engine and interface.
# Covers the native UI service.
tui-acceptance:
	cargo test --locked --release --lib tui::native_acceptance -- --ignored --nocapture

# README screenshots from the real engine and renderer; local sample, offline.
IMAGE ?= images/linux-sample-1.bin
SYMBOLS ?= symbols/linux.zip
screenshots:
	cargo run --locked --release --example screenshots -- $(IMAGE) $(SYMBOLS) docs/assets
