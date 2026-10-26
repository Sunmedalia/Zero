.PHONY: build install run tui test ui-install ui-build ui-test check acceptance windows-acceptance tui-acceptance screenshots clean

build:
	cargo build --release --locked

install:
	cargo install --path . --locked

# The interface is TypeScript; `run` builds it first so `zero` finds dist/.
ui-install:
	cd ts && npm install --no-audit --no-fund

ui-build:
	cd ts && npm run build

ui-test:
	cd ts && npm test

run tui: ui-build
	cargo run --release --bin zero -- $(ARGS)

test:
	cargo test --locked

check: ui-build
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings
	cargo test --locked
	cd ts && npm run typecheck
	cd ts && npm test
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
# Drives `zero tui-backend` exactly as the TypeScript UI does.
tui-acceptance: ui-build
	cargo test --locked --release --test tui_backend -- --ignored --nocapture

# README screenshots from the real engine and renderer; local sample, offline.
IMAGE ?= images/linux-sample-1.bin.gz
SYMBOLS ?= symbols/linux.zip
screenshots: build ui-build
	node scripts/screenshots.mjs $(IMAGE) $(SYMBOLS) docs/assets
