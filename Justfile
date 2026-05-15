set shell        := ["bash", "-cu"]
set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]
set dotenv-load  := true

default:
    @just --list

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
    cargo nextest run --workspace --all-features

doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

cov:
    cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info

deny:
    cargo deny check

machete:
    cargo machete --skip-target-dir

audit-supply-chain: deny machete

bench:
    cargo bench --workspace

watch:
    bacon

# full CI pipeline locally
ci: fmt-check lint test doc deny machete

# install Phase-1 tooling (everything the init hooks/CI rely on)
bootstrap:
    cargo install --locked prek
    cargo install --locked cargo-nextest
    cargo install --locked typos-cli
    cargo install --locked cocogitto
    cargo install --locked taplo-cli
    prek install

# install Phase-2 release tooling (run only after first impl PR; not needed at init)
bootstrap-phase2:
    cargo install --locked git-cliff
    cargo install --locked release-plz
    cargo install --locked cargo-dist
