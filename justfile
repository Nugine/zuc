dev:
    just fmt
    just lint
    just test

fmt *ARGS:
    cargo fmt --all {{ARGS}}

lint *ARGS:
    cargo clippy --all-features --tests {{ARGS}}

test:
    cargo test --all-features

doc:
    RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --open --no-deps --all-features

ci:
    just fmt --check
    just lint -- -D warnings
    just test
