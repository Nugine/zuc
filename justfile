dev:
    just fmt
    just lint
    just test

fmt *ARGS:
    cargo fmt --all {{ARGS}}

lint *ARGS:
    cargo clippy --all-features --tests --benches {{ARGS}}

test *ARGS:
    cargo test --all-features {{ARGS}}

doc *ARGS:
    RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --open --no-deps --all-features {{ARGS}}

ci:
    just fmt --check
    just lint -- -D warnings
    just test

coverage:
    cargo llvm-cov --all-features --lcov --output-path lcov.info
