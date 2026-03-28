FROM rust:latest

RUN apt-get update \
    && apt-get install -y --no-install-recommends bats e2fsprogs libc6-dev sudo \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add llvm-tools-preview \
    && cargo install cargo-llvm-cov --locked

WORKDIR /workspace

COPY Cargo.toml Cargo.lock ./
COPY crates/secure-sudoers-common/Cargo.toml crates/secure-sudoers-common/Cargo.toml
COPY crates/secure-sudoers/Cargo.toml crates/secure-sudoers/Cargo.toml
COPY crates/secure-sudoers-utils/Cargo.toml crates/secure-sudoers-utils/Cargo.toml
RUN mkdir -p crates/secure-sudoers-common/src crates/secure-sudoers/src crates/secure-sudoers-utils/src \
    && printf 'pub fn _ci_stub() {}\n' > crates/secure-sudoers-common/src/lib.rs \
    && printf 'fn main() {}\n' > crates/secure-sudoers/src/main.rs \
    && printf 'fn main() {}\n' > crates/secure-sudoers-utils/src/main.rs \
    && cargo fetch --locked

COPY . .

RUN chmod +x /workspace/tests/run_privileged_tests.sh

CMD ["/workspace/tests/run_privileged_tests.sh"]
