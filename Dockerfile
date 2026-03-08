# Privileged test harness for secure-sudoers
# Build:  docker build -t secure-sudoers-cov .
# Run:    docker run --rm --privileged secure-sudoers-cov
FROM rust:latest

RUN apt-get update  \
    && apt-get install -y --no-install-recommends e2fsprogs libc6-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add llvm-tools-preview \
    && cargo install cargo-llvm-cov --locked

WORKDIR /workspace
COPY . .

RUN chmod +x /workspace/run_privileged_tests.sh

CMD ["/workspace/run_privileged_tests.sh"]
