SHELL := /bin/bash

.PHONY: build test fmt lint run

build:
	cargo build --workspace

test:
	cargo test --workspace --all-features -- --nocapture

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace --all-targets -- -D warnings

run:
	cargo run -p toolbox --features scan -- scan 127.0.0.1

.PHONY: bench-up bench bench-down
bench-up:
	docker compose -f ops/bench/docker-compose.yml up -d

bench:
	cargo run -p toolbox -- bench --compose-up --out target/bench --qps 800 --store

bench-down:
	docker compose -f ops/bench/docker-compose.yml down -v

.PHONY: dev
dev:
	cargo watch -x "clippy -- -D warnings" -x "test --all-features" -x "run -p toolbox --features scan -- scan 127.0.0.1 --top 50"
