.PHONY: demo test

test:
	cargo test

demo:
	cargo run --example demo

setup:
	prek install --prepare-hooks -f

pc:
	prek run --all-files
