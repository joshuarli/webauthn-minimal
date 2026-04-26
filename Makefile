.PHONY: demo test build-demo gen-types

test:
	cargo test

gen-types:
	cargo run --example gen-types

build-demo: gen-types
	esbuild examples/demo/ts/auth.ts --bundle --outfile=examples/demo/static/auth.js

demo: build-demo
	cargo run --example demo
