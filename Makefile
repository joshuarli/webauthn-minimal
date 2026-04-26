.PHONY: types

types:
	mkdir -p ts
	TS_OUTPUT_PATH=ts/index.ts cargo run --example gen-types --features ts

demo:
	esbuild examples/demo/ts/auth.ts --bundle --outfile=examples/demo/static/auth.js
	cargo run --example demo --features ts
