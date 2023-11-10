modify:
	wasm-snip target/wasm32-unknown-unknown/release/passkey_demo_backend.wasm -o output.wasm __wbindgen_placeholder__ __wbindgen_describe
generate: modify
	candid-extractor output.wasm > backend.did