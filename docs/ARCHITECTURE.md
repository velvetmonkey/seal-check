# Architecture

`seal-check` is a static browser verifier.

## Components

- `wasm/seal.{js,wasm}`: pinned kernel artifact.
- `receipt-format.js`: receipt shape, canonical request hash, and JavaScript target-commitment mirror.
- `seal-config.js`: standard policy and call shaping.
- `kernel.js`: wasm loading, self-hash, kernel execution, and receipt construction.
- `app.js`, `index.html`, `style.css`: browser UI.
- `test/`: Node checks for receipt vectors and cross-tool compatibility.

## Data flow

1. The browser verifies the wasm hash against the pinned SHA-256.
2. A call or receipt is normalized into the standard kernel input.
3. The wasm kernel emits the decision bytes.
4. The page re-derives receipt fields and compares expected bytes.
5. Target commitments are lowercase SHA-256 hex over Lean-compatible netstrings.

## Trust boundaries

The page proves nothing about the user's deployment. It checks a local artifact and receipt against the bundled kernel.
