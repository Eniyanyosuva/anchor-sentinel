# Anchor Sentinel Playground

A static, single-page web playground for [Anchor Sentinel](../). Paste
an IDL and an Anchor `lib.rs`, hit **Scan**, and see the rule engine's
findings inline.

The page is pure HTML + a thin JS shim that imports the WASM module
built from `src/wasm.rs`. No backend, no build step on the user side.

## Local development

The WASM build emits `./pkg/anchor_sentinel.js` plus a `.wasm` file. To
build and serve locally:

```sh
# 1. Build the WASM module. Output goes to playground/pkg/.
wasm-pack build --target web --out-dir playground/pkg

# 2. Serve playground/ on a local port. Python's stdlib is enough.
cd playground
python3 -m http.server 8080

# 3. Open http://localhost:8080/ in a browser.
```

Use any static file server you like — the only requirement is that the
server can serve `.wasm` with the correct MIME type
(`application/wasm`). Most do, but if you hit issues, the
[wasm-bindgen docs](https://rustwasm.github.io/docs/wasm-bindgen/web.html)
list a few recipes.

## How it works

- `playground/index.html` ships two CodeMirror panes (JSON for the IDL,
  Rust for the source), a Scan button, a Share button, and a findings
  panel.
- The Scan button calls `mod.scan(idl, rust)`, the `#[wasm_bindgen]`
  entrypoint in `src/wasm.rs`. That function:
  1. Parses the IDL through the same `idl::from_value` path the CLI uses.
  2. Runs the AST visitors (`AccountsStructVisitor`,
     `InstructionFnVisitor`) on the Rust source string.
  3. Runs every registered rule over the resulting `AnalysisContext`.
  4. Returns the findings as a plain JS array of objects.
- The findings panel renders each finding with a severity badge, the
  rule id, the message, the source location, and any hint.

## Sharing

The Share button base64-encodes both panes into the URL hash. Pasting
the URL into another browser restores the state on load. Use this for
discussions, bug reports, or reproducible demos.

## CodeMirror version

This playground uses **CodeMirror 5** (loaded from a CDN) rather than
CodeMirror 6. CM6 requires an ES-module-aware build step, which would
contradict the "single file, no build step" goal of the playground.
CM5 gives us line numbers, syntax highlighting, bracket matching, and
the dark theme without any tooling.

If you want to upgrade, see the [CodeMirror 6 migration guide](https://codemirror.net/docs/migration/).

## Production deploy

The CI workflow `.github/workflows/pages.yml` builds the WASM module
and deploys `playground/` to the `gh-pages` branch. The deployed
playground is served at <https://eniyanyosuva.github.io/anchor-sentinel/>.
