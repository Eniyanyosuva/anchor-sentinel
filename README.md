# Anchor Sentinel Playground

A static, single-page web playground for [Anchor Sentinel](../). Paste
an IDL and an Anchor `lib.rs`, hit **Scan**, and see the rule engine's
findings inline.

The page is pure HTML + a thin JS shim that imports the WASM module
built from `src/wasm.rs`. No backend, no build step on the user side.

## Local development

The prebuilt WASM is checked into `playground/pkg/`, so you can serve
the page directly:

```sh
# Serve playground/ on a local port. Python's stdlib is enough.
cd playground
python3 -m http.server 8080

# Open http://localhost:8080/ in a browser.
```

Use any static file server you like — the only requirement is that the
server can serve `.wasm` with the correct MIME type
(`application/wasm`). Most do, but if you hit issues, the
[wasm-bindgen docs](https://rustwasm.github.io/docs/wasm-bindgen/web.html)
list a few recipes.

## Rebuilding the WASM

The WASM in `playground/pkg/` is **checked into the repo** rather than
built in CI. This keeps the Pages deploy trivial (a single `rsync`)
and avoids a class of build-cache issues we hit with the in-CI flow.

When you add or change a rule, rebuild the WASM and commit the new
`pkg/`:

```sh
# 1. Install wasm-pack once. (Rust toolchain required.)
cargo install wasm-pack --locked

# 2. Build the WASM module. The first run will install
#    `wasm-bindgen-cli` and take a few minutes; subsequent runs
#    are fast.
wasm-pack build --target web --out-dir playground/pkg

# 3. Delete the wasm-pack-generated .gitignore (it would otherwise
#    hide the built files from `git add`).
rm playground/pkg/.gitignore

# 4. Commit and push the regenerated pkg/.
git add -f playground/pkg
git commit -m "chore: rebuild WASM playground pkg"
git push
```

The CI Pages workflow will pick up the new `pkg/` on the next push to
`main` and deploy it.

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

The CI workflow `.github/workflows/pages.yml` deploys `playground/`
to the `gh-pages` branch. The deployed playground is served at
<https://eniyanyosuva.github.io/anchor-sentinel/>.

The workflow has no Rust toolchain or `wasm-pack` step — it just
checks out the source (which already contains the prebuilt
`playground/pkg/`) and rsyncs `playground/` into a fresh clone of
`gh-pages`. See "Rebuilding the WASM" above for how to refresh the
pkg/ after a rule change.
