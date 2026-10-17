# Vendored third-party assets

This directory ships a pinned snapshot of Mermaid so the guide viewer can
render diagrams entirely offline (our Content-Security-Policy disallows
third-party `script-src`).

## mermaid

- Upstream: <https://github.com/mermaid-js/mermaid>
- Version: **11.17.2**
- Fetched from: `https://registry.npmjs.org/mermaid/-/mermaid-11.17.2.tgz`
- License: [MIT](https://github.com/mermaid-js/mermaid/blob/v11.17.2/LICENSE)
- Files:
  - `mermaid.min.js` (the self-contained UMD build)

The UMD build is used rather than the ESM entry point because the latter
resolves its parser, DOMPurify and es-toolkit dependencies at runtime
through bare specifiers, which needs a bundler step this build does not
have. `mermaid.min.js` carries every dependency inline and loads from a
single same-origin URL.

Mermaid runs under the shipped CSP (`script-src 'self'`, no
`unsafe-eval`) with `securityLevel: "strict"`; the guide viewer loads it
on demand, only when an opened document contains a `mermaid` fence.

## Update procedure

```bash
VER_MERMAID=11.17.2
DIR=$(git rev-parse --show-toplevel)/gui_frontend/src/vendor/mermaid
TMP=$(mktemp -d)
curl -fsSL -o "$TMP/mermaid.tgz" \
  "https://registry.npmjs.org/mermaid/-/mermaid-${VER_MERMAID}.tgz"
tar -xzf "$TMP/mermaid.tgz" -C "$TMP" package/dist/mermaid.min.js
cp "$TMP/package/dist/mermaid.min.js" "$DIR/mermaid.min.js"
rm -rf "$TMP"
```

After updating, adjust the version number in this file and the digest in
`tests/test_gui_vendor_integrity.py`, re-run
`./scripts/build_gui_frontend.sh`, and open Environment -> About ->
Architecture to smoke-test the diagrams. Copy the file as fetched: the
digest test fails on any edit, typography included.
