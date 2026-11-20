# Vendored third-party assets

This directory ships a pinned subset of the IBM Plex Mono typeface, the data
face of the Bench skin (`css/skins/bench.css`): APDUs, TLV, identifiers,
the status line. It is vendored because the GUI's Content-Security-Policy
allows fonts from `'self'` only and the GUI has to render the same offline.

## IBM Plex Mono

- Upstream: <https://github.com/IBM/plex>
- Package: `@ibm/plex-mono`, version **2.5.0**
- Fetched from: `https://registry.npmjs.org/@ibm/plex-mono/-/plex-mono-2.5.0.tgz`
- License: SIL Open Font License 1.1 (`license.txt`, copied from the package)
- Files (the package's Latin-1 split subset, `fonts/split/woff2/`):
  - `IBMPlexMono-Regular-Latin1.woff2`
  - `IBMPlexMono-SemiBold-Latin1.woff2`
  - `license.txt`

Glyphs outside the subset fall back to the next family in the skin's
`--font-mono` stack.

## Update procedure

```bash
VER=2.5.0
DIR=$(git rev-parse --show-toplevel)/gui_frontend/src/vendor/plex-mono
TMP=$(mktemp -d)
curl -fsSL -o "$TMP/plex.tgz" "https://registry.npmjs.org/@ibm/plex-mono/-/plex-mono-${VER}.tgz"
tar -xzf "$TMP/plex.tgz" -C "$TMP"
for w in Regular SemiBold; do
  cp "$TMP/package/fonts/split/woff2/IBMPlexMono-${w}-Latin1.woff2" "$DIR/"
done
cp "$TMP/package/fonts/split/woff2/license.txt" "$DIR/license.txt"
```

Check the tarball against the `dist.integrity` value the registry publishes
for that version before copying. After updating, adjust the version in this
file and the digests in `tests/test_gui_vendor_integrity.py`, then re-run
`./scripts/build_gui_frontend.sh`. Copy the files as fetched: the digest test
fails on any edit.
