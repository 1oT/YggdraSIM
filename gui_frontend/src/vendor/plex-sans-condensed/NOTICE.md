# Vendored third-party assets

This directory ships a pinned subset of the IBM Plex Sans Condensed typeface,
the interface face of the Bench skin (`css/skins/bench.css`). It is vendored
because the GUI's Content-Security-Policy allows fonts from `'self'` only and
the GUI has to render the same offline.

## IBM Plex Sans Condensed

- Upstream: <https://github.com/IBM/plex>
- Package: `@ibm/plex-sans-condensed`, version **2.0.0**
- Fetched from: `https://registry.npmjs.org/@ibm/plex-sans-condensed/-/plex-sans-condensed-2.0.0.tgz`
- License: SIL Open Font License 1.1 (`license.txt`, copied from the package)
- Files (the package's Latin-1 split subset, `fonts/split/woff2/`):
  - `IBMPlexSansCondensed-Regular-Latin1.woff2`
  - `IBMPlexSansCondensed-Medium-Latin1.woff2`
  - `IBMPlexSansCondensed-SemiBold-Latin1.woff2`
  - `license.txt`

Glyphs outside the subset (arrows, box drawing, other scripts) fall back to
the next family in the skin's `--font-sans` stack.

## Update procedure

```bash
VER=2.0.0
DIR=$(git rev-parse --show-toplevel)/gui_frontend/src/vendor/plex-sans-condensed
TMP=$(mktemp -d)
curl -fsSL -o "$TMP/plex.tgz" "https://registry.npmjs.org/@ibm/plex-sans-condensed/-/plex-sans-condensed-${VER}.tgz"
tar -xzf "$TMP/plex.tgz" -C "$TMP"
for w in Regular Medium SemiBold; do
  cp "$TMP/package/fonts/split/woff2/IBMPlexSansCondensed-${w}-Latin1.woff2" "$DIR/"
done
cp "$TMP/package/fonts/split/woff2/license.txt" "$DIR/license.txt"
```

Check the tarball against the `dist.integrity` value the registry publishes
for that version before copying. After updating, adjust the version in this
file and the digests in `tests/test_gui_vendor_integrity.py`, then re-run
`./scripts/build_gui_frontend.sh`. Copy the files as fetched: the digest test
fails on any edit.
