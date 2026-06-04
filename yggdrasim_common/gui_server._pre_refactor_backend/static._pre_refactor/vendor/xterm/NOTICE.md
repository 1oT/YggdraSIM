# Vendored third-party assets

This directory ships a pinned snapshot of xterm.js so the GUI can run
entirely offline (our Content-Security-Policy disallows third-party
`script-src`).

## xterm.js

- Upstream: <https://github.com/xtermjs/xterm.js>
- Version: **5.3.0**
- Fetched from: `https://cdn.jsdelivr.net/npm/xterm@5.3.0/`
- License: [MIT](https://github.com/xtermjs/xterm.js/blob/5.3.0/LICENSE)
- Files:
  - `xterm.js`
  - `xterm.css`

## xterm-addon-fit

- Upstream: <https://github.com/xtermjs/xterm.js/tree/main/addons/xterm-addon-fit>
- Version: **0.8.0**
- Fetched from: `https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/`
- License: [MIT](https://github.com/xtermjs/xterm.js/blob/5.3.0/LICENSE)
- Files:
  - `addon-fit.js`

## Update procedure

```bash
VER_XTERM=5.3.0
VER_FIT=0.8.0
DIR=$(git rev-parse --show-toplevel)/yggdrasim_common/gui_server/static/vendor/xterm
curl -fsSL -o "$DIR/xterm.js"     "https://cdn.jsdelivr.net/npm/xterm@${VER_XTERM}/lib/xterm.js"
curl -fsSL -o "$DIR/xterm.css"    "https://cdn.jsdelivr.net/npm/xterm@${VER_XTERM}/css/xterm.css"
curl -fsSL -o "$DIR/addon-fit.js" "https://cdn.jsdelivr.net/npm/xterm-addon-fit@${VER_FIT}/lib/xterm-addon-fit.js"
```

After updating, adjust the version numbers in this file and re-run
`python3 main/main.py --gui` to smoke-test the terminal panel.
