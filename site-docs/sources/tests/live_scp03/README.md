# SCP03 live command test bundle

Per-command stdin scripts that exercise the full SCP03 admin shell command
surface against the simulated card backend (`YGGDRASIM_CARD_BACKEND=sim`).

Layout:

* `*.in.txt`        — one stdin script per command (newline-separated). Lines
                      starting with `#` are treated as comments and ignored by
                      the SCP03 batch loader.
* `manifest.json`   — declarative test catalogue: which command each script
                      exercises, prerequisites, and the expected APDU SW
                      tail (`9000` for happy paths, error SWs where the test
                      validates a refusal path).
* `run_all.py`      — runner. Iterates the manifest, pipes each `.in.txt`
                      through `python -m SCP03 --stdin`, captures
                      stdout / stderr / exit code, parses transmit traces for
                      the trailing `SW=…` tokens, and writes a single
                      review-ready dump to
                      `reports/scp03_live_run_<timestamp>.md`.

The runner sets `YGGDRASIM_CARD_BACKEND=sim`, `YGGDRASIM_DISALLOW_PLUGINS=1`
(to silence the optional polling plugin), and `PYTHONIOENCODING=utf-8` for
deterministic output. ANSI colour escapes are stripped before SW extraction.
