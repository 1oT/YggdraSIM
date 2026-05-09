#!/usr/bin/env python3
"""SCP03 live command runner.

Iterates `tests/live_scp03/manifest.json`, pipes each `*.in.txt` script through
`python -m SCP03 --stdin` against the simulated card backend, captures
stdout / stderr / exit code, parses transmit traces for trailing `SW=…` tokens
and writes a single review-ready dump to
`reports/scp03_live_run_<timestamp>.md`.

Run from the repository root with the project venv:

    .venv/bin/python tests/live_scp03/run_all.py                # simulator (default)
    SCP03_LIVE_BACKEND=reader .venv/bin/python tests/live_scp03/run_all.py

Optional environment knobs:
    SCP03_LIVE_BACKEND      "sim" (default) or "reader"
    SCP03_LIVE_REPORT       override the output report path (must end with `.md`)
    SCP03_LIVE_FILTER       comma-separated list of test names to run
    SCP03_LIVE_TIMEOUT      per-test timeout in seconds (defaults: 45 sim / 90 reader)
    SCP03_LIVE_ALLOW_AUTH   "1" to enable tests that authenticate against the SD
                            (only honoured when backend=reader; can lock the SD if
                            the configured keys do not match the card)
    SCP03_LIVE_ALLOW_WRITE  "1" to enable destructive write tests (e.g. UPDATE)
                            (requires SCP03_LIVE_ALLOW_AUTH=1)
    SCP03_LIVE_READER_INDEX PC/SC reader index to probe in preflight (default 0)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
LIVE_DIR = Path(__file__).resolve().parent
MANIFEST = LIVE_DIR / "manifest.json"
REPORTS_DIR = REPO_ROOT / "reports"
RUN_ARTIFACT_DIR = REPORTS_DIR / "scp03_live_run"
SNAPSHOT_DIR = RUN_ARTIFACT_DIR / "_state_snapshot"
DEFAULT_TIMEOUT_SIM = 45
DEFAULT_TIMEOUT_READER = 90
BACKEND_SIM = "sim"
BACKEND_READER = "reader"
ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
SW_RX_LINE_RE = re.compile(
    r"\[<--\]\s+(?:[0-9A-Fa-f]+\s+)?([0-9A-Fa-f]{4})\s*$",
    re.MULTILINE,
)
SW_TAGGED_RE = re.compile(r"SW=([0-9A-Fa-f]{4})")


def _strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


def _extract_sws(text: str) -> list[str]:
    seen: list[str] = []
    for match in SW_RX_LINE_RE.findall(text):
        token = match.upper()
        if token not in seen:
            seen.append(token)
    for match in SW_TAGGED_RE.findall(text):
        token = match.upper()
        if token not in seen:
            seen.append(token)
    return seen


def _sw_counts(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for match in SW_RX_LINE_RE.findall(text):
        token = match.upper()
        counts[token] = counts.get(token, 0) + 1
    return counts


def _snapshot_state(files: list[str]) -> None:
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    for relative in files:
        source = REPO_ROOT / relative
        destination = SNAPSHOT_DIR / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.exists():
            shutil.copy2(source, destination)
        else:
            marker = destination.with_suffix(destination.suffix + ".missing")
            marker.write_text("", encoding="utf-8")


def _restore_state(files: list[str]) -> None:
    for relative in files:
        source = SNAPSHOT_DIR / relative
        target = REPO_ROOT / relative
        marker = source.with_suffix(source.suffix + ".missing")
        if source.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            continue
        if marker.exists():
            if target.exists():
                try:
                    target.unlink()
                except OSError:
                    pass


def _ensure_run_artifacts() -> None:
    RUN_ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    script_path = RUN_ARTIFACT_DIR / "run.script"
    script_path.write_text("HELP\nEXIT\n", encoding="utf-8")


def _resolve_python() -> str:
    candidate = REPO_ROOT / ".venv" / "bin" / "python"
    if candidate.exists():
        return str(candidate)
    return sys.executable


def _build_env(backend: str) -> dict[str, str]:
    env = os.environ.copy()
    env["YGGDRASIM_CARD_BACKEND"] = backend
    env["YGGDRASIM_DISALLOW_PLUGINS"] = env.get("YGGDRASIM_DISALLOW_PLUGINS", "1")
    env["PYTHONIOENCODING"] = "utf-8"
    env["NO_COLOR"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    return env


def _resolve_backend() -> str:
    raw = os.environ.get("SCP03_LIVE_BACKEND", BACKEND_SIM).strip().lower()
    if raw in {"reader", "real", "pcsc", "hardware"}:
        return BACKEND_READER
    return BACKEND_SIM


def _resolve_reader_index() -> int:
    raw = os.environ.get("SCP03_LIVE_READER_INDEX", "0").strip()
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def _reader_preflight(reader_index: int) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "ok": False,
        "reader_count": 0,
        "selected_index": reader_index,
        "selected_name": "",
        "atr": "",
        "error": "",
        "all_readers": [],
    }
    try:
        from smartcard.System import readers as pcsc_readers
    except Exception as import_error:
        summary["error"] = f"pyscard import failed: {import_error}"
        return summary
    rs = list(pcsc_readers())
    summary["reader_count"] = len(rs)
    summary["all_readers"] = [str(r) for r in rs]
    if len(rs) == 0:
        summary["error"] = "No PC/SC readers detected on the system."
        return summary
    if reader_index >= len(rs):
        summary["error"] = (
            f"Reader index {reader_index} out of range "
            f"(only {len(rs)} reader(s) detected)."
        )
        return summary
    selected = rs[reader_index]
    summary["selected_name"] = str(selected)
    try:
        connection = selected.createConnection()
        connection.connect()
        summary["atr"] = "".join(f"{byte:02X}" for byte in connection.getATR())
        connection.disconnect()
        summary["ok"] = True
    except Exception as connect_error:
        summary["error"] = f"reader connect failed: {connect_error}"
    return summary


def _classify_policy(name: str, manifest: dict[str, Any]) -> str:
    policy_block = manifest.get("reader_policy", {}) or {}
    write_list = {n.upper() for n in policy_block.get("write", []) or []}
    auth_list = {n.upper() for n in policy_block.get("auth", []) or []}
    upper = name.upper()
    if upper in write_list:
        return "write"
    if upper in auth_list:
        return "auth"
    return "default"


def _filter_for_reader(
    tests: list[dict[str, Any]],
    manifest: dict[str, Any],
    allow_auth: bool,
    allow_write: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    selected: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for entry in tests:
        policy = _classify_policy(entry["name"], manifest)
        decorated = dict(entry)
        decorated["reader_policy"] = policy
        if policy == "default":
            selected.append(decorated)
            continue
        if policy == "auth":
            if allow_auth:
                selected.append(decorated)
            else:
                decorated["skip_reason"] = (
                    "Requires SCP03 SD authentication; gated by "
                    "SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments "
                    "the SD lockout counter — 3 misses can brick the SD)."
                )
                skipped.append(decorated)
            continue
        if policy == "write":
            if allow_auth and allow_write:
                selected.append(decorated)
            else:
                decorated["skip_reason"] = (
                    "Destructive write to card; gated by "
                    "SCP03_LIVE_ALLOW_AUTH=1 + SCP03_LIVE_ALLOW_WRITE=1."
                )
                skipped.append(decorated)
            continue
        skipped.append(decorated)
    return selected, skipped


def _run_test(
    test: dict[str, Any],
    python_bin: str,
    env: dict[str, str],
    timeout: int,
    *,
    relaxed_assertions: bool = False,
) -> dict[str, Any]:
    script_name = test["script"]
    script_path = LIVE_DIR / script_name
    stdin_text = script_path.read_text(encoding="utf-8")
    has_debug = False
    for line in stdin_text.splitlines():
        stripped = line.strip().upper()
        if stripped == "DEBUG":
            has_debug = True
            break
        if stripped == "VERBOSE":
            has_debug = True
            break
    if has_debug is False:
        injected_stdin = "DEBUG\n" + stdin_text
    else:
        injected_stdin = stdin_text
    started_wall = datetime.now(timezone.utc).isoformat()
    started_mono = time.monotonic()
    process_result: dict[str, Any] = {
        "name": test["name"],
        "script": script_name,
        "started_at": started_wall,
        "category": test.get("category", ""),
        "reader_policy": test.get("reader_policy", "default"),
        "stdin_preview": stdin_text,
        "stdin_runtime": injected_stdin,
    }
    try:
        completed = subprocess.run(
            [python_bin, "-m", "SCP03", "--stdin"],
            input=injected_stdin,
            capture_output=True,
            cwd=str(REPO_ROOT),
            env=env,
            text=True,
            timeout=timeout,
        )
        elapsed = time.monotonic() - started_mono
        process_result.update({
            "exit_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "elapsed_s": round(elapsed, 3),
            "timed_out": False,
        })
    except subprocess.TimeoutExpired as expired:
        elapsed = time.monotonic() - started_mono
        process_result.update({
            "exit_code": -1,
            "stdout": expired.stdout or "",
            "stderr": (expired.stderr or "") + f"\n[runner] timed out after {timeout}s",
            "elapsed_s": round(elapsed, 3),
            "timed_out": True,
        })
    clean_stdout = _strip_ansi(process_result["stdout"])
    clean_stderr = _strip_ansi(process_result["stderr"])
    process_result["stdout_clean"] = clean_stdout
    process_result["stderr_clean"] = clean_stderr
    combined = clean_stdout + "\n" + clean_stderr
    process_result["sw_observed"] = _extract_sws(combined)
    process_result["sw_counts"] = _sw_counts(combined)

    expected_sw = [s.upper() for s in test.get("expected_sw", [])]
    expected_sw_any = [s.upper() for s in test.get("expected_sw_any", [])]
    expected_substrings = test.get("expected_substrings", [])
    tolerate_failure = bool(test.get("tolerate_failure", False))

    sw_pass = True
    sw_reasons: list[str] = []
    if len(expected_sw) > 0:
        for token in expected_sw:
            if token not in process_result["sw_observed"]:
                sw_pass = False
                sw_reasons.append(f"missing SW={token}")
    if len(expected_sw_any) > 0:
        any_match = False
        for token in expected_sw_any:
            if token in process_result["sw_observed"]:
                any_match = True
                break
        if any_match is False:
            sw_pass = False
            sw_reasons.append(f"none of SW {expected_sw_any} observed")

    substr_pass = True
    substr_missing: list[str] = []
    haystack = clean_stdout + "\n" + clean_stderr
    haystack_lower = haystack.lower()
    for needle in expected_substrings:
        if needle.lower() not in haystack_lower:
            substr_pass = False
            substr_missing.append(needle)

    exit_pass = (process_result["exit_code"] == 0) or tolerate_failure
    if relaxed_assertions is True:
        overall_pass = (process_result["timed_out"] is False)
    else:
        overall_pass = sw_pass and substr_pass and exit_pass and not process_result["timed_out"]

    process_result["assertions"] = {
        "expected_sw": expected_sw,
        "expected_sw_any": expected_sw_any,
        "sw_pass": sw_pass,
        "sw_reasons": sw_reasons,
        "expected_substrings": expected_substrings,
        "substr_pass": substr_pass,
        "substr_missing": substr_missing,
        "exit_pass": exit_pass,
        "tolerate_failure": tolerate_failure,
        "relaxed_assertions": relaxed_assertions,
        "overall_pass": overall_pass,
    }
    return process_result


def _format_block(text: str, *, max_lines: int = 200) -> str:
    if text is None:
        return ""
    lines = text.splitlines()
    if len(lines) > max_lines:
        head = lines[: max_lines // 2]
        tail = lines[-max_lines // 2 :]
        skipped = len(lines) - len(head) - len(tail)
        return "\n".join(head + [f"... ({skipped} lines elided) ..."] + tail)
    return "\n".join(lines)


def _verdict_label(result: dict[str, Any]) -> str:
    if result["assertions"]["overall_pass"]:
        return "PASS"
    if result["timed_out"]:
        return "TIMEOUT"
    return "FAIL"


def _render_report(
    results: list[dict[str, Any]],
    started_at: str,
    finished_at: str,
    *,
    backend: str,
    reader_summary: dict[str, Any] | None,
    skipped: list[dict[str, Any]],
    allow_auth: bool,
    allow_write: bool,
) -> str:
    summary_lines: list[str] = []
    backend_label = "simulated card" if backend == BACKEND_SIM else "real PC/SC reader"
    summary_lines.append(f"# SCP03 live command run ({backend_label})")
    summary_lines.append("")
    summary_lines.append(f"- Started:  {started_at}")
    summary_lines.append(f"- Finished: {finished_at}")
    summary_lines.append(f"- Backend:  YGGDRASIM_CARD_BACKEND={backend}")
    summary_lines.append(f"- Plugins:  YGGDRASIM_DISALLOW_PLUGINS=1")
    if backend == BACKEND_READER and reader_summary is not None:
        summary_lines.append(f"- Reader:   [{reader_summary.get('selected_index')}] {reader_summary.get('selected_name', '')}")
        if reader_summary.get("atr"):
            summary_lines.append(f"- ATR:      {reader_summary['atr']}")
        summary_lines.append(f"- Allow auth tests:  {allow_auth} (env SCP03_LIVE_ALLOW_AUTH)")
        summary_lines.append(f"- Allow write tests: {allow_write} (env SCP03_LIVE_ALLOW_WRITE)")
    summary_lines.append("")
    pass_count = sum(1 for r in results if r["assertions"]["overall_pass"])
    fail_count = len(results) - pass_count
    timeout_count = sum(1 for r in results if r["timed_out"])
    summary_lines.append(f"- Total:   {len(results)}")
    summary_lines.append(f"- Pass:    {pass_count}")
    summary_lines.append(f"- Fail:    {fail_count}")
    summary_lines.append(f"- Timeout: {timeout_count}")
    summary_lines.append(f"- Skipped: {len(skipped)}")
    summary_lines.append("")
    if backend == BACKEND_READER and len(skipped) > 0:
        summary_lines.append("## Skipped (gated for reader safety)")
        summary_lines.append("")
        summary_lines.append("| Command | Policy | Reason |")
        summary_lines.append("| --- | --- | --- |")
        for entry in skipped:
            reason = entry.get("skip_reason", "—")
            summary_lines.append(
                f"| `{entry['name']}` | {entry.get('reader_policy', '—')} | {reason} |"
            )
        summary_lines.append("")
    summary_lines.append("## Verdict matrix")
    summary_lines.append("")
    if backend == BACKEND_READER:
        summary_lines.append("| Command | Policy | Verdict | Exit | Elapsed (s) | SWs observed | Notes |")
        summary_lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    else:
        summary_lines.append("| Command | Verdict | Exit | Elapsed (s) | SWs observed | Notes |")
        summary_lines.append("| --- | --- | --- | --- | --- | --- |")
    for r in results:
        verdict = _verdict_label(r)
        sws = ", ".join(r["sw_observed"]) if r["sw_observed"] else "—"
        notes_parts: list[str] = []
        a = r["assertions"]
        if not a["sw_pass"]:
            notes_parts.append("SW " + "; ".join(a["sw_reasons"]))
        if not a["substr_pass"]:
            notes_parts.append("missing strings: " + ", ".join(a["substr_missing"]))
        if not a["exit_pass"]:
            notes_parts.append(f"exit={r['exit_code']}")
        if a["tolerate_failure"] and verdict == "PASS":
            notes_parts.append("tolerate_failure")
        if a.get("relaxed_assertions") and verdict == "PASS" and not a["sw_pass"]:
            notes_parts.append("relaxed (reader)")
        notes_text = "; ".join(notes_parts) if notes_parts else "ok"
        if backend == BACKEND_READER:
            summary_lines.append(
                f"| `{r['name']}` | {r.get('reader_policy', '—')} | {verdict} | {r['exit_code']} | {r['elapsed_s']} | {sws} | {notes_text} |"
            )
        else:
            summary_lines.append(
                f"| `{r['name']}` | {verdict} | {r['exit_code']} | {r['elapsed_s']} | {sws} | {notes_text} |"
            )
    summary_lines.append("")
    summary_lines.append("## Per-command transcripts")
    summary_lines.append("")
    body_blocks: list[str] = []
    for r in results:
        a = r["assertions"]
        block: list[str] = []
        block.append(f"### `{r['name']}` — {_verdict_label(r)}")
        block.append("")
        block.append(f"- Category:        {r['category'] or '—'}")
        block.append(f"- Script:          `tests/live_scp03/{r['script']}`")
        block.append(f"- Started at:      {r['started_at']}")
        block.append(f"- Elapsed:         {r['elapsed_s']} s")
        block.append(f"- Exit code:       {r['exit_code']}")
        block.append(f"- Timed out:       {r['timed_out']}")
        block.append(f"- SWs observed:    {', '.join(r['sw_observed']) if r['sw_observed'] else '—'}")
        if r.get("sw_counts"):
            counts_render = ", ".join(f"{sw}×{count}" for sw, count in r["sw_counts"].items())
            block.append(f"- SW frequency:    {counts_render}")
        block.append(f"- Expected SW:     {a['expected_sw'] or '—'}")
        block.append(f"- Expected SW any: {a['expected_sw_any'] or '—'}")
        block.append(f"- Expected text:   {a['expected_substrings'] or '—'}")
        block.append(f"- SW assertion:    {'pass' if a['sw_pass'] else 'fail (' + '; '.join(a['sw_reasons']) + ')'}")
        block.append(f"- Text assertion:  {'pass' if a['substr_pass'] else 'fail (missing: ' + ', '.join(a['substr_missing']) + ')'}")
        block.append(f"- Exit assertion:  {'pass' if a['exit_pass'] else 'fail'}")
        block.append("")
        block.append("Stdin script:")
        block.append("")
        block.append("```")
        block.append(r["stdin_preview"].rstrip())
        block.append("```")
        block.append("")
        block.append("Stdout (ANSI stripped):")
        block.append("")
        block.append("```")
        block.append(_format_block(r["stdout_clean"]))
        block.append("```")
        block.append("")
        if r["stderr_clean"].strip():
            block.append("Stderr (ANSI stripped):")
            block.append("")
            block.append("```")
            block.append(_format_block(r["stderr_clean"]))
            block.append("```")
            block.append("")
        body_blocks.append("\n".join(block))
    summary_lines.append("\n".join(body_blocks))
    return "\n".join(summary_lines).rstrip() + "\n"


def main() -> int:
    if MANIFEST.exists() is False:
        print(f"manifest not found: {MANIFEST}", file=sys.stderr)
        return 2
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    snapshot_files = manifest.get("snapshot_files", [])
    raw_tests = manifest.get("tests", [])
    name_filter = os.environ.get("SCP03_LIVE_FILTER", "").strip()
    if len(name_filter) > 0:
        wanted = {n.strip().upper() for n in name_filter.split(",") if n.strip()}
        raw_tests = [t for t in raw_tests if t["name"].upper() in wanted]

    backend = _resolve_backend()
    allow_auth = os.environ.get("SCP03_LIVE_ALLOW_AUTH", "").strip() == "1"
    allow_write = os.environ.get("SCP03_LIVE_ALLOW_WRITE", "").strip() == "1"

    skipped: list[dict[str, Any]] = []
    if backend == BACKEND_READER:
        tests, skipped = _filter_for_reader(raw_tests, manifest, allow_auth, allow_write)
    else:
        tests = [dict(entry, reader_policy=_classify_policy(entry["name"], manifest)) for entry in raw_tests]

    timeout_env = os.environ.get("SCP03_LIVE_TIMEOUT", "").strip()
    if backend == BACKEND_READER:
        timeout = DEFAULT_TIMEOUT_READER
    else:
        timeout = DEFAULT_TIMEOUT_SIM
    if len(timeout_env) > 0:
        try:
            timeout = max(5, int(timeout_env))
        except ValueError:
            pass

    reader_summary: dict[str, Any] | None = None
    if backend == BACKEND_READER:
        reader_index = _resolve_reader_index()
        reader_summary = _reader_preflight(reader_index)
        print("[runner] reader-mode preflight:", flush=True)
        for line in reader_summary.get("all_readers", []):
            print(f"           - {line}", flush=True)
        if reader_summary.get("ok") is True:
            print(
                f"[runner] using reader [{reader_summary['selected_index']}] "
                f"{reader_summary['selected_name']} (ATR={reader_summary['atr']})",
                flush=True,
            )
        else:
            print(f"[runner] reader preflight failed: {reader_summary.get('error', 'unknown error')}", file=sys.stderr)
            return 3
        print(
            "[runner] reader policy: default=run, auth=opt-in (SCP03_LIVE_ALLOW_AUTH=1), "
            "write=opt-in (+ SCP03_LIVE_ALLOW_WRITE=1)",
            flush=True,
        )
        print(
            f"[runner] selected={len(tests)}  skipped={len(skipped)}  "
            f"allow_auth={allow_auth}  allow_write={allow_write}",
            flush=True,
        )

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    _ensure_run_artifacts()
    _snapshot_state(snapshot_files)

    python_bin = _resolve_python()
    env = _build_env(backend)

    results: list[dict[str, Any]] = []
    started_at = datetime.now(timezone.utc).isoformat()
    print(
        f"[runner] backend={backend} tests={len(tests)} python={python_bin} timeout={timeout}s",
        flush=True,
    )
    relaxed = (backend == BACKEND_READER)
    for index, test in enumerate(tests, start=1):
        policy_tag = test.get("reader_policy", "default")
        print(
            f"[{index:>3}/{len(tests)}] {test['name']:<22} [{policy_tag:<7}] ... ",
            end="",
            flush=True,
        )
        result = _run_test(test, python_bin, env, timeout, relaxed_assertions=relaxed)
        verdict = _verdict_label(result)
        sws = ",".join(result["sw_observed"]) or "-"
        print(
            f"{verdict:<7} exit={result['exit_code']:<4} sw=[{sws}] in {result['elapsed_s']}s",
            flush=True,
        )
        results.append(result)
    finished_at = datetime.now(timezone.utc).isoformat()

    _restore_state(snapshot_files)

    report_text = _render_report(
        results,
        started_at,
        finished_at,
        backend=backend,
        reader_summary=reader_summary,
        skipped=skipped,
        allow_auth=allow_auth,
        allow_write=allow_write,
    )
    override = os.environ.get("SCP03_LIVE_REPORT", "").strip()
    if len(override) > 0:
        report_path = Path(override)
        if report_path.is_absolute() is False:
            report_path = REPO_ROOT / report_path
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        suffix = "_reader" if backend == BACKEND_READER else ""
        report_path = REPORTS_DIR / f"scp03_live_run{suffix}_{stamp}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_text, encoding="utf-8")
    json_path = report_path.with_suffix(".json")
    json_path.write_text(
        json.dumps(
            {
                "started_at": started_at,
                "finished_at": finished_at,
                "backend": backend,
                "reader_summary": reader_summary,
                "allow_auth": allow_auth,
                "allow_write": allow_write,
                "skipped": [
                    {
                        "name": entry["name"],
                        "reader_policy": entry.get("reader_policy", ""),
                        "skip_reason": entry.get("skip_reason", ""),
                    }
                    for entry in skipped
                ],
                "results": [
                    {
                        "name": r["name"],
                        "script": r["script"],
                        "category": r["category"],
                        "reader_policy": r.get("reader_policy", "default"),
                        "exit_code": r["exit_code"],
                        "elapsed_s": r["elapsed_s"],
                        "timed_out": r["timed_out"],
                        "sw_observed": r["sw_observed"],
                        "assertions": r["assertions"],
                    }
                    for r in results
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"[runner] wrote {report_path}")
    print(f"[runner] wrote {json_path}")

    failures = [r for r in results if r["assertions"]["overall_pass"] is False]
    if len(failures) > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
