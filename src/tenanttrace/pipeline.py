"""Stage orchestration: ingest -> coverage -> analyze -> report.

Each stage reads what the previous one stored in the case folder, so stages can be run and
inspected one at a time from the CLI.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tenanttrace import TOOL_NAME, __version__
from tenanttrace.case import Case, Timer, file_mtime_utc, list_inputs, utc_now_iso
from tenanttrace.hashing import long_path, sha256_file
from tenanttrace.schema import SCHEMA_VERSION
from tenanttrace.store import CaseStore


def tool_versions() -> dict[str, str]:
    from tenanttrace.versions import reference_version, ruleset_version

    return {
        "tool": f"{TOOL_NAME} {__version__}",
        "schema": SCHEMA_VERSION,
        "ruleset": ruleset_version(),
        "reference_table": reference_version(),
    }


def ingest(input_dir: Path, case: Case, force: bool = False) -> dict[str, Any]:
    from tenanttrace.ingest.runner import ingest_file
    from tenanttrace.ingest.linking import link_events

    input_dir = Path(input_dir).resolve()
    if not input_dir.is_dir():
        raise NotADirectoryError(f"input folder not found: {input_dir}")
    if case.root == input_dir or input_dir in case.root.parents:
        raise ValueError("the case folder must not be inside the input folder")
    shown_input = str(input_dir)
    input_dir = long_path(input_dir)   # collector folders can exceed the classic Windows path limit
    case.create(force=force)
    log = case.log
    timer = Timer()
    log.write("ingest", f"{TOOL_NAME} {__version__} starting ingest", input_dir=shown_input, versions=tool_versions())

    inputs = list_inputs(input_dir, exclude=long_path(case.root))
    log.write("ingest", f"found {len(inputs)} input file(s)")

    manifest_inputs: list[dict[str, Any]] = []
    with CaseStore(case.db_path) as store:
        store.bulk_mode()
        store.set_meta("input_dir", shown_input)
        for path in inputs:
            rel = path.relative_to(input_dir).as_posix()
            size = path.stat().st_size
            digest = sha256_file(path)
            file_id = store.add_file(rel, digest, size)
            log.write("hash", f"sha256 {digest} {rel}", size=size)
            result = ingest_file(path, rel, file_id, digest, size, store, log)
            after = sha256_file(path)
            if after != digest:  # the input changed under us: never silently accept it
                log.write("integrity", f"input changed during processing: {rel}", before=digest, after=after)
                raise RuntimeError(f"input file changed while it was being processed: {rel}")
            entry = {
                "path": rel,
                "sha256": digest,
                "size": size,
                "modified_utc": file_mtime_utc(path),
                **result,
            }
            manifest_inputs.append(entry)
            store.commit()
        link_summary = link_events(store, log)
        store.build_indexes()
        store.set_meta("ingested_utc", utc_now_iso())
        store.commit()

    manifest = {
        "tool": TOOL_NAME,
        "tool_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "versions": tool_versions(),
        "created_utc": utc_now_iso(),
        "input_dir": shown_input,
        "inputs": manifest_inputs,
        "totals": _totals(manifest_inputs),
        "linking": link_summary,
    }
    case.write_json("manifest.json", manifest)
    log.write("ingest", f"ingest finished in {timer.elapsed()}s", totals=manifest["totals"])
    return manifest


def _totals(inputs: list[dict[str, Any]]) -> dict[str, int]:
    keys = ("records_total", "records_parsed", "records_unrecognised", "records_malformed")
    t = {k: sum(int(i.get(k, 0) or 0) for i in inputs) for k in keys}
    t["files"] = len(inputs)
    t["files_unrecognised"] = sum(1 for i in inputs if not i.get("parser"))
    return t


def _case_params(case: Case, user: str | None, window_start: str | None, collected_at: str | None,
                 ipdb: str | None) -> dict[str, Any]:
    params = case.save_params(user=user.lower() if user else None, window_start=window_start,
                              collected_at=collected_at, ipdb=ipdb)
    if not params.get("user"):
        raise ValueError("no user given: pass --user UPN")
    return params


def coverage(case: Case, user: str | None = None, window_start: str | None = None,
             collected_at: str | None = None, ipdb: str | None = None) -> dict[str, Any]:
    from tenanttrace.coverage.analysis import compute_coverage

    params = _case_params(case, user, window_start, collected_at, ipdb)
    log = case.log
    with CaseStore(case.db_path) as store:
        cov = compute_coverage(store, params, log)
    case.write_json("coverage.json", cov)
    log.write("coverage", "coverage written", summary=cov.get("summary"))
    return cov


def analyze(case: Case, user: str | None = None, window_start: str | None = None,
            collected_at: str | None = None, ipdb: str | None = None) -> dict[str, Any]:
    from tenanttrace.analysis import run_analysis

    params = _case_params(case, user, window_start, collected_at, ipdb)
    cov = case.read_json("coverage.json") or coverage(case)
    log = case.log
    with CaseStore(case.db_path) as store:
        ipdb = None
        if params.get("ipdb"):
            from tenanttrace.geo import enrich

            ipdb = enrich(store, params["ipdb"], log)
        result = run_analysis(store, params, cov, log)
        if ipdb:
            result["ipdb"] = ipdb
    case.write_json("analysis.json", result)
    # rule capability feeds back into the gap analysis
    if result.get("capability"):
        cov["detection_capability"] = result["capability"]
        case.write_json("coverage.json", cov)
    log.write("analyze", "analysis written", summary=result.get("summary"))
    return result


def report(case: Case, pdf: bool = True) -> dict[str, str]:
    from tenanttrace.report.build import build_reports

    log = case.log
    out = build_reports(case, pdf=pdf, log=log)
    log.write("report", "reports written", outputs=out)
    return out


def run_all(input_dir: Path, case: Case, user: str, force: bool = False, window_start: str | None = None,
            collected_at: str | None = None, ipdb: str | None = None, pdf: bool = True) -> dict[str, Any]:
    manifest = ingest(input_dir, case, force=force)
    cov = coverage(case, user=user, window_start=window_start, collected_at=collected_at, ipdb=ipdb)
    res = analyze(case)
    out = report(case, pdf=pdf)
    return {"manifest": manifest, "coverage": cov, "analysis": res, "report": out}
