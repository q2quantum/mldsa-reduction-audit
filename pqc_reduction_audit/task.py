"""
task.py -- Issue #319: unified task-file -> result.json entry point.

Wraps the existing M1(+M1b)-M5 pipeline. Does NOT change the search or
proof logic (that stays entirely in m1_parser.py / m1b_site_finder.py /
m3_smt*.py) -- this module only adds:

  - a single task-file description in (library, version, target file,
    function, profile -- previously a handful of separate --flags),
  - a self-check against a known answer declared *in the task file itself*
    (previously only available as an external byte-diff against a
    committed reference JSON, in run_known_answer.sh),
  - the auditor's own version (this checkout's git commit) and wall-clock
    run time in the output -- neither was recorded before.

cli.py (the pre-existing --target/--include-root/... flags interface) now
builds the same AuditTask this module defines and calls run_task() too, so
there is exactly one place that walks M1->M1b->M3->M5.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from pqc_reduction_audit.m1_parser import parse_function_calls
from pqc_reduction_audit.m1b_site_finder import find_missing_reduction_sites, _name_matches
from pqc_reduction_audit.m5_report import write_report
from pqc_reduction_audit.profile_loader import TargetProfile, load_profile
from pqc_reduction_audit.version_info import compute_target_version_info


def map_hi_by_line(calls, function_name: str, profile: TargetProfile,
                    site_order: list[str] | None = None) -> dict[int, tuple[str, int]]:
    """Builds {line: (label, hi)} for known check calls by order of
    appearance (stable even if exact line numbers shift). Site labels/
    thresholds and the expected order come from the profile (Issue #320) --
    site_order overrides the profile's own order for this one run (task
    file's own "site_order" field, or --site-order flag).

    Raises ValueError if the number of check_low call sites actually found
    doesn't match the expected order's length -- previously this silently
    dropped the excess via zip() (Issue #320: "четвёртое тихо пропускает"),
    which is exactly the failure mode this task-file interface is meant to
    surface as a report, not hide."""
    check_lines = [c.line for c in calls if _name_matches(c.callee, profile.check, profile.match_mode)]
    order = site_order or profile.site_order_for(function_name)
    if len(check_lines) != len(order):
        raise ValueError(
            f"expected {len(order)} check-site(s) ({list(order)}) for function "
            f"{function_name!r} under profile {profile.name!r}, but found "
            f"{len(check_lines)} check_low call(s) at line(s) {check_lines} -- "
            f"a profile/site_order mismatch, not a droppable extra site"
        )
    return {line: (profile.site_labels[key].label, profile.site_labels[key].hi)
            for line, key in zip(check_lines, order)}


@dataclass
class KnownAnswerSite:
    label: str
    is_defect: bool


@dataclass
class AuditTask:
    """One audit run, fully described by a single task file (Issue #319).

    target_file: path to the target .c/.cpp file, absolute or relative to
        include_root. The target source is never vendored into this
        repository (license constraint) -- the task file just names a path
        on the caller's own checkout, same as --target/--include-root did.
    """

    target_file: str
    include_root: str
    function: str
    run_label: str
    target_profile: str = "wolfssl"
    library: str | None = None
    version: str | None = None
    defines: list[str] = field(default_factory=list)
    extra_include: list[str] = field(default_factory=list)
    # None (not "c99") -- Issue #320: the language, and so the effective
    # clang -std default, now comes from the profile (profile.language) so
    # a C++ target doesn't need the caller to remember --std/"std" at all.
    # An explicit value here (or --std on the CLI) still overrides it.
    std: str | None = None
    site_order: list[str] | None = None
    known_answer: list[KnownAnswerSite] | None = None

    @classmethod
    def from_file(cls, path: str | Path) -> "AuditTask":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data, default_run_label=Path(path).stem)

    @classmethod
    def from_dict(cls, data: dict, default_run_label: str | None = None) -> "AuditTask":
        known_answer = None
        ka = data.get("known_answer")
        if ka and ka.get("expected_sites"):
            known_answer = [
                KnownAnswerSite(label=s["label"], is_defect=bool(s["is_defect"]))
                for s in ka["expected_sites"]
            ]
        run_label = data.get("run_label") or default_run_label
        if not run_label:
            raise ValueError("task is missing 'run_label' and no default was given")
        return cls(
            target_file=data["target_file"],
            include_root=data["include_root"],
            function=data["function"],
            run_label=run_label,
            target_profile=data.get("target_profile", "wolfssl"),
            library=data.get("library"),
            version=data.get("version"),
            defines=list(data.get("defines", [])),
            extra_include=list(data.get("extra_include", [])),
            std=data.get("std"),
            site_order=data.get("site_order"),
            known_answer=known_answer,
        )


def compute_auditor_version() -> dict:
    """git commit of THIS checkout of quantum-map (where pqc_reduction_audit
    lives) -- independent of the target's own version_info.py entry, which
    tracks the checkout being *audited*, not the tool doing the auditing."""
    repo_root = Path(__file__).resolve().parent.parent
    try:
        commit = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
        )
        if commit.returncode != 0:
            return {"commit": None, "dirty": None}
        dirty = subprocess.run(
            ["git", "-C", str(repo_root), "status", "--porcelain", "--",
             "pqc_reduction_audit"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
        )
        return {
            "commit": commit.stdout.strip(),
            "dirty": bool(dirty.stdout.strip()) if dirty.returncode == 0 else None,
        }
    except (OSError, subprocess.TimeoutExpired):
        return {"commit": None, "dirty": None}


def _check_known_answer(findings, expected: list[KnownAnswerSite] | None) -> dict:
    """Self-check against a known answer declared in the task file itself
    (Issue #319) -- distinct from run_known_answer.sh's external byte-diff
    against a committed reference report, which still exists separately for
    full-report reproducibility."""
    if expected is None:
        return {"declared": False, "passed": None, "mismatches": []}
    actual = [(f.hi_hint, f.is_defect) for f in findings]
    wanted = [(s.label, s.is_defect) for s in expected]
    mismatches = []
    if len(actual) != len(wanted):
        mismatches.append(f"site count: expected {len(wanted)}, got {len(actual)}")
    for i, (a, w) in enumerate(zip(actual, wanted)):
        if a != w:
            mismatches.append(f"site {i}: expected label/is_defect {w}, got {a}")
    return {"declared": True, "passed": not mismatches, "mismatches": mismatches}


def run_task(task: AuditTask, out_dir: Path) -> tuple[dict, Path, Path]:
    """Runs M1(+M1b)-M5 for one AuditTask, returns (result_dict, json_path,
    md_path). The target profile (Issue #320) is loaded by name from
    profiles/<task.target_profile>.json -- ProfileError propagates as-is
    (an unknown/malformed profile is a real, actionable error, not a
    caller's problem to pre-check)."""
    started = time.perf_counter()

    profile = load_profile(task.target_profile)
    std = task.std or ("c++17" if profile.language == "cpp" else "c99")
    lang_args = ["-x", "c++"] if std.startswith("c++") else []
    clang_args = (
        lang_args
        + [f"-std={std}", f"-I{task.include_root}"]
        + [f"-I{p}" for p in task.extra_include]
        + [f"-D{d}" for d in task.defines]
    )

    target_path = task.target_file
    if not os.path.isabs(target_path):
        target_path = os.path.join(task.include_root, task.target_file)

    trace = parse_function_calls(target_path, task.function, args=clang_args)
    hi_map = map_hi_by_line(trace.calls, task.function, profile, task.site_order)
    findings = find_missing_reduction_sites(trace.calls, hi_map, profile=profile)

    target_version = compute_target_version_info(target_path, task.include_root)

    try:
        display_path = os.path.relpath(target_path, task.include_root).replace(os.sep, "/")
    except ValueError:
        # target and include_root on different drives (Windows) -- fall back
        # to the raw path rather than crash
        display_path = target_path

    run_seconds = time.perf_counter() - started

    extra_fields = {
        "task": {
            "library": task.library,
            "version": task.version,
            "target_profile": task.target_profile,
        },
        "auditor_version": compute_auditor_version(),
        "run_seconds": round(run_seconds, 3),
        "known_answer_check": _check_known_answer(findings, task.known_answer),
    }

    json_path, md_path = write_report(
        findings, display_path, task.function, out_dir, task.run_label,
        target_version=target_version, extra_fields=extra_fields,
    )
    data = json.loads(json_path.read_text(encoding="utf-8"))
    return data, json_path, md_path
