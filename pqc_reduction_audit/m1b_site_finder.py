"""
Связывает M1 (последовательность вызовов) с M2/M3 (несущая/избыточная
редукция): для каждого места, где арифметическая цепочка заканчивается
вызовом check_low, проверяет, есть ли между последней арифметической
операцией и check_low вызов reduce -- и если нет, классифицирует находку
через M3 (несущая -> реальный дефект, избыточная -> не флагуется).

Issue #176 introduced per-target-codebase function-name profiles (wolfSSL's
dilithium_* naming isn't universal). Issue #320 moved those profiles out of
this file entirely, into profiles/<name>.json (see profile_loader.py) --
adding a target now means adding a profile file, not editing this module.
"""
from __future__ import annotations

from dataclasses import dataclass

from pqc_reduction_audit.m1_parser import CallSite
from pqc_reduction_audit.m3_smt import build_reduction_necessity_certificate, Certificate
from pqc_reduction_audit.profile_loader import TargetProfile


def _name_matches(callee: str, names, match_mode: str = "suffix") -> bool:
    """True if callee is exactly one of names, or (match_mode == "suffix")
    ends with "_<name>" -- the suffix form covers namespace-macro-expanded
    symbols (mldsa_native: `#define mld_poly_reduce MLD_NAMESPACE(poly_reduce)`,
    expanding to e.g. PQCP_MLDSA_NATIVE_MLDSA44_C_poly_reduce under liboqs's
    build config -- libclang sees the post-macro-expansion token, never the
    raw "mld_*" name). A profile that doesn't need this (function names not
    namespace-mangled) can set match_mode="exact" to avoid an accidental
    suffix collision with an unrelated function."""
    if callee in names:
        return True
    if match_mode == "suffix":
        return any(callee.endswith("_" + n) for n in names)
    return False


@dataclass
class Finding:
    check_call_line: int
    last_arith_op: str
    last_arith_line: int
    reduce_present: bool
    hi_hint: str
    certificate: Certificate | None
    is_defect: bool


def find_missing_reduction_sites(calls: list[CallSite], hi_by_check_line: dict[int, tuple[str, int]],
                                  profile: TargetProfile) -> list[Finding]:
    """hi_by_check_line: {line_of_check_low_call: (label, hi_value)} -- порог
    известен из контекста вызова (hi передаётся переменной, не литералом,
    поэтому подставляется вручную по разбору кода, см. cli.py).

    profile: a loaded TargetProfile (profile_loader.load_profile) -- selects
    which function names count as arithmetic/reduce/check calls, and how
    they're matched (Issue #176, file-driven since Issue #320). Detection
    logic (the state machine below) is identical across profiles; only the
    name sets and match mode differ."""
    arith_ops, reduce_ops, check_ops = profile.arith, profile.reduce, profile.check
    match_mode = profile.match_mode

    findings: list[Finding] = []
    last_arith: CallSite | None = None
    reduce_seen_since_arith = False

    for call in calls:
        if _name_matches(call.callee, arith_ops, match_mode):
            last_arith = call
            reduce_seen_since_arith = False
        elif _name_matches(call.callee, reduce_ops, match_mode):
            reduce_seen_since_arith = True
        elif _name_matches(call.callee, check_ops, match_mode):
            if last_arith is None:
                continue
            label, hi = hi_by_check_line.get(call.line, (f"check@{call.line}", None))
            cert = None
            is_defect = False
            if not reduce_seen_since_arith and hi is not None:
                cert = build_reduction_necessity_certificate(label, hi)
                is_defect = cert.verdict == "sat"
            findings.append(Finding(
                check_call_line=call.line,
                last_arith_op=last_arith.callee,
                last_arith_line=last_arith.line,
                reduce_present=reduce_seen_since_arith,
                hi_hint=label,
                certificate=cert,
                is_defect=is_defect,
            ))
    return findings
