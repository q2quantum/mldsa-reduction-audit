"""
generate_verification_document.py -- Issue #369, задача 3: генератор
"документа проверки" для получателя (компании-производители PQC-библиотек,
лаборатории сертификации) из result.json прогона pqc_reduction_audit.

Форма и постоянные тексты -- venture/база_знаний/PQC_IMP_SW/документ_проверки_форма.md
(решение владельца 25.09.2026). Семь разделов, всегда в этом порядке:
1 (What was checked), 3 (Findings), 6 (How to reproduce) -- из result.json и
файла задачи. 2 (How it was checked), 5 (What we do not claim), 7 (Contact) --
постоянный текст. 4 (What this means) -- текст по библиотеке из этого скрипта;
если библиотеки нет в LIBRARY_SECTION_4 -- "Consequences not analysed."

Наружу документ уходит только по "отправляй" владельца (правило формы, п.4) --
этот скрипт сам никуда не публикует, только пишет файл на диск.

Использование:
    python scripts/generate_verification_document.py \
        --result path/to/result.json \
        --tool-link github.com/q2quantum/mldsa-reduction-audit \
        --output path/to/document.md
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

Q = 8_380_417  # FIPS 204 modulus


def _thousands(n: int) -> str:
    return f"{n:,}".replace(",", " ")


HOW_IT_WAS_CHECKED = (
    "Before each norm check in the signing loop, coefficients should be reduced "
    f"modulo q = {_thousands(Q)}. For every check, the tool finds the last arithmetic "
    "operation that produced the checked value and looks for a reduction "
    "between the two. Where there is none, the Z3 solver searches for a value "
    "that fails the check before reduction and passes it after. Such a value "
    "is a witness that the two results differ."
)

WHAT_WE_DO_NOT_CLAIM_BASE = [
    "This is not a vulnerability report. The tool shows that the code and the "
    "reference model disagree. It does not show that such values occur in "
    "practice: it assumes the full input range (−q, q).",
    "Only the last arithmetic operation before each check is examined.",
]

CONTACT = "Q² quantum ecosystem · q2quantum.app@gmail.com · github.com/q2quantum"

# Раздел 4 по библиотекам -- текст утверждён владельцем 25.09.2026
# (документ_проверки_форма.md, "Раздел 4 по библиотекам").
LIBRARY_SECTION_4 = {
    "wolfSSL": (
        "The difference goes one way only. Across all ML-DSA parameter sets, "
        "the check bounds are at most 524 288, and reduction does not change "
        "values below 2²². So a raw value that passes a check is "
        "already below the bound; the only possible difference is \"fails raw, "
        "passes reduced\". A failed check rejects the candidate and the signing "
        "loop repeats; w0 and ct0 are reduced before any later use. Worst case: "
        "one extra iteration of the signing loop. No memory corruption, no "
        "invalid signature, no key leakage.\n\n"
        "{pr_11113_status}\n\n"
        "These are not the places fixed in wolfSSL PR #9760 (reductions after "
        "matrix multiplication, 18.02.2026)."
    ),
}


def _fetch_pr_status(repo: str, pr_number: int) -> str:
    """Живой статус PR через gh api -- не полагаемся на память/устаревшую строку."""
    import subprocess

    try:
        r = subprocess.run(
            ["gh", "api", f"repos/{repo}/pulls/{pr_number}"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            return f"could not fetch live status of {repo}#{pr_number} (gh api failed)"
        data = json.loads(r.stdout)
        merged = data.get("merged")
        state = data.get("state")
        merged_at = data.get("merged_at")
        if merged:
            return f"A fix that adds both reductions was merged in {repo}#{pr_number} ({merged_at[:10]})."
        if state == "closed":
            return f"A fix that adds both reductions was proposed in {repo}#{pr_number}, closed without merging."
        return f"A fix that adds both reductions is proposed in {repo}#{pr_number}, not merged as of `<date>`."
    except Exception as e:
        return f"could not fetch live status of {repo}#{pr_number}: {e}"


LIBRARY_NO_FINDINGS_TEXT = "No differences found: every checked value is reduced before its check."

# Только wolfSSL получает третий пункт про SMALL_MEM-вариант (форма, раздел 5).
LIBRARY_EXTRA_NOT_COVERED = {
    "wolfSSL": "code variants not named in section 1, assembly code, and the `WOLFSSL_MLDSA_SIGN_SMALL_MEM` variant.",
}
DEFAULT_NOT_COVERED = "code variants not named in section 1, assembly code."


def _fmt_witness(w: dict) -> str:
    a_str = _thousands(w["a"]) if w["a"] >= 0 else "−" + _thousands(-w["a"])
    raw = "fails" if w["check_low_raw"] is False else "passes"
    reduced = "passes" if w["check_low_reduced"] else "fails"
    return f"difference proven: a = {a_str} {raw} raw, {reduced} after reduction (reduced value {w['reduced_value']})"


_STEP_RE = re.compile(r"Step (\d+(?:/\d+)?)")


def _standard_steps(sites: list[dict]) -> str:
    steps: set[str] = set()
    for site in sites:
        m = _STEP_RE.search(site.get("label", ""))
        if m:
            steps.add(m.group(1))
    ordered = sorted(steps, key=lambda s: int(s.split("/")[0]))
    return f"FIPS 204, Algorithm 2, steps {', '.join(ordered)}" if ordered else "FIPS 204, Algorithm 2"


def build_section1(result: dict) -> str:
    tv = result["target_version"]
    task = result["task"]
    av = result.get("auditor_version", {})
    sha_short = tv["sha256"][:12] + "…" + tv["sha256"][-6:]
    rows = [
        ("Library", f"{task['library']} {tv['git_tag']}, commit `{tv['git_commit'][:12]}`"),
        ("File", f"`{result['target_file']}`, SHA-256 `{sha_short}`"),
        ("Function", f"`{result['function']}`"),
        ("Standard", _standard_steps(result.get("sites", []))),
        ("Tool", f"`pqc_reduction_audit`, commit `{av.get('commit', '?')}`"),
    ]
    lines = ["**1. What was checked**", "", "| | |", "|---|---|"]
    for k, v in rows:
        lines.append(f"| {k} | {v} |")
    return "\n".join(lines)


def build_section3(result: dict) -> str:
    lines = [
        "**3. Findings**", "",
        "| # | Checked value | Check, line | Last operation, line | Reduction before check | Result |",
        "|---|---|---|---|---|---|",
    ]
    for i, site in enumerate(result["sites"], start=1):
        reduced = "yes" if site["reduce_present_in_source"] else "no"
        if site["is_defect"] and site.get("witness"):
            outcome = _fmt_witness(site["witness"])
        elif site["reduce_present_in_source"]:
            outcome = "not evaluated, reduction present"
        else:
            outcome = site.get("verdict", "unsat")
        label = site["label"]
        lines.append(f"| {i} | {label} | {site['check_call_line']} | `{site['last_arith_op']}`, {site['last_arith_line']} | {reduced} | {outcome} |")
    return "\n".join(lines)


def build_section4(library: str, has_defect: bool) -> str:
    if library in LIBRARY_SECTION_4:
        text = LIBRARY_SECTION_4[library]
        if "{pr_11113_status}" in text:
            text = text.format(pr_11113_status=_fetch_pr_status("wolfSSL/wolfssl", 11113))
        return "**4. What this means**\n\n" + text
    if not has_defect:
        return "**4. What this means**\n\n" + LIBRARY_NO_FINDINGS_TEXT
    return "**4. What this means**\n\nConsequences not analysed."


def build_section6(result: dict, tool_link: str) -> str:
    task = result["task"]
    defect_lines = [str(s["check_call_line"]) for s in result["sites"] if s["is_defect"]]
    tv = result["target_version"]
    kac = result.get("known_answer_check", {})
    lines = [
        "**6. How to reproduce**",
        f"Tool: `{tool_link}`.",
        "`python3 -m pqc_reduction_audit.cli --task task.json --out-dir out/`",
        f"Task file: library `{task['library']}`, version `{task['version']}`, profile `{task['target_profile']}`, file `{result['target_file']}`.",
    ]
    if defect_lines:
        lines.append(f"Expected: the file SHA-256 above, differences at lines {' and '.join(defect_lines)}.")
    else:
        lines.append("Expected: the file SHA-256 above, no differences.")
    if kac.get("declared"):
        lines.append("Before every run, the tool reproduces a known answer on a reference version of this library.")
    return "\n".join(lines)


def build_section5(library: str) -> str:
    items = list(WHAT_WE_DO_NOT_CLAIM_BASE)
    items.append("Not covered: other functions, " + LIBRARY_EXTRA_NOT_COVERED.get(library, DEFAULT_NOT_COVERED))
    body = "\n".join(f"- {it}" for it in items)
    return "**5. What we do not claim**\n\n" + body


def generate(result: dict, tool_link: str) -> str:
    library = result["task"]["library"]
    tv = result["target_version"]
    has_defect = any(s["is_defect"] for s in result.get("sites", []))
    parts = [
        f"**ML-DSA reduction audit — {library} {tv['git_tag']}**\n"
        f"Prepared as part of the Q² quantum ecosystem · `<date>` · q2quantum.app@gmail.com",
        build_section1(result),
        "**2. How it was checked**\n\n" + HOW_IT_WAS_CHECKED,
        build_section3(result),
        build_section4(library, has_defect),
        build_section5(library),
        build_section6(result, tool_link),
        "**7. Contact**\n\n" + CONTACT,
    ]
    return "\n\n".join(parts) + "\n"


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser()
    p.add_argument("--result", required=True, help="путь к result.json прогона")
    p.add_argument("--tool-link", default="<link to open code>", help="ссылка на открытый код инструмента")
    p.add_argument("--output", required=True, help="куда записать документ (.md)")
    args = p.parse_args()

    result = json.loads(Path(args.result).read_text(encoding="utf-8"))
    doc = generate(result, args.tool_link)
    Path(args.output).write_text(doc, encoding="utf-8")
    print(f"Документ записан: {args.output} ({len(doc)} символов)")


if __name__ == "__main__":
    main()
