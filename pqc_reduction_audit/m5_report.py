"""
M5 — Генератор отчёта. Собирает находки M1b (структурный поиск мест
редукции) + M3 (сертификаты) в JSON и Markdown — строки редукций с
классификацией, sat/unsat-сертификаты, ссылка на сертификат.
"""
from __future__ import annotations

import json
from pathlib import Path

from pqc_reduction_audit.m1b_site_finder import Finding
from pqc_reduction_audit.version_info import TargetVersionInfo


def findings_to_dict(findings: list[Finding], target_file: str, function_name: str,
                      target_version: TargetVersionInfo | None = None,
                      extra_fields: dict | None = None) -> dict:
    data = {
        "target_file": target_file,
        "function": function_name,
        "target_version": target_version.to_dict() if target_version else None,
        "sites": [
            {
                "check_call_line": f.check_call_line,
                "last_arith_op": f.last_arith_op,
                "last_arith_line": f.last_arith_line,
                "reduce_present_in_source": f.reduce_present,
                "label": f.hi_hint,
                "verdict": f.certificate.verdict if f.certificate else "not_evaluated (reduce present in source)",
                "is_defect": f.is_defect,
                "witness": f.certificate.witness if f.certificate else None,
            }
            for f in findings
        ],
    }
    # Issue #319: task-file runs add {task, auditor_version, run_seconds,
    # known_answer_check} -- kept as an update() so the flags-only call
    # sites (and every existing committed reference report) stay byte-for-
    # byte identical in shape when extra_fields is None.
    if extra_fields:
        data.update(extra_fields)
    return data


def write_report(findings: list[Finding], target_file: str, function_name: str,
                  out_dir: Path, run_label: str,
                  target_version: TargetVersionInfo | None = None,
                  extra_fields: dict | None = None) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    data = findings_to_dict(findings, target_file, function_name, target_version, extra_fields)

    json_path = out_dir / f"{run_label}.json"
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    version_lines = []
    if target_version:
        version_lines.append(f"**SHA-256 цели:** `{target_version.sha256}`  ")
        if target_version.git_tag or target_version.git_commit:
            ref = target_version.git_tag or target_version.git_commit
            dirty = " (незакоммиченные изменения!)" if target_version.git_dirty else ""
            version_lines.append(f"**Версия цели (git):** `{ref}`{dirty}  ")
    task_meta = data.get("task")
    if task_meta:
        if task_meta.get("library"):
            version_lines.append(f"**Библиотека:** {task_meta['library']}"
                                  + (f" {task_meta['version']}" if task_meta.get("version") else "")
                                  + "  ")
        version_lines.append(f"**Профиль цели:** `{task_meta.get('target_profile')}`  ")
    auditor_version = data.get("auditor_version")
    if auditor_version and auditor_version.get("commit"):
        dirty = " (незакоммиченные изменения!)" if auditor_version.get("dirty") else ""
        version_lines.append(f"**Версия аудитора (коммит):** `{auditor_version['commit']}`{dirty}  ")
    if data.get("run_seconds") is not None:
        version_lines.append(f"**Время прогона:** {data['run_seconds']} с  ")

    lines = [
        f"# Отчёт аудита редукций -- {run_label}",
        "",
        f"**Файл:** `{target_file}`  ",
        f"**Функция:** `{function_name}`",
        *version_lines,
        "",
        "| Строка check_low | Последняя арифметика | Редукция в исходнике | Вердикт (sat=несущая/unsat=избыточна) | Дефект? |",
        "|---|---|---|---|---|",
    ]
    for site in data["sites"]:
        lines.append(
            f"| {site['check_call_line']} | {site['last_arith_op']}@{site['last_arith_line']} | "
            f"{'да' if site['reduce_present_in_source'] else '**нет**'} | {site['verdict']} | "
            f"{'**ДА**' if site['is_defect'] else 'нет'} |"
        )
    lines.append("")
    for site in data["sites"]:
        if site["witness"]:
            lines.append(f"### Свидетель для строки {site['check_call_line']} ({site['label']})")
            lines.append(f"- `a = {site['witness']['a']}`")
            lines.append(f"- `check_low(a, hi)` (сырое) = {site['witness']['check_low_raw']}")
            lines.append(f"- `dilithium_red(a)` = {site['witness']['reduced_value']}")
            lines.append(f"- `check_low(red(a), hi)` = {site['witness']['check_low_reduced']}")
            lines.append("")

    known_answer_check = data.get("known_answer_check")
    if known_answer_check and known_answer_check.get("declared"):
        verdict = "✓ PASS" if known_answer_check["passed"] else "✗ FAIL"
        lines.append(f"## Самопроверка на известном ответе: {verdict}")
        for m in known_answer_check.get("mismatches", []):
            lines.append(f"- {m}")
        lines.append("")

    md_path = out_dir / f"{run_label}.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path
