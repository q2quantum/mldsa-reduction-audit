"""
CLI — прогоняет M1(+M1b)-M5 на целевом файле пользователя.

Task-file form (Issue #319, preferred going forward):

    python -m pqc_reduction_audit.cli --task <path/to/task.json> --out-dir <path>

Task-file schema is documented in README.md ("Task-file interface").

Flags form (kept for backward compatibility, same behaviour as before #319):

    python -m pqc_reduction_audit.cli --target <path/to/dilithium.c> \
        --include-root <path/to/wolfssl/checkout> \
        --function dilithium_sign_with_seed_mu \
        --run-label KNOWN_ANSWER_WOLFSSL_DILITHIUM_SMALL

Both forms build the same AuditTask (task.py) and run through the same
run_task() -- there is exactly one place that walks M1->M1b->M3->M5.

Целевой файл НЕ копируется в этот репозиторий (лицензионное правило ТЗ) --
только путь передаётся снаружи, аналогично тому, как реальный пользователь
укажет свой checkout wolfSSL.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import json

from pqc_reduction_audit.profile_loader import ProfileError, available_profiles
from pqc_reduction_audit.task import AuditTask, run_task

RESULTS_DIR = Path("results") / "pqc_audit_run"


def _task_from_flags(args: argparse.Namespace) -> AuditTask:
    return AuditTask(
        target_file=args.target,
        include_root=args.include_root,
        function=args.function,
        run_label=args.run_label,
        target_profile=args.target_profile,
        defines=list(args.define or []),
        extra_include=list(args.extra_include or []),
        std=args.std,
        site_order=args.site_order.split(",") if args.site_order else None,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="PQC reduction-placement auditor (M1-M5)")
    parser.add_argument("--task", default=None,
                         help="Путь к файлу задачи (JSON, схема в README) -- Issue #319. "
                              "Взаимоисключающе с --target/--include-root/--function.")
    parser.add_argument("--target", help="Путь к целевому .c файлу (только чтение)")
    parser.add_argument("--include-root", help="Корень include-путей целевого проекта")
    parser.add_argument("--function", default="dilithium_sign_with_seed_mu")
    parser.add_argument("--run-label", default=None)
    parser.add_argument("--define", action="append", default=[], help="Доп. -D макросы (можно несколько раз)")
    parser.add_argument("--extra-include", action="append", default=[],
                         help="Доп. -I пути (можно несколько раз) -- для целей с несколькими include-корнями "
                              "(напр. сгенерированные/сторонние заголовки, не под --include-root)")
    parser.add_argument("--target-profile", default="wolfssl", choices=available_profiles(),
                         help="Набор имён функций (арифметика/редукция/проверка) под целевую кодовую базу -- "
                              "из profiles/<name>.json (Issue #176, файлом -- Issue #320). Новая цель "
                              "подключается новым файлом в profiles/, без правки кода.")
    parser.add_argument("--site-order", default=None,
                         help="Через запятую, порядок известных check-сайтов в этой функции -- переопределяет "
                              "site_order профиля для этого прогона (по умолчанию берётся из profiles/<name>.json)")
    parser.add_argument("--out-dir", default=str(RESULTS_DIR),
                         help="Куда писать отчёт (по умолчанию results/pqc_audit_run). "
                              "Использовать отдельную (например, временную) папку для локального "
                              "воспроизведения эталонного прогона, чтобы не затирать закоммиченный "
                              "эталонный отчёт под тем же run-label (Issue #194 п.2)")
    parser.add_argument("--std", default=None,
                         help="Стандарт языка для clang. По умолчанию берётся из profiles/<name>.json "
                              "(language: c -> c99, cpp -> c++17, Issue #320) -- указывать явно нужно только "
                              "чтобы переопределить профильное значение. Значение, начинающееся с 'c++', "
                              "также включает `-x c++`.")
    args = parser.parse_args()

    if args.task and (args.target or args.include_root):
        parser.error("--task взаимоисключающе с --target/--include-root/--function/--run-label")
    if args.task:
        audit_task = AuditTask.from_file(args.task)
    else:
        if not args.target or not args.include_root or not args.run_label:
            parser.error("без --task нужны --target, --include-root и --run-label")
        audit_task = _task_from_flags(args)

    out_dir = Path(args.out_dir)

    # Warn (not error) if a previous run under the same run-label audited a
    # different version of the target -- Issue #194 п.2: the report is about
    # to be overwritten with a run against different source.
    existing_json = out_dir / f"{audit_task.run_label}.json"
    prev_target_version = None
    if existing_json.exists():
        try:
            prev = json.loads(existing_json.read_text(encoding="utf-8"))
            prev_target_version = (prev.get("target_version") or {}).get("sha256")
        except (json.JSONDecodeError, OSError):
            pass

    try:
        data, json_path, md_path = run_task(audit_task, out_dir)
    except (ProfileError, ValueError) as exc:
        parser.error(str(exc))

    new_sha = (data.get("target_version") or {}).get("sha256")
    if prev_target_version and new_sha and prev_target_version != new_sha:
        print(f"  ⚠ target_version изменился с прошлого прогона под тем же "
              f"run-label {audit_task.run_label!r}: {prev_target_version[:12]} -> "
              f"{new_sha[:12]} -- отчёт был перезаписан")

    print(f"Найдено сайтов check_low: {len(data['sites'])}")
    for site in data["sites"]:
        flag = "ДЕФЕКТ" if site["is_defect"] else "ок"
        print(f"  строка {site['check_call_line']} [{site['label']}]: "
              f"редукция {'есть' if site['reduce_present_in_source'] else 'ОТСУТСТВУЕТ'} -> {flag}")
    print(f"Отчёт: {json_path}, {md_path}")

    known_answer_check = data.get("known_answer_check") or {}
    if known_answer_check.get("declared"):
        if known_answer_check["passed"]:
            print("Самопроверка на известном ответе: PASS")
        else:
            print("Самопроверка на известном ответе: FAIL")
            for m in known_answer_check.get("mismatches", []):
                print(f"  - {m}")
            sys.exit(1)


if __name__ == "__main__":
    main()
