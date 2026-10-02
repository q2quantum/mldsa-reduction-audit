"""
M3 — SMT-LIB2 генератор сертификатов (Z3, дефолтные тактики).

Формализует и ФОРМАЛЬНО доказывает (не перебором отдельных значений, как в
M2, а по всему диапазону сразу) вопрос: расходится ли dilithium_check_low()
на сыром значении после dilithium_invntt (диапазон (-Q,Q), гарантированный
dilithium_mont_red) и на том же значении, дополнительно пропущенном через
dilithium_red (Barrett) — как это делает путь z = y + cs1 (dilithium_poly_red
вызывается) в отличие от пути w0 = w - cs2 (не вызывается).

sat  = разошлись -> редукция НЕСУЩАЯ (не избыточна, есть свидетель)
unsat = никогда не расходятся -> редукция ИЗБЫТОЧНА
"""
from __future__ import annotations

from dataclasses import dataclass

import z3

from pqc_reduction_audit.constants import Q


@dataclass
class Certificate:
    site_name: str
    hi: int
    verdict: str          # "sat" (несущая) | "unsat" (избыточна)
    witness: dict | None  # значения a, raw_result, reduced_result при sat
    smt_lib2: str          # текст запроса в формате SMT-LIB2 (для приложения к отчёту)


def build_reduction_necessity_certificate(site_name: str, hi: int) -> Certificate:
    """Формально проверяет: exists a in (-Q,Q): check_low(a,hi) != check_low(red(a),hi)."""
    a = z3.Int("a")
    q_const = z3.IntVal(Q)
    two22 = z3.IntVal(1 << 22)

    # dilithium_check_low(x, hi): проходит, если -hi < x < hi (строго,
    # src/dilithium.c:4844-4859)
    def check_low(x):
        return z3.And(x > -hi, x < hi)

    t = (a + two22) / (1 << 23)
    reduced = a - t * q_const

    raw_pass = check_low(a)
    reduced_pass = check_low(reduced)

    solver = z3.Solver()
    solver.set("timeout", 30000)
    # Диапазон a гарантирован dilithium_mont_red (M2: 200 000 случайных
    # проверок, 0 выходов за (-Q,Q); свойство Монтгомери-редукции для этого
    # модуля и битности -- см. src/dilithium.c:5440).
    solver.add(a > -Q, a < Q)
    solver.add(raw_pass != reduced_pass)

    smt_lib2 = solver.to_smt2()
    result = solver.check()

    witness = None
    if result == z3.sat:
        m = solver.model()
        a_val = m[a].as_long()
        red_val = (a_val - ((a_val + (1 << 22)) // (1 << 23)) * Q)
        witness = {
            "a": a_val,
            "check_low_raw": bool(-hi < a_val < hi),
            "check_low_reduced": bool(-hi < red_val < hi),
            "reduced_value": red_val,
        }

    return Certificate(
        site_name=site_name,
        hi=hi,
        verdict=str(result),
        witness=witness,
        smt_lib2=smt_lib2,
    )
