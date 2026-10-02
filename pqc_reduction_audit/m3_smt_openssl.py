"""
M3 (второй таргет, Issue #153) — формальное (Z3, не перебор) подтверждение
инварианта "reduce_once/mod_sub/reduce_montgomery на OpenSSL 3.5 ВСЕГДА
возвращают каноническое значение [0,Q)", в отличие от m3_smt.py (wolfSSL),
которое доказывает "расходится ли check_low на сыром и редуцированном значении"
-- в OpenSSL сырого значения не существует (m2_bounds_openssl.py), поэтому
здесь проверяется сам инвариант, а не расхождение до/после.

unsat для ОТРИЦАНИЯ инварианта = инвариант выполняется всегда = на местах-
кандидатах (ml_dsa_sign.c:178, :187) нередуцированное значение не может
возникнуть -> класс дефекта (редукция как отдельный, пропускаемый шаг) не
имеет поверхности проявления.
"""
from __future__ import annotations

from dataclasses import dataclass

import z3

from pqc_reduction_audit.constants import Q


@dataclass
class InvariantCertificate:
    claim: str
    negation_check: str   # "unsat" => invariant always holds
    invariant_holds: bool
    smt_lib2: str


def _prove_always_canonical(claim: str, free_vars: list[z3.ArithRef],
                             domain_constraints, result_expr) -> InvariantCertificate:
    solver = z3.Solver()
    solver.set("timeout", 30000)
    solver.add(*domain_constraints)
    solver.add(z3.Or(result_expr < 0, result_expr >= Q))  # negation of "always in [0,Q)"
    smt_lib2 = solver.to_smt2()
    result = solver.check()
    return InvariantCertificate(
        claim=claim,
        negation_check=str(result),
        invariant_holds=(str(result) == "unsat"),
        smt_lib2=smt_lib2,
    )


def prove_mod_sub_always_canonical() -> InvariantCertificate:
    """mod_sub(a,b) = reduce_once(Q+a-b) for a,b in [0,Q) -- ml_dsa_local.h:112,128."""
    a, b = z3.Ints("a b")
    pre_reduce = Q + a - b
    result = z3.If(pre_reduce < Q, pre_reduce, pre_reduce - Q)
    return _prove_always_canonical(
        "mod_sub(a,b) for a,b in [0,Q) is always in [0,Q)",
        [a, b], [a >= 0, a < Q, b >= 0, b < Q], result,
    )


def prove_reduce_montgomery_final_step_always_canonical() -> InvariantCertificate:
    """reduce_once(c) for c in [0,2Q), the final step of reduce_montgomery -- ml_dsa_ntt.c:93-99."""
    c = z3.Int("c")
    result = z3.If(c < Q, c, c - Q)
    return _prove_always_canonical(
        "reduce_once(c) for c in [0,2Q) (reduce_montgomery's final step) is always in [0,Q)",
        [c], [c >= 0, c < 2 * Q], result,
    )


if __name__ == "__main__":
    for cert in (prove_mod_sub_always_canonical(),
                 prove_reduce_montgomery_final_step_always_canonical()):
        print(f"{cert.claim}: negation_check={cert.negation_check} "
              f"=> invariant_holds={cert.invariant_holds}")
