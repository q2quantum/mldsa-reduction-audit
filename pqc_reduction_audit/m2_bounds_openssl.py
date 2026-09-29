"""
M2 (второй таргет, Issue #153) — те же функции, что и m2_bounds.py, но
транскрибированные дословно по формуле из openssl/openssl, ветка openssl-3.5,
crypto/ml_dsa/:

- reduce_once      (ml_dsa_local.h:112)   — редукция по модулю, вход [0,2Q)
- mod_sub          (ml_dsa_local.h:128)   — (Q + a - b) затем reduce_once
- reduce_montgomery(ml_dsa_ntt.c:93)      — Montgomery-редукция, вход 0..(2^32)*Q

В отличие от wolfSSL (m2_bounds.py: dilithium_mont_red/dilithium_red — редукция
вызывается ОТДЕЛЬНО от арифметики и не на всех путях), здесь reduce_once /
reduce_montgomery вызываются БЕЗУСЛОВНО внутри самой функции вычитания/NTT^-1 —
нет пути, который производит значение без его же редукции. Задача этого модуля —
не "избыточна ли редукция", а формально подтвердить: существует ли вообще
нередуцированное («сырое») значение на выходе poly_sub / vector_ntt_inverse.
Ответ (см. m3_smt_openssl.py) — нет, по построению.
"""
from __future__ import annotations

from pqc_reduction_audit.constants import Q


def reduce_once(x: int) -> int:
    """Дословно ml_dsa_local.h:112-115: x < Q ? x : x - Q. Домен x: [0, 2Q)."""
    return x if x < Q else x - Q


def mod_sub(a: int, b: int) -> int:
    """Дословно ml_dsa_local.h:128-131: reduce_once(Q + a - b). Домен a,b: [0,Q)."""
    return reduce_once(Q + a - b)


def reduce_montgomery_final_step(c: int) -> int:
    """Дословно ml_dsa_ntt.c:93-99, только финальный шаг c=b>>32 (0..2Q) -> reduce_once(c).
    Полная функция берёт uint64 a в домене 0..(2^32)*Q; здесь моделируется
    именно этап, гарантирующий каноничность выхода (c уже в 0..2Q по комментарию
    исходника, ml_dsa_ntt.c:97)."""
    return reduce_once(c)
