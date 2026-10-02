"""
M2 — Движок целочисленных границ (интервальная арифметика).

Реализует ровно те функции, что реально определены в целевом исходнике
(wolfcrypt/src/dilithium.c, ветка v5.9.0-stable, wolfSSL/wolfssl) —
транскрибированы дословно по формуле, с цитатой строки, НЕ переизобретены:

- dilithium_mont_red   (src/dilithium.c:5440)  — Montgomery reduction
- dilithium_red        (src/dilithium.c:5469)  — Barrett-style reduction
- dilithium_check_low  (src/dilithium.c:4844)  — диапазонная проверка (сырое
                                                   целочисленное сравнение,
                                                   БЕЗ приведения по модулю)

Задача M2: классифицировать место редукции (после dilithium_invntt, перед
dilithium_vec_check_low) как избыточное или несущее — сравнивая результат
check_low на СЫРОМ значении против check_low на значении, дополнительно
пропущенном через dilithium_red.
"""
from __future__ import annotations

from pqc_reduction_audit.constants import Q, QINV


def _to_s32(x: int) -> int:
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x & 0x80000000 else x


def dilithium_mont_red(a: int) -> int:
    """Montgomery reduction — дословно src/dilithium.c:5440-5450
    (DILITHIUM_MUL_QINV_SLOW/DILITHIUM_MUL_Q_SLOW не определены, основной путь).
    Python `>>` на отрицательных int эквивалентен арифметическому сдвигу C
    для sword64 (floor-деление на степень двойки) -- проверено регресс-тестом."""
    t = _to_s32(_to_s32(a) * _to_s32(QINV))
    result64 = a - t * Q
    return result64 >> 32


def dilithium_red(a: int) -> int:
    """Barrett-style reduction — дословно src/dilithium.c:5469-5477."""
    t = (a + (1 << 22)) >> 23
    return a - t * Q


def dilithium_check_low(a: int, hi: int) -> bool:
    """Дословно src/dilithium.c:4844-4859: проходит, если -hi < a < hi (строго)."""
    nhi = -hi
    return not (a <= nhi or a >= hi)


def reduction_is_redundant(sample_values: list[int], hi: int) -> tuple[bool, list[tuple[int, bool, bool]]]:
    """Перебирает конкретные значения (для быстрой докидки перед полным SMT-
    доказательством в M3) и проверяет, расходится ли check_low на сыром
    значении и на редуцированном. Возвращает (redundant_on_samples, детали).
    Полное доказательство по ВСЕМ значениям диапазона — задача M3 (Z3)."""
    details = []
    redundant = True
    for a in sample_values:
        raw_pass = dilithium_check_low(a, hi)
        red_pass = dilithium_check_low(dilithium_red(a), hi)
        if raw_pass != red_pass:
            redundant = False
        details.append((a, raw_pass, red_pass))
    return redundant, details
