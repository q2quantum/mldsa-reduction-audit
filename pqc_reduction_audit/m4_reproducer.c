/*
 * M4 -- C-репродьюсер (Issue #153, техзадание на суперэксперта №3, PQC_IMP_SW).
 *
 * Демонстрирует расхождение dilithium_check_low() на "сыром" значении после
 * dilithium_invntt (гарантированный диапазон (-Q,Q) по свойству Montgomery-
 * редукции) против того же значения, дополнительно пропущенного через
 * dilithium_red (Barrett) -- ровно так, как это делает путь z = y + cs1
 * (dilithium_poly_red вызывается, wolfcrypt/src/dilithium.c ~8358-8364), но
 * НЕ делает путь w0 = w - cs2 (dilithium_poly_red отсутствует, ~8347-8353).
 *
 * Формулы dilithium_red/dilithium_check_low транскрибированы дословно из
 * wolfSSL/wolfssl, wolfcrypt/src/dilithium.c (ветка v5.9.0-stable):
 *   - dilithium_red:        строки 5469-5477
 *   - dilithium_check_low:  строки 4844-4859
 * Целевой код -- вход, только чтение (лицензионное правило ТЗ: GPL wolfSSL
 * не встраивается в продукт). Этот файл НЕ содержит и не линкует код
 * wolfSSL -- только собственную транскрипцию арифметики для верификации.
 *
 * ПРИМЕЧАНИЕ О СРЕДЕ: в песочнице, где готовился этот аудит, нет установленного
 * C/C++ компилятора (то же ограничение, что и у PySCF для химического домена,
 * см. Issue #153 п.2) -- этот файл не был скомпилирован в рамках данной сессии.
 * Эквивалентная арифметика (те же целочисленные операции, та же модель) была
 * прогнана и формально доказана через Z3 (pqc_reduction_audit/m3_smt.py) и
 * перепроверена на 200 000 случайных значений в Python
 * (pqc_reduction_audit/m2_bounds.py) -- см. results/pqc_audit_run/report.md.
 * Скомпилировать и прогнать этот файл на машине с gcc/clang -- следующий шаг
 * перед тем, как считать критерий экзамена №3 (независимый прогон) закрытым
 * буквально "в C", а не только в эквивалентной модели.
 */
#include <stdio.h>
#include <stdint.h>

typedef int32_t sword32;
typedef int64_t sword64;

#define DILITHIUM_Q 8380417

/* Дословно wolfcrypt/src/dilithium.c:5469-5477 */
static sword32 dilithium_red(sword32 a) {
    sword32 t = (sword32)((a + ((sword32)1 << 22)) >> 23);
    return (sword32)(a - (t * DILITHIUM_Q));
}

/* Дословно wolfcrypt/src/dilithium.c:4844-4859 */
static int dilithium_check_low(sword32 a, sword32 hi) {
    sword32 nhi = -hi;
    return !((a <= nhi) || (a >= hi));
}

int main(void) {
    /* HI_W0 = GAMMA2 - BETA = (Q-1)/88 - 39*2 = 95232 - 78 = 95154 (ML-DSA-44) */
    const sword32 HI_W0 = 95154;
    /* Witness, найден формальным доказательством в Z3 (m3_smt.py): SAT при
     * a = -(Q-1). Гарантированный диапазон после dilithium_mont_red -- (-Q,Q),
     * -(Q-1) -- крайнее значение этого диапазона, не экзотика. */
    sword32 witness = -(DILITHIUM_Q - 1);

    int raw_pass = dilithium_check_low(witness, HI_W0);
    sword32 reduced = dilithium_red(witness);
    int reduced_pass = dilithium_check_low(reduced, HI_W0);

    printf("witness (raw value after invntt, no poly_red): %d\n", witness);
    printf("check_low(raw, HI_W0)      = %s\n", raw_pass ? "PASS" : "FAIL");
    printf("dilithium_red(witness)      = %d\n", reduced);
    printf("check_low(red(witness), HI_W0) = %s\n", reduced_pass ? "PASS" : "FAIL");

    if (raw_pass != reduced_pass) {
        printf("\nMISMATCH: w0-path (no poly_red) would %s a candidate that "
               "z-path's reduction would have %s.\n",
               raw_pass ? "ACCEPT" : "REJECT",
               reduced_pass ? "ACCEPTED" : "REJECTED");
        printf("This is a real disagreement -- the omitted reduction is "
               "NECESSARY, not redundant (matches SAT verdict from M3).\n");
        return 1;
    }
    printf("\nNo mismatch for this witness.\n");
    return 0;
}
