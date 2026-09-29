"""
Реальные константы ML-DSA-44 (FIPS 204 + wolfSSL wolfcrypt/dilithium.h,
ветка v5.9.0-stable) — используются M2/M3/M4 для интервальной арифметики и
SMT-сертификатов. Не переизобретены — взяты из первоисточника (см. ссылки
в docstring каждой константы).
"""

# wolfcrypt/wolfcrypt/dilithium.h:193 -- DILITHIUM_Q = 0x7fe001
Q = 8380417

# wolfcrypt/wolfcrypt/dilithium.h:259 -- PARAMS_ML_DSA_44_ETA = DILITHIUM_ETA_2
ETA = 2

# wolfcrypt/wolfcrypt/dilithium.h:265 -- PARAMS_ML_DSA_44_TAU
TAU = 39

# BETA = TAU * ETA (dilithium.h:266-268)
BETA = TAU * ETA  # 78

# FIPS 204 Table 1 (ML-DSA-44): GAMMA1 = 2^17
GAMMA1_BITS = 17
GAMMA1 = 1 << GAMMA1_BITS  # 131072

# FIPS 204 Table 1 (ML-DSA-44): GAMMA2 = (Q-1)/88
GAMMA2 = (Q - 1) // 88  # 95232

# Thresholds used by dilithium_vec_check_low() call sites in
# dilithium_sign_with_seed_mu (Step 23 of FIPS 204 Algorithm 2)
HI_Z = GAMMA1 - BETA      # z = y + cs1 threshold
HI_W0 = GAMMA2 - BETA     # w0 = w - cs2 threshold

# q^-1 mod 2^32 (wolfcrypt/src/dilithium.c:5433, DILITHIUM_QINV)
QINV = 58728449
