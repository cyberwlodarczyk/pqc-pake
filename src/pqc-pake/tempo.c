#ifdef TEMPO_FLS_LOG_ITER
#include <stdio.h>
#endif
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <kyber/kyber.h>
#include <kyber/polyvec.h>
#include <kyber/symmetric.h>
#include "tempo.h"

#define FLS_ITERATIONS 280
#define FLSX_ITERATIONS 185

static void fls(KYBER_polyvec *a, const uint8_t *seed, int transposed, int n)
{
    xof_state state;
    uint8_t buf[5 * XOF_BLOCKBYTES];
    for (uint8_t y = 0; y < n; y++)
    {
        for (uint8_t x = 0; x < KYBER_K; x++)
        {
            if (transposed)
            {
                KYBER_xof_absorb(&state, seed, y, x);
            }
            else
            {
                KYBER_xof_absorb(&state, seed, x, y);
            }
            KYBER_xof_squeezeblocks(buf, 5, &state);
            int ctr = 0;
#ifdef TEMPO_FLS_LOG_ITER
            int logged = 0;
#endif
            for (int i = 0, buf_i = 0; i < FLS_ITERATIONS; i++, buf_i += 3)
            {
                uint16_t d[2];
                int d_ok[2];
                d[0] = ((buf[buf_i + 0] >> 0) |
                        ((uint16_t)buf[buf_i + 1] << 8)) &
                       0xFFF;
                d[1] = ((buf[buf_i + 1] >> 4) |
                        ((uint16_t)buf[buf_i + 2] << 4)) &
                       0xFFF;
                d_ok[0] = (d[0] < KYBER_Q);
                d_ok[1] = (d[1] < KYBER_Q);
                for (int d_i = 0; d_i < 2; d_i++)
                {
                    int flag = 0;
                    for (int j = 0; j < KYBER_N; j++)
                    {
                        int match = (j == ctr);
                        int mask = match * d_ok[d_i];
                        int16_t *coeffs = a[y].vec[x].coeffs;
                        coeffs[j] = coeffs[j] * (1 - mask) + d[d_i] * mask;
                        flag += mask;
                    }
                    ctr += flag;
                }
#ifdef TEMPO_FLS_LOG_ITER
                if (ctr == KYBER_N && !logged)
                {
                    logged = 1;
                    printf("%d\n", i + 1);
                }
#endif
            }
        }
    }
    OPENSSL_cleanse(&state, sizeof(xof_state));
    OPENSSL_cleanse(buf, 5 * XOF_BLOCKBYTES);
}

static int flsx(KYBER_polyvec *a, const uint8_t *seed, int transposed, int n)
{
    xof_state state;
    uint8_t buf[5 * XOF_BLOCKBYTES];
    int fail = 0;
    for (uint8_t y = 0; y < n; y++)
    {
        for (uint8_t x = 0; x < KYBER_K; x++)
        {
            if (transposed)
            {
                KYBER_xof_absorb(&state, seed, y, x);
            }
            else
            {
                KYBER_xof_absorb(&state, seed, x, y);
            }
            KYBER_xof_squeezeblocks(buf, 5, &state);
            int ctr = 0;
            for (int i = 0, buf_i = 0; i < FLSX_ITERATIONS; i++, buf_i += 3)
            {
                uint16_t d[2];
                int d_ok[2];
                d[0] = ((buf[buf_i + 0] >> 0) |
                        ((uint16_t)buf[buf_i + 1] << 8)) &
                       0xFFF;
                d[1] = ((buf[buf_i + 1] >> 4) |
                        ((uint16_t)buf[buf_i + 2] << 4)) &
                       0xFFF;
                d_ok[0] = (d[0] < KYBER_Q);
                d_ok[1] = (d[1] < KYBER_Q);
                for (int d_i = 0; d_i < 2; d_i++)
                {
                    int flag = 0;
                    for (int j = 0; j < KYBER_N; j++)
                    {
                        int match = (j == ctr);
                        int mask = match * d_ok[d_i];
                        int16_t *coeffs = a[y].vec[x].coeffs;
                        coeffs[j] = coeffs[j] * (1 - mask) + d[d_i] * mask;
                        flag += mask;
                    }
                    ctr += flag;
                }
            }
            fail |= ctr < KYBER_N;
        }
    }
    OPENSSL_cleanse(&state, sizeof(xof_state));
    OPENSSL_cleanse(buf, 5 * XOF_BLOCKBYTES);
    return !fail - 1;
}

void TEMPO_gen_matrix_fls(
    KYBER_polyvec *a,
    const uint8_t *seed,
    int tranposed)
{
    fls(a, seed, tranposed, KYBER_K);
}

int TEMPO_gen_matrix_flsx(
    KYBER_polyvec *a,
    const uint8_t *seed,
    int tranposed)
{
    return flsx(a, seed, tranposed, KYBER_K);
}

#ifdef TEMPO_USE_FLSX
static int hash_1(
    KYBER_polyvec *r,
    const TEMPO_session sess,
    const uint8_t *seed,
    const uint8_t *r_seed)
#else
static void hash_1(
    KYBER_polyvec *r,
    const TEMPO_session sess,
    const uint8_t *seed,
    const uint8_t *r_seed)
#endif
{
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, (uint8_t *)&sess.fsid, sizeof(TEMPO_fsid));
    shake256_absorb(&state, sess.password, KYBER_LEN_SEED);
    shake256_absorb(&state, seed, KYBER_LEN_SEED);
    shake256_absorb(&state, r_seed, TEMPO_LEN_3LAMBDA);
    uint8_t hash[KYBER_LEN_SEED];
    shake256_squeeze(hash, KYBER_LEN_SEED, &state);
#ifdef TEMPO_USE_FLSX
    int ret = flsx(r, hash, 0, 1);
#else
    fls(r, hash, 0, 1);
#endif
    OPENSSL_cleanse(&state, sizeof(keccak_state));
    OPENSSL_cleanse(hash, KYBER_LEN_SEED);
#ifdef TEMPO_USE_FLSX
    return ret;
#endif
}

static void hash_2(
    uint8_t *v_hash,
    const TEMPO_session sess,
    const uint8_t *seed,
    const uint8_t *v_buf)
{
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, (uint8_t *)&sess.fsid, sizeof(TEMPO_fsid));
    shake256_absorb(&state, sess.password, KYBER_LEN_SEED);
    shake256_absorb(&state, seed, KYBER_LEN_SEED);
    shake256_absorb(&state, v_buf, KYBER_LEN_POLYVEC);
    shake256_squeeze(v_hash, TEMPO_LEN_3LAMBDA, &state);
    OPENSSL_cleanse(&state, sizeof(keccak_state));
}

static void hash_key(
    uint8_t *tag,
    uint8_t *shared_secret,
    const TEMPO_session sess,
    const uint8_t *public_key,
    const TEMPO_apk *apk,
    const uint8_t *ciphertext,
    const uint8_t *key)
{
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, (uint8_t *)&sess.fsid, sizeof(TEMPO_fsid));
    shake256_absorb(&state, sess.password, KYBER_LEN_SEED);
    shake256_absorb(&state, public_key, KYBER_LEN_PUBLIC_KEY);
    shake256_absorb(&state, (uint8_t *)apk, sizeof(TEMPO_apk));
    shake256_absorb(&state, ciphertext, KYBER_LEN_CIPHERTEXT);
    shake256_absorb(&state, key, KYBER_LEN_SHARED_SECRET);
    shake256_squeeze(tag, TEMPO_LEN_TAG, &state);
    shake256_squeeze(shared_secret, TEMPO_LEN_LAMBDA, &state);
    OPENSSL_cleanse(&state, sizeof(keccak_state));
}

void TEMPO_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    TEMPO_apk *apk,
    const TEMPO_session sess)
{
    KYBER_keygen(public_key, secret_key);
    uint8_t poly[KYBER_LEN_POLYVEC];
    memcpy(apk->seed, public_key + KYBER_LEN_POLYVEC, KYBER_LEN_SEED);
    memcpy(poly, public_key, KYBER_LEN_POLYVEC);
    uint8_t r_seed[TEMPO_LEN_3LAMBDA];
    KYBER_polyvec r;
#ifdef TEMPO_USE_FLSX
    int ret = -1;
    while (ret == -1)
    {
        RAND_bytes(r_seed, TEMPO_LEN_3LAMBDA);
        ret = hash_1(&r, sess, apk->seed, r_seed);
    }
#else
    RAND_bytes(r_seed, TEMPO_LEN_3LAMBDA);
    hash_1(&r, sess, apk->seed, r_seed);
#endif
    KYBER_polyvec t;
    KYBER_polyvec_frombytes(&t, poly);
    KYBER_polyvec v;
    KYBER_polyvec_add(&v, &t, &r);
    KYBER_polyvec_reduce(&v);
    KYBER_polyvec_tobytes(apk->v, &v);
    uint8_t v_hash[TEMPO_LEN_3LAMBDA];
    hash_2(v_hash, sess, apk->seed, apk->v);
    for (int i = 0; i < TEMPO_LEN_3LAMBDA; i++)
    {
        apk->u[i] = v_hash[i] ^ r_seed[i];
    }
    OPENSSL_cleanse(poly, KYBER_LEN_POLYVEC);
    OPENSSL_cleanse(&r, sizeof(KYBER_polyvec));
    OPENSSL_cleanse(&t, sizeof(KYBER_polyvec));
    OPENSSL_cleanse(r_seed, TEMPO_LEN_3LAMBDA);
    OPENSSL_cleanse(v_hash, TEMPO_LEN_3LAMBDA);
}

#if defined(TEMPO_USE_FLSX) || defined(TEMPO_ENCAPS_FORCE_DUMMY)
KYBER_polyvec r_dummy = {{{{2978, 670, 904, 2543, 2246, 1739, 3200, 124, 2752, 2607, 637, 1721, 172, 1023, 1736, 1205, 1151, 1921, 2990, 2063, 1980, 2378, 1176, 839, 2758, 3165, 1669, 1256, 335, 2013, 486, 1675, 1438, 1838, 3172, 1505, 3172, 2946, 2984, 3019, 400, 2763, 2798, 1710, 424, 2717, 1566, 2886, 3056, 1951, 3235, 1427, 2678, 3084, 780, 2575, 966, 1087, 330, 660, 1614, 1544, 1992, 2450, 1354, 2923, 1699, 2544, 1323, 1528, 1306, 2173, 83, 572, 559, 2300, 1494, 1862, 1328, 272, 2739, 1327, 148, 906, 89, 190, 1495, 1326, 216, 946, 853, 793, 1797, 1760, 967, 3107, 968, 105, 994, 2767, 2544, 1695, 2913, 1127, 346, 2074, 704, 1911, 2037, 2922, 3065, 2699, 960, 2000, 1277, 687, 1429, 1855, 1990, 3179, 341, 3287, 2405, 930, 1688, 3196, 2786, 3225, 2321, 3324, 1098, 997, 2472, 2992, 3324, 1301, 1396, 283, 3170, 3213, 1063, 3153, 1227, 1018, 3104, 2416, 226, 1798, 1544, 1265, 1066, 188, 595, 1810, 1001, 575, 1851, 1867, 203, 690, 1497, 2047, 2369, 2559, 3182, 861, 2433, 710, 1075, 2640, 1351, 2777, 1016, 1020, 393, 2037, 71, 1494, 2552, 1035, 2148, 2672, 2318, 3320, 1058, 1251, 1524, 280, 448, 355, 2585, 3168, 3320, 2271, 1955, 277, 91, 2336, 606, 979, 802, 205, 2589, 2493, 3033, 3023, 1552, 2046, 1732, 1626, 2249, 3073, 545, 529, 677, 1106, 2602, 2494, 3137, 700, 1671, 209, 586, 2480, 282, 3114, 1768, 2985, 2280, 78, 3079, 665, 248, 2502, 2621, 3184, 1611, 1291, 1292, 1189, 40, 1046, 2491, 2723, 2329, 2786, 2530, 2271, 1285, 1753, 570, 368, 2350, 2025, 3252, 120}},
                          {{2001, 1956, 783, 786, 809, 948, 1417, 2629, 1565, 686, 2399, 233, 2504, 1373, 1382, 3086, 631, 2068, 1563, 601, 1955, 1407, 1538, 2358, 2589, 491, 1529, 3110, 2946, 818, 902, 2829, 1132, 691, 2313, 1464, 1808, 2514, 256, 285, 2858, 1390, 80, 2864, 1609, 1901, 3029, 604, 2423, 1004, 3177, 373, 1901, 1645, 1963, 2339, 1870, 654, 1535, 880, 446, 2295, 1569, 2177, 1013, 1312, 504, 3120, 218, 2925, 2263, 1193, 2263, 2422, 2597, 612, 506, 1088, 173, 2575, 2404, 1117, 2359, 2470, 2917, 2395, 1952, 404, 229, 2765, 903, 1306, 2134, 3064, 476, 903, 2685, 977, 972, 2724, 463, 1938, 2474, 2990, 2025, 2674, 619, 3057, 2121, 1225, 130, 70, 848, 748, 2949, 1522, 171, 2234, 2184, 222, 640, 473, 2245, 2162, 92, 1900, 1549, 2635, 2385, 1286, 176, 1798, 1107, 1926, 2758, 1825, 1507, 989, 1421, 238, 188, 2576, 873, 982, 3218, 1997, 1748, 1073, 621, 1329, 171, 1487, 1095, 3239, 50, 2578, 2373, 877, 1597, 3212, 2201, 305, 2357, 854, 2248, 121, 3298, 1571, 1041, 3220, 945, 1878, 600, 2456, 492, 2763, 2613, 1798, 3319, 3066, 1975, 1103, 903, 2516, 247, 2662, 1893, 3323, 2122, 1589, 1957, 276, 1357, 1430, 1753, 640, 2479, 85, 631, 2564, 3254, 2939, 1505, 558, 1318, 614, 2245, 340, 1008, 2327, 3288, 2338, 1601, 2562, 1750, 78, 1815, 1126, 1801, 706, 2175, 3126, 3255, 2151, 2370, 755, 2215, 1621, 3003, 890, 1760, 775, 1416, 2650, 1541, 2062, 550, 1974, 497, 968, 453, 1510, 2645, 670, 721, 3146, 1194, 3101, 1666, 2409, 3309, 2774, 942, 2211, 1221, 32}},
                          {{2007, 1869, 623, 240, 2606, 1366, 1048, 2020, 1040, 1761, 2064, 644, 2476, 2687, 932, 2686, 1667, 1739, 2217, 1749, 1287, 379, 1325, 3127, 695, 2026, 2142, 1518, 1587, 2739, 1086, 2868, 2317, 1769, 2396, 1869, 2459, 1445, 3278, 3009, 2342, 251, 3165, 2472, 2415, 1648, 3258, 119, 2797, 3076, 992, 2293, 1787, 3093, 1680, 1140, 1265, 2620, 408, 2416, 71, 2676, 1708, 748, 1070, 536, 377, 2686, 2017, 1562, 940, 2439, 690, 2044, 924, 1043, 446, 1705, 1063, 1872, 2892, 1121, 459, 1823, 1945, 508, 627, 269, 2515, 2004, 2526, 113, 1291, 2197, 3051, 221, 2766, 2249, 2033, 1756, 2091, 1180, 2691, 1807, 842, 1490, 1213, 3214, 963, 2325, 1931, 1141, 2252, 1554, 496, 1252, 2027, 898, 1896, 1764, 1939, 2884, 250, 3293, 173, 3148, 1777, 2736, 3219, 877, 2690, 2263, 301, 1564, 478, 913, 3011, 1081, 3245, 1936, 2612, 108, 2439, 325, 329, 2665, 2495, 1559, 25, 54, 1575, 1415, 1821, 640, 291, 195, 2378, 760, 799, 934, 2407, 1576, 2232, 416, 2299, 2492, 3267, 2401, 3186, 1395, 2035, 3119, 658, 1516, 929, 2221, 613, 3248, 98, 1480, 140, 2881, 1984, 3074, 581, 1099, 1388, 2830, 1709, 1185, 2995, 551, 865, 1970, 3309, 2324, 2923, 1373, 1757, 196, 1951, 2061, 725, 3315, 2829, 1565, 737, 1214, 3204, 891, 1162, 746, 1629, 235, 939, 1123, 149, 3247, 2685, 3309, 2901, 2095, 3274, 2393, 1074, 3234, 2233, 2874, 514, 2367, 1504, 2518, 1991, 2376, 1534, 366, 2660, 2933, 1113, 409, 828, 162, 2682, 1486, 2004, 1324, 39, 2758, 588, 2087, 2694, 2664, 2836, 894, 747, 220}}}};
#endif

void TEMPO_encaps(uint8_t *ciphertext, uint8_t *tag, uint8_t *shared_secret, const TEMPO_session sess, const TEMPO_apk *apk)
{
    uint8_t v_hash[TEMPO_LEN_3LAMBDA];
    hash_2(v_hash, sess, apk->seed, apk->v);
    uint8_t r_seed[TEMPO_LEN_3LAMBDA];
    for (int i = 0; i < TEMPO_LEN_3LAMBDA; i++)
    {
        r_seed[i] = v_hash[i] ^ apk->u[i];
    }
    KYBER_polyvec r;
    int dummy;
#ifdef TEMPO_USE_FLSX
    dummy = hash_1(&r, sess, apk->seed, r_seed) == -1;
#elif defined(TEMPO_ENCAPS_FORCE_DUMMY)
    hash_1(&r, sess, apk->seed, r_seed);
#endif
#ifdef TEMPO_ENCAPS_FORCE_DUMMY
    dummy = 1;
#endif
#if defined(TEMPO_USE_FLSX) || defined(TEMPO_ENCAPS_FORCE_DUMMY)
    for (int i = 0; i < KYBER_K; i++)
    {
        for (int j = 0; j < KYBER_N; j++)
        {
            r.vec[i].coeffs[j] = (1 - dummy) * r.vec[i].coeffs[j] +
                                 dummy * r_dummy.vec[i].coeffs[j];
        }
    }
#else
    hash_1(&r, sess, apk->seed, r_seed);
#endif
    KYBER_polyvec v;
    KYBER_polyvec_frombytes(&v, apk->v);
    KYBER_polyvec t;
    KYBER_polyvec_sub(&t, &v, &r);
    KYBER_polyvec_reduce(&t);
    uint8_t poly[KYBER_LEN_POLYVEC];
    KYBER_polyvec_tobytes(poly, &t);
    uint8_t public_key[KYBER_LEN_PUBLIC_KEY];
    memcpy(public_key + KYBER_LEN_POLYVEC, apk->seed, KYBER_LEN_SEED);
    memcpy(public_key, poly, KYBER_LEN_POLYVEC);
    uint8_t key[KYBER_LEN_SHARED_SECRET];
    KYBER_encaps(ciphertext, key, public_key);
    hash_key(
        tag,
        shared_secret,
        sess,
        public_key,
        apk,
        ciphertext,
        key);
    OPENSSL_cleanse(key, KYBER_LEN_SHARED_SECRET);
    OPENSSL_cleanse(public_key, KYBER_LEN_PUBLIC_KEY);
    OPENSSL_cleanse(poly, KYBER_LEN_POLYVEC);
    OPENSSL_cleanse(&r, sizeof(KYBER_polyvec));
    OPENSSL_cleanse(&t, sizeof(KYBER_polyvec));
    OPENSSL_cleanse(v_hash, TEMPO_LEN_3LAMBDA);
    OPENSSL_cleanse(r_seed, TEMPO_LEN_3LAMBDA);
}

void TEMPO_decaps(
    uint8_t *shared_secret,
    const TEMPO_session sess,
    const TEMPO_apk *apk,
    const uint8_t *ciphertext,
    const uint8_t *tag,
    const uint8_t *public_key,
    const uint8_t *secret_key)
{
    uint8_t key[KYBER_LEN_SHARED_SECRET];
    KYBER_decaps(key, ciphertext, secret_key);
    uint8_t local_tag[TEMPO_LEN_TAG];
    uint8_t real_shared_secret[TEMPO_LEN_LAMBDA];
    hash_key(
        local_tag,
        real_shared_secret,
        sess,
        public_key,
        apk,
        ciphertext,
        key);
    uint8_t alt_shared_secret[TEMPO_LEN_LAMBDA];
    RAND_bytes(alt_shared_secret, TEMPO_LEN_LAMBDA);
    if (CRYPTO_memcmp(local_tag, tag, TEMPO_LEN_TAG) != 0)
    {
        memcpy(shared_secret, alt_shared_secret, TEMPO_LEN_LAMBDA);
    }
    else
    {
        memcpy(shared_secret, real_shared_secret, TEMPO_LEN_LAMBDA);
    }
    OPENSSL_cleanse(key, KYBER_LEN_SHARED_SECRET);
    OPENSSL_cleanse(alt_shared_secret, TEMPO_LEN_LAMBDA);
    OPENSSL_cleanse(real_shared_secret, TEMPO_LEN_LAMBDA);
}
