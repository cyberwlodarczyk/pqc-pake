#include <string.h>
#include <openssl/rand.h>
#include <kyber/kyber.h>
#include <rkem/rkem.h>
#include <rkem/xrkem.h>
#include <pqc-pake/nice_pake.h>
#include <pqc-pake/nice_pake_re.h>
#include <pqc-pake/tempo.h>
#include <pqc-pake/tempo_re.h>

int cmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0 ? 1 : 0;
}

int exchange_kyber()
{
    uint8_t pk[KYBER_LEN_PUBLIC_KEY];
    uint8_t sk[KYBER_LEN_SECRET_KEY];
    KYBER_keygen(pk, sk);
    uint8_t ct[KYBER_LEN_CIPHERTEXT];
    uint8_t ss1[KYBER_LEN_SHARED_SECRET];
    KYBER_encaps(ct, ss1, pk);
    uint8_t ss2[KYBER_LEN_SHARED_SECRET];
    KYBER_decaps(ss2, ct, sk);
    return cmp(ss1, ss2, KYBER_LEN_SHARED_SECRET);
}

int exchange_rkem()
{
    uint8_t pk[RKEM_LEN_PUBLIC_KEY];
    uint8_t sk[RKEM_LEN_SECRET_KEY];
    RKEM_keygen(pk, sk);
    uint8_t seed[RKEM_LEN_SEED];
    RAND_bytes(seed, RKEM_LEN_SEED);
    uint8_t rand_pk[RKEM_LEN_PUBLIC_KEY];
    RKEM_rand(rand_pk, seed, pk);
    uint8_t ct[RKEM_LEN_CIPHERTEXT];
    uint8_t ss1[RKEM_LEN_SHARED_SECRET];
    RKEM_encaps(ct, ss1, rand_pk);
    uint8_t ss2[RKEM_LEN_SHARED_SECRET];
    RKEM_decaps(ss2, ct, sk, seed);
    return cmp(ss1, ss2, RKEM_LEN_SHARED_SECRET);
}

int exchange_xrkem()
{
    uint8_t pk[XRKEM_LEN_PUBLIC_KEY];
    uint8_t sk[XRKEM_LEN_SECRET_KEY];
    XRKEM_keygen(pk, sk);
    uint8_t seed[XRKEM_LEN_SEED];
    RAND_bytes(seed, XRKEM_LEN_SEED);
    uint8_t rand_pk[XRKEM_LEN_PUBLIC_KEY];
    XRKEM_rand(rand_pk, seed, pk);
    uint8_t ct[XRKEM_LEN_CIPHERTEXT];
    uint8_t ss1[XRKEM_LEN_SHARED_SECRET];
    XRKEM_encaps(ct, ss1, rand_pk);
    uint8_t ss2[XRKEM_LEN_SHARED_SECRET];
    XRKEM_decaps(ss2, ct, sk, seed);
    return cmp(ss1, ss2, RKEM_LEN_SHARED_SECRET);
}

int exchange_xrkem_derand()
{
    uint8_t pk[XRKEM_LEN_PUBLIC_KEY];
    uint8_t sk[XRKEM_LEN_SECRET_KEY];
    XRKEM_keygen(pk, sk);
    uint8_t seed[XRKEM_LEN_SEED];
    RAND_bytes(seed, XRKEM_LEN_SEED);
    uint8_t rand_pk[XRKEM_LEN_PUBLIC_KEY];
    XRKEM_rand(rand_pk, seed, pk);
    XRKEM_derand(pk, seed, rand_pk);
    uint8_t ct[XRKEM_LEN_CIPHERTEXT];
    uint8_t ss1[XRKEM_LEN_SHARED_SECRET];
    XRKEM_encaps(ct, ss1, pk);
    uint8_t ss2[XRKEM_LEN_SHARED_SECRET];
    XRKEM_decaps_derand(ss2, ct, sk);
    return cmp(ss1, ss2, RKEM_LEN_SHARED_SECRET);
}

int exchange_nice_pake(const uint8_t *pw1, const uint8_t *pw2)
{
    uint8_t seed[NICE_PAKE_LEN_SEED];
    uint8_t poly[NICE_PAKE_LEN_POLY];
    uint8_t sk[NICE_PAKE_LEN_SECRET_KEY];
    NICE_PAKE_keygen(seed, poly, sk, pw1);
    uint8_t ct[NICE_PAKE_LEN_CIPHERTEXT];
    uint8_t ss1[NICE_PAKE_LEN_SHARED_SECRET];
    NICE_PAKE_encaps(ct, ss1, seed, poly, pw2);
    uint8_t ss2[NICE_PAKE_LEN_SHARED_SECRET];
    NICE_PAKE_decaps(ss2, ct, sk);
    return cmp(ss1, ss2, NICE_PAKE_LEN_SHARED_SECRET);
}

int exchange_nice_pake_correct()
{
    uint8_t password[NICE_PAKE_LEN_PASSWORD];
    RAND_bytes(password, NICE_PAKE_LEN_PASSWORD);
    return exchange_nice_pake(password, password);
}

int exchange_nice_pake_incorrect()
{
    uint8_t password1[NICE_PAKE_LEN_PASSWORD];
    RAND_bytes(password1, NICE_PAKE_LEN_PASSWORD);
    uint8_t password2[NICE_PAKE_LEN_PASSWORD];
    RAND_bytes(password2, NICE_PAKE_LEN_PASSWORD);
    return !exchange_nice_pake(password1, password2);
}

int exchange_nice_pake_re(const uint8_t *pw1, const uint8_t *pw2)
{
    uint8_t seed_a[NICE_PAKE_RE_LEN_SEED];
    uint8_t poly[NICE_PAKE_RE_LEN_POLY];
    uint8_t sk[NICE_PAKE_RE_LEN_SECRET_KEY];
    NICE_PAKE_RE_keygen(seed_a, poly, sk, pw1);
    uint8_t seed_b[NICE_PAKE_RE_LEN_SEED];
    uint8_t ct[NICE_PAKE_RE_LEN_CIPHERTEXT];
    uint8_t ss1[NICE_PAKE_RE_LEN_SHARED_SECRET];
    NICE_PAKE_RE_encaps(seed_b, ct, ss1, seed_a, poly, pw2);
    uint8_t ss2[NICE_PAKE_RE_LEN_SHARED_SECRET];
    NICE_PAKE_RE_decaps(ss2, seed_b, ct, sk, pw1);
    return cmp(ss1, ss2, NICE_PAKE_RE_LEN_SHARED_SECRET);
}

int exchange_nice_pake_re_correct()
{
    uint8_t password[NICE_PAKE_RE_LEN_PASSWORD];
    RAND_bytes(password, NICE_PAKE_RE_LEN_PASSWORD);
    return exchange_nice_pake_re(password, password);
}

int exchange_nice_pake_re_incorrect()
{
    uint8_t password1[NICE_PAKE_RE_LEN_PASSWORD];
    RAND_bytes(password1, NICE_PAKE_RE_LEN_PASSWORD);
    uint8_t password2[NICE_PAKE_RE_LEN_PASSWORD];
    RAND_bytes(password2, NICE_PAKE_RE_LEN_PASSWORD);
    return !exchange_nice_pake_re(password1, password2);
}

int exchange_tempo(const uint8_t *pw1, const uint8_t *pw2)
{
    uint8_t pk[TEMPO_LEN_PUBLIC_KEY];
    uint8_t sk[TEMPO_LEN_SECRET_KEY];
    TEMPO_apk apk;
    TEMPO_fsid fsid;
    fsid.sid = 100;
    fsid.a = 1;
    fsid.b = 2;
    TEMPO_session sess1;
    sess1.fsid = fsid;
    sess1.password = pw1;
    TEMPO_keygen(pk, sk, &apk, sess1);
    uint8_t ct[TEMPO_LEN_CIPHERTEXT];
    uint8_t tag[TEMPO_LEN_TAG];
    uint8_t ss1[TEMPO_LEN_SHARED_SECRET];
    TEMPO_session sess2;
    sess2.fsid = fsid;
    sess2.password = pw2;
    TEMPO_encaps(ct, tag, ss1, sess2, &apk);
    uint8_t ss2[TEMPO_LEN_SHARED_SECRET];
    TEMPO_decaps(ss2, sess1, &apk, ct, tag, pk, sk);
    return cmp(ss1, ss2, TEMPO_LEN_SHARED_SECRET);
}

int exchange_tempo_correct()
{
    uint8_t password[TEMPO_LEN_PASSWORD];
    RAND_bytes(password, TEMPO_LEN_PASSWORD);
    return exchange_tempo(password, password);
}

int exchange_tempo_incorrect()
{
    uint8_t password1[TEMPO_LEN_PASSWORD];
    RAND_bytes(password1, TEMPO_LEN_PASSWORD);
    uint8_t password2[TEMPO_LEN_PASSWORD];
    RAND_bytes(password2, TEMPO_LEN_PASSWORD);
    return !exchange_tempo(password1, password2);
}

int exchange_tempo_re(const uint8_t *pw1, const uint8_t *pw2)
{
    uint8_t pk[TEMPO_RE_LEN_PUBLIC_KEY];
    uint8_t sk[TEMPO_RE_LEN_SECRET_KEY];
    TEMPO_RE_apk apk;
    TEMPO_RE_fsid fsid;
    fsid.sid = 100;
    fsid.a = 1;
    fsid.b = 2;
    TEMPO_RE_session sess1;
    sess1.fsid = fsid;
    sess1.password = pw1;
    TEMPO_RE_keygen(pk, sk, &apk, sess1);
    uint8_t ct[TEMPO_RE_LEN_CIPHERTEXT];
    uint8_t tag[TEMPO_RE_LEN_TAG];
    uint8_t ss1[TEMPO_RE_LEN_SHARED_SECRET];
    TEMPO_RE_session sess2;
    sess2.fsid = fsid;
    sess2.password = pw2;
    TEMPO_RE_encaps(ct, tag, ss1, sess2, &apk);
    uint8_t ss2[TEMPO_RE_LEN_SHARED_SECRET];
    TEMPO_RE_decaps(ss2, sess1, &apk, ct, tag, pk, sk);
    return cmp(ss1, ss2, TEMPO_RE_LEN_SHARED_SECRET);
}

int exchange_tempo_re_correct()
{
    uint8_t password[TEMPO_RE_LEN_PASSWORD];
    RAND_bytes(password, TEMPO_RE_LEN_PASSWORD);
    return exchange_tempo_re(password, password);
}

int exchange_tempo_re_incorrect()
{
    uint8_t password1[TEMPO_RE_LEN_PASSWORD];
    RAND_bytes(password1, TEMPO_RE_LEN_PASSWORD);
    uint8_t password2[TEMPO_RE_LEN_PASSWORD];
    RAND_bytes(password2, TEMPO_RE_LEN_PASSWORD);
    return !exchange_tempo_re(password1, password2);
}
