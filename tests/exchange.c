#include <string.h>
#include <openssl/rand.h>
#include <kyber/kem.h>
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
    uint8_t pk[KYBER_PUBLICKEYBYTES];
    uint8_t sk[KYBER_SECRETKEYBYTES];
    pqcrystals_kyber768_ref_keypair(pk, sk);
    uint8_t ct[KYBER_CIPHERTEXTBYTES];
    uint8_t ss1[KYBER_SSBYTES];
    pqcrystals_kyber768_ref_enc(ct, ss1, pk);
    uint8_t ss2[KYBER_SSBYTES];
    pqcrystals_kyber768_ref_dec(ss2, ct, sk);
    return cmp(ss1, ss2, KYBER_SSBYTES);
}

int exchange_rkem()
{
    uint8_t pk[RKEM_len_public_key];
    uint8_t sk[RKEM_len_secret_key];
    RKEM_keygen(pk, sk);
    uint8_t seed[RKEM_len_seed];
    RAND_bytes(seed, RKEM_len_seed);
    uint8_t rand_pk[RKEM_len_public_key];
    RKEM_rand(rand_pk, seed, pk);
    uint8_t ct[RKEM_len_ciphertext];
    uint8_t ss1[RKEM_len_shared_secret];
    RKEM_encaps(ct, ss1, rand_pk);
    uint8_t ss2[RKEM_len_shared_secret];
    RKEM_decaps(ss2, ct, sk, seed);
    return cmp(ss1, ss2, RKEM_len_shared_secret);
}

int exchange_xrkem()
{
    uint8_t pk[XRKEM_len_public_key];
    uint8_t sk[XRKEM_len_secret_key];
    XRKEM_keygen(pk, sk);
    uint8_t seed[XRKEM_len_seed];
    RAND_bytes(seed, XRKEM_len_seed);
    uint8_t rand_pk[XRKEM_len_public_key];
    XRKEM_rand(rand_pk, seed, pk);
    uint8_t ct[XRKEM_len_ciphertext];
    uint8_t ss1[XRKEM_len_shared_secret];
    XRKEM_encaps(ct, ss1, rand_pk);
    uint8_t ss2[XRKEM_len_shared_secret];
    XRKEM_decaps(ss2, ct, sk, seed);
    return cmp(ss1, ss2, RKEM_len_shared_secret);
}

int exchange_xrkem_derand()
{
    uint8_t pk[XRKEM_len_public_key];
    uint8_t sk[XRKEM_len_secret_key];
    XRKEM_keygen(pk, sk);
    uint8_t seed[XRKEM_len_seed];
    RAND_bytes(seed, XRKEM_len_seed);
    uint8_t rand_pk[XRKEM_len_public_key];
    XRKEM_rand(rand_pk, seed, pk);
    XRKEM_derand(pk, seed, rand_pk);
    uint8_t ct[XRKEM_len_ciphertext];
    uint8_t ss1[XRKEM_len_shared_secret];
    XRKEM_encaps(ct, ss1, pk);
    uint8_t ss2[XRKEM_len_shared_secret];
    XRKEM_decaps_derand(ss2, ct, sk);
    return cmp(ss1, ss2, RKEM_len_shared_secret);
}

int exchange_nice_pake(const uint8_t *pw1, const uint8_t *pw2)
{
    uint8_t seed[NICE_PAKE_len_seed];
    uint8_t poly[NICE_PAKE_len_poly];
    uint8_t sk[NICE_PAKE_len_secret_key];
    NICE_PAKE_keygen(seed, poly, sk, pw1);
    uint8_t ct[NICE_PAKE_len_ciphertext];
    uint8_t ss1[NICE_PAKE_len_shared_secret];
    NICE_PAKE_encaps(ct, ss1, seed, poly, pw2);
    uint8_t ss2[NICE_PAKE_len_shared_secret];
    NICE_PAKE_decaps(ss2, ct, sk);
    return cmp(ss1, ss2, NICE_PAKE_len_shared_secret);
}

int exchange_nice_pake_correct()
{
    uint8_t password[NICE_PAKE_len_password];
    RAND_bytes(password, NICE_PAKE_len_password);
    return exchange_nice_pake(password, password);
}

int exchange_nice_pake_incorrect()
{
    uint8_t password1[NICE_PAKE_len_password];
    RAND_bytes(password1, NICE_PAKE_len_password);
    uint8_t password2[NICE_PAKE_len_password];
    RAND_bytes(password2, NICE_PAKE_len_password);
    return !exchange_nice_pake(password1, password2);
}

int exchange_nice_pake_re(const uint8_t *pw1, const uint8_t *pw2)
{
    uint8_t seed_a[NICE_PAKE_RE_len_seed];
    uint8_t poly[NICE_PAKE_RE_len_poly];
    uint8_t sk[NICE_PAKE_RE_len_secret_key];
    NICE_PAKE_RE_keygen(seed_a, poly, sk, pw1);
    uint8_t seed_b[NICE_PAKE_RE_len_seed];
    uint8_t ct[NICE_PAKE_RE_len_ciphertext];
    uint8_t ss1[NICE_PAKE_RE_len_shared_secret];
    NICE_PAKE_RE_encaps(seed_b, ct, ss1, seed_a, poly, pw2);
    uint8_t ss2[NICE_PAKE_RE_len_shared_secret];
    NICE_PAKE_RE_decaps(ss2, seed_b, ct, sk, pw1);
    return cmp(ss1, ss2, NICE_PAKE_RE_len_shared_secret);
}

int exchange_nice_pake_re_correct()
{
    uint8_t password[NICE_PAKE_RE_len_password];
    RAND_bytes(password, NICE_PAKE_RE_len_password);
    return exchange_nice_pake_re(password, password);
}

int exchange_nice_pake_re_incorrect()
{
    uint8_t password1[NICE_PAKE_RE_len_password];
    RAND_bytes(password1, NICE_PAKE_RE_len_password);
    uint8_t password2[NICE_PAKE_RE_len_password];
    RAND_bytes(password2, NICE_PAKE_RE_len_password);
    return !exchange_nice_pake_re(password1, password2);
}

int exchange_tempo(const uint8_t *pw1, const uint8_t *pw2)
{
    uint8_t pk[TEMPO_len_public_key];
    uint8_t sk[TEMPO_len_secret_key];
    TEMPO_apk apk;
    TEMPO_fsid fsid;
    fsid.sid = 100;
    fsid.a = 1;
    fsid.b = 2;
    TEMPO_session sess1;
    sess1.fsid = fsid;
    sess1.password = pw1;
    TEMPO_keygen(pk, sk, &apk, sess1);
    uint8_t ct[TEMPO_len_ciphertext];
    uint8_t tag[TEMPO_len_tag];
    uint8_t ss1[TEMPO_len_shared_secret];
    TEMPO_session sess2;
    sess2.fsid = fsid;
    sess2.password = pw2;
    TEMPO_encaps(ct, tag, ss1, sess2, &apk);
    uint8_t ss2[TEMPO_len_shared_secret];
    TEMPO_decaps(ss2, sess1, &apk, ct, tag, pk, sk);
    return cmp(ss1, ss2, TEMPO_len_shared_secret);
}

int exchange_tempo_correct()
{
    uint8_t password[TEMPO_len_password];
    RAND_bytes(password, TEMPO_len_password);
    return exchange_tempo(password, password);
}

int exchange_tempo_incorrect()
{
    uint8_t password1[TEMPO_len_password];
    RAND_bytes(password1, TEMPO_len_password);
    uint8_t password2[TEMPO_len_password];
    RAND_bytes(password2, TEMPO_len_password);
    return !exchange_tempo(password1, password2);
}

int exchange_tempo_re(const uint8_t *pw1, const uint8_t *pw2)
{
    uint8_t pk[TEMPO_RE_len_public_key];
    uint8_t sk[TEMPO_RE_len_secret_key];
    TEMPO_RE_apk apk;
    TEMPO_RE_fsid fsid;
    fsid.sid = 100;
    fsid.a = 1;
    fsid.b = 2;
    TEMPO_RE_session sess1;
    sess1.fsid = fsid;
    sess1.password = pw1;
    TEMPO_RE_keygen(pk, sk, &apk, sess1);
    uint8_t ct[TEMPO_RE_len_ciphertext];
    uint8_t tag[TEMPO_RE_len_tag];
    uint8_t ss1[TEMPO_RE_len_shared_secret];
    TEMPO_RE_session sess2;
    sess2.fsid = fsid;
    sess2.password = pw2;
    TEMPO_RE_encaps(ct, tag, ss1, sess2, &apk);
    uint8_t ss2[TEMPO_RE_len_shared_secret];
    TEMPO_RE_decaps(ss2, sess1, &apk, ct, tag, pk, sk);
    return cmp(ss1, ss2, TEMPO_RE_len_shared_secret);
}

int exchange_tempo_re_correct()
{
    uint8_t password[TEMPO_RE_len_password];
    RAND_bytes(password, TEMPO_RE_len_password);
    return exchange_tempo_re(password, password);
}

int exchange_tempo_re_incorrect()
{
    uint8_t password1[TEMPO_RE_len_password];
    RAND_bytes(password1, TEMPO_RE_len_password);
    uint8_t password2[TEMPO_RE_len_password];
    RAND_bytes(password2, TEMPO_RE_len_password);
    return exchange_tempo_re(password1, password2);
}