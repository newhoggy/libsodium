
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "crypto_hash_sha512.h"
#include "crypto_sign_ed25519.h"
#include "crypto_verify_32.h"
#include "sign_ed25519_ref10.h"
#include "private/ed25519_ref10.h"
#include "utils.h"

static void
multiply_by_cofactor(ge25519_p3 *point) {
    ge25519_cached tmp_point;
    ge25519_p1p1   tmp2_point;

    ge25519_p3_to_cached(&tmp_point, point);     /* tmp = input */
    ge25519_add(&tmp2_point, point, &tmp_point); /* tmp2 = 2*input */
    ge25519_p1p1_to_p3(point, &tmp2_point);      /* point = 2*input */
    ge25519_p3_to_cached(&tmp_point, point);     /* tmp = 2*input */
    ge25519_add(&tmp2_point, point, &tmp_point); /* tmp2 = 4*input */
    ge25519_p1p1_to_p3(point, &tmp2_point);      /* point = 4*input */
    ge25519_p3_to_cached(&tmp_point, point);     /* tmp = 4*input */
    ge25519_add(&tmp2_point, point, &tmp_point); /* tmp2 = 8*input */
    ge25519_p1p1_to_p3(point, &tmp2_point);      /* point = 8*input */
}

int
_crypto_sign_ed25519_verify_detached(const unsigned char *sig,
                                     const unsigned char *m,
                                     unsigned long long   mlen,
                                     const unsigned char *pk,
                                     int prehashed)
{
    crypto_hash_sha512_state hs;
    unsigned char            h[64];
    unsigned char            rcheck[32];
    ge25519_p3               A;
    ge25519_p2               R;

#ifdef ED25519_COMPAT
    if (sig[63] & 224) {
        return -1;
    }
#else
    if (sc25519_is_canonical(sig + 32) == 0 ||
        ge25519_has_small_order(sig) != 0) {
        return -1;
    }
    if (ge25519_is_canonical(pk) == 0 ||
        ge25519_has_small_order(pk) != 0) {
        return -1;
    }
#endif
    if (ge25519_frombytes_negate_vartime(&A, pk) != 0) {
        return -1;
    }
    _crypto_sign_ed25519_ref10_hinit(&hs, prehashed);
    crypto_hash_sha512_update(&hs, sig, 32);
    crypto_hash_sha512_update(&hs, pk, 32);
    crypto_hash_sha512_update(&hs, m, mlen);
    crypto_hash_sha512_final(&hs, h);
    sc25519_reduce(h);

    printf("libsodium: ");
    for (int i = 0; i<32; i++) {
        printf("%c", h[i]);
    }
    printf("\n");

    ge25519_double_scalarmult_vartime(&R, h, &A, sig + 32);
    ge25519_tobytes(rcheck, &R);

    ge25519_p3               new_R, new_Sig;
    unsigned char new_sig_bytes[32];
    ge25519_frombytes(&new_R, rcheck);
    multiply_by_cofactor(&new_R);
    ge25519_frombytes(&new_Sig, sig);
    multiply_by_cofactor(&new_Sig);

    ge25519_p3_tobytes(rcheck, &new_R);
    ge25519_p3_tobytes(new_sig_bytes, &new_Sig);

    return crypto_verify_32(rcheck, new_sig_bytes) | (-(rcheck == new_sig_bytes)) |
           sodium_memcmp(new_sig_bytes, rcheck, 32);
}

/*
 * Given a ristretto pk and signature, it returns the canonical representation (prime subgroup)
 * of the corresponding edwards points.
 */
int crypto_sign_ed25519_prepare_sig_and_pk(
        unsigned char *ge25519_pk,
        unsigned char *ge25519_announcement,
        unsigned char *ristretto255_pk,
        unsigned char *ristretto255_announcement) {

    ge25519_p3     pk, pk_torsion_safe, announcement, announcement_torsion_safe;
    if (ristretto255_frombytes(&pk, ristretto255_pk) != 0) {
    return -1;
    }
    if (ristretto255_frombytes(&announcement, ristretto255_announcement) != 0) {
    return -1;
    }

//    mul_torsion_safe(&pk_torsion_safe, &pk);
//    mul_torsion_safe(&announcement_torsion_safe, &announcement);

    ge25519_p3_tobytes(ge25519_pk, &pk);
    ge25519_p3_tobytes(ge25519_announcement, &announcement);

    return 0;
}

int
crypto_sign_ed25519_verify_detached(const unsigned char *sig,
                                    const unsigned char *m,
                                    unsigned long long   mlen,
                                    const unsigned char *pk)
{
    return _crypto_sign_ed25519_verify_detached(sig, m, mlen, pk, 0);
}

int
crypto_sign_ed25519_open(unsigned char *m, unsigned long long *mlen_p,
                         const unsigned char *sm, unsigned long long smlen,
                         const unsigned char *pk)
{
    unsigned long long mlen;

    if (smlen < 64 || smlen - 64 > crypto_sign_ed25519_MESSAGEBYTES_MAX) {
        goto badsig;
    }
    mlen = smlen - 64;
    if (crypto_sign_ed25519_verify_detached(sm, sm + 64, mlen, pk) != 0) {
        if (m != NULL) {
            memset(m, 0, mlen);
        }
        goto badsig;
    }
    if (mlen_p != NULL) {
        *mlen_p = mlen;
    }
    if (m != NULL) {
        memmove(m, sm + 64, mlen);
    }
    return 0;

badsig:
    if (mlen_p != NULL) {
        *mlen_p = 0;
    }
    return -1;
}
