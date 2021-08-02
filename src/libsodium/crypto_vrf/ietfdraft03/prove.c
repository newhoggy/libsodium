/*
Copyright (c) 2018 Algorand LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <string.h>
#include <time.h>
#include <stdio.h>

#include "crypto_hash_sha512.h"
#include "crypto_generichash.h"
#include "crypto_vrf_ietfdraft03.h"
#include "private/ed25519_ref10.h"
#include "crypto_core_ed25519.h"
#include "randombytes.h"
#include "utils.h"
#include "vrf_ietfdraft03.h"

/* Utility function to convert a "secret key" (32-byte seed || 32-byte PK)
 * into the public point Y, the private saclar x, and truncated hash of the
 * seed to be used later in nonce generation.
 * Return 0 on success, -1 on failure decoding the public point Y.
 */
static int
vrf_expand_sk(ge25519_p3 *Y_point, unsigned char x_scalar[32],
	      unsigned char truncated_hashed_sk_string[32], const unsigned char skpk[64])
{
    unsigned char h[64];

    crypto_hash_sha512(h, skpk, 32);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    memmove(x_scalar, h, 32);
    memmove(truncated_hashed_sk_string, h + 32, 32);
    sodium_memzero(h, 64);

    return _vrf_ietfdraft03_string_to_point(Y_point, skpk+32);
}


/* Deterministically generate a (secret) nonce to be used in a proof.
 * Specified in draft spec section 5.4.2.2.
 * Note: In the spec, this subroutine computes truncated_hashed_sk_string
 * Here we instead takes it as an argument, and we compute it in vrf_expand_sk
 */
static void
vrf_nonce_generation(unsigned char k_scalar[32],
		     const unsigned char truncated_hashed_sk_string[32],
		     const unsigned char h_string[32])
{
    crypto_hash_sha512_state hs;
    unsigned char            k_string[64];

    /* k_string = SHA512(truncated_hashed_sk_string || h_string) */
    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, truncated_hashed_sk_string, 32);
    crypto_hash_sha512_update(&hs, h_string, 32);
    crypto_hash_sha512_final(&hs, k_string);

    sc25519_reduce(k_string); /* k_string[0:32] = string_to_int(k_string) mod q */
    memmove(k_scalar, k_string, 32);

    sodium_memzero(k_string, sizeof k_string);
}

/*
 * Nonce generation using Blake2b
 */
static void
vrf_nonce_generation_blake(unsigned char k_scalar[32],
                     const unsigned char truncated_hashed_sk_string[32],
                     const unsigned char h_string[32])
{
    crypto_generichash_blake2b_state hs;
    unsigned char            k_string[32];

    /* k_string = SHA512(truncated_hashed_sk_string || h_string) */
    crypto_generichash_blake2b_init(&hs, NULL, 0U, sizeof k_string);
    crypto_generichash_blake2b_update(&hs, truncated_hashed_sk_string, 32);
    crypto_generichash_blake2b_update(&hs, h_string, 32);
    crypto_generichash_blake2b_final(&hs, k_string, 32);

    sc25519_reduce(k_string); /* k_string[0:32] = string_to_int(k_string) mod q */
    memmove(k_scalar, k_string, 32);

    sodium_memzero(k_string, sizeof k_string);
}

double time_per_proof(const unsigned int size) {
    // for random point gen
    unsigned char x[crypto_core_ed25519_UNIFORMBYTES];
    unsigned char random_point[crypto_core_ed25519_BYTES];
    unsigned char random_scal[crypto_core_ed25519_SCALARBYTES];

    unsigned char **multiscalar_scalars = (unsigned char **)malloc(size * 6 * sizeof(unsigned char *));
    ge25519_p3 multiscalar_bases[size * 6];
    ge25519_p2 expected_zero;
    for (int i = 0; i < size * 6; i++) {
        randombytes_buf(x, sizeof x);
        crypto_core_ed25519_from_uniform(random_point, x);
        crypto_core_ed25519_scalar_random(random_scal);
        multiscalar_scalars[i] = random_scal;
        ge25519_frombytes(&multiscalar_bases[i], random_point);
    }

    clock_t t_api;
    t_api = clock();
    /* calculate V = s*H -  c*Gamma */
    ge25519_multi_scalarmult_vartime(&expected_zero, multiscalar_scalars, multiscalar_bases, size * 6, 0);
    t_api = clock() - t_api;
    free(multiscalar_scalars);

    return ((double) t_api) / (CLOCKS_PER_SEC * size);
}

int internal_scalarmul(unsigned char *point, const unsigned char *scalar) {
    unsigned char result_bytes[32];
    ge25519_p3 result, point_in;
    if (ge25519_frombytes(&point_in, point) != 0) {
        return -1;
    }
    ge25519_scalarmult(&result, scalar, &point_in);
    // note that if we work with the internal operations, we don't need to perform this test.
    ge25519_p3_tobytes(result_bytes, &result);
    return 0;
}

/* Construct a proof for a message using try and increment
 */
static void
vrf_prove_try_inc(unsigned char pi[80], const ge25519_p3 *Y_point,
          const unsigned char x_scalar[32],
          const unsigned char truncated_hashed_sk_string[32],
          const unsigned char *alpha, unsigned long long alphalen)
{
    /* c fits in 16 bytes, but we store it in a 32-byte array because
     * sc25519_muladd expects a 32-byte scalar */
    unsigned char h_string[32], k_scalar[32], c_scalar[32];
    ge25519_p3    H_point, Gamma_point, kB_point, kH_point;

    _vrf_ietfdraft03_hash_to_curve_try_inc(h_string, Y_point, alpha, alphalen);
    ge25519_frombytes(&H_point, h_string);

    ge25519_scalarmult(&Gamma_point, x_scalar, &H_point); /* Gamma = x*H */
    vrf_nonce_generation(k_scalar, truncated_hashed_sk_string, h_string);
    ge25519_scalarmult_base(&kB_point, k_scalar); /* compute k*B */
    ge25519_scalarmult(&kH_point, k_scalar, &H_point); /* compute k*H */

    /* c = ECVRF_hash_points(h, gamma, k*B, k*H)
     * (writes only to the first 16 bytes of c_scalar */
    _vrf_ietfdraft03_hash_points(c_scalar, &H_point, &Gamma_point, &kB_point, &kH_point);
    memset(c_scalar+16, 0, 16); /* zero the remaining 16 bytes of c_scalar */

    /* output pi */
    _vrf_ietfdraft03_point_to_string(pi, &Gamma_point); /* pi[0:32] = point_to_string(Gamma) */
    memmove(pi+32, c_scalar, 16); /* pi[32:48] = c (16 bytes) */
    sc25519_muladd(pi+48, c_scalar, x_scalar, k_scalar); /* pi[48:80] = s = c*x + k (mod q) */

    sodium_memzero(k_scalar, sizeof k_scalar); /* k must remain secret */
    /* erase other non-sensitive intermediate state for good measure */
    sodium_memzero(h_string, sizeof h_string);
    sodium_memzero(c_scalar, sizeof c_scalar);
    sodium_memzero(&H_point, sizeof H_point);
    sodium_memzero(&Gamma_point, sizeof Gamma_point);
    sodium_memzero(&kB_point, sizeof kB_point);
    sodium_memzero(&kH_point, sizeof kH_point);
}

/* Construct a proof for a message alpha per draft spec section 5.1.
 * Takes in a secret scalar x, a public point Y, and a secret string
 * truncated_hashed_sk that is used in nonce generation.
 * These are computed from the secret key using the expand_sk function.
 * Constant time in everything except alphalen (the length of the message)
 */
static void
vrf_prove(unsigned char pi[80], const ge25519_p3 *Y_point,
          const unsigned char x_scalar[32],
          const unsigned char truncated_hashed_sk_string[32],
          const unsigned char *alpha, unsigned long long alphalen)
{
    /* c fits in 16 bytes, but we store it in a 32-byte array because
     * sc25519_muladd expects a 32-byte scalar */
    unsigned char h_string[32], k_scalar[32], c_scalar[32];
    ge25519_p3    H_point, Gamma_point, kB_point, kH_point;

    _vrf_ietfdraft03_hash_to_curve_elligator2_25519(h_string, Y_point, alpha, alphalen);
    ge25519_frombytes(&H_point, h_string);

    ge25519_scalarmult(&Gamma_point, x_scalar, &H_point); /* Gamma = x*H */
    vrf_nonce_generation(k_scalar, truncated_hashed_sk_string, h_string);
    ge25519_scalarmult_base(&kB_point, k_scalar); /* compute k*B */
    ge25519_scalarmult(&kH_point, k_scalar, &H_point); /* compute k*H */

    /* c = ECVRF_hash_points(h, gamma, k*B, k*H)
     * (writes only to the first 16 bytes of c_scalar */
    _vrf_ietfdraft03_hash_points(c_scalar, &H_point, &Gamma_point, &kB_point, &kH_point);
    memset(c_scalar+16, 0, 16); /* zero the remaining 16 bytes of c_scalar */

    /* output pi */
    _vrf_ietfdraft03_point_to_string(pi, &Gamma_point); /* pi[0:32] = point_to_string(Gamma) */
    memmove(pi+32, c_scalar, 16); /* pi[32:48] = c (16 bytes) */
    sc25519_muladd(pi+48, c_scalar, x_scalar, k_scalar); /* pi[48:80] = s = c*x + k (mod q) */

    sodium_memzero(k_scalar, sizeof k_scalar); /* k must remain secret */
    /* erase other non-sensitive intermediate state for good measure */
    sodium_memzero(h_string, sizeof h_string);
    sodium_memzero(c_scalar, sizeof c_scalar);
    sodium_memzero(&H_point, sizeof H_point);
    sodium_memzero(&Gamma_point, sizeof Gamma_point);
    sodium_memzero(&kB_point, sizeof kB_point);
    sodium_memzero(&kH_point, sizeof kH_point);
}

/* Construct a proof for a message alpha per draft spec section 5.1.
 * Takes in a secret scalar x, a public point Y, and a secret string
 * truncated_hashed_sk that is used in nonce generation.
 * These are computed from the secret key using the expand_sk function.
 * Constant time in everything except alphalen (the length of the message).
 *
 * The proof contains the two points U and V instead of the challenge
 * to allow for batch-verification.
 */
static void
vrf_prove_batch_compatible(unsigned char pi[128], const ge25519_p3 *Y_point,
          const unsigned char x_scalar[32],
          const unsigned char truncated_hashed_sk_string[32],
          const unsigned char *alpha, unsigned long long alphalen)
{
    /* c fits in 16 bytes, but we store it in a 32-byte array because
     * sc25519_muladd expects a 32-byte scalar */
    unsigned char h_string[32], k_scalar[32], c_scalar[32];
    ge25519_p3    H_point, Gamma_point, kB_point, kH_point;

    _vrf_ietfdraft03_hash_to_curve_try_inc(h_string, Y_point, alpha, alphalen);
    ge25519_frombytes(&H_point, h_string);

    ge25519_scalarmult(&Gamma_point, x_scalar, &H_point); /* Gamma = x*H */
    vrf_nonce_generation(k_scalar, truncated_hashed_sk_string, h_string);
    ge25519_scalarmult_base(&kB_point, k_scalar); /* compute k*B */
    ge25519_scalarmult(&kH_point, k_scalar, &H_point); /* compute k*H */

    /* c = ECVRF_hash_points(h, gamma, k*B, k*H)
     * (writes only to the first 16 bytes of c_scalar */
    _vrf_ietfdraft03_hash_points(c_scalar, &H_point, &Gamma_point, &kB_point, &kH_point);
    memset(c_scalar+16, 0, 16); /* zero the remaining 16 bytes of c_scalar */

    /* output pi */
    _vrf_ietfdraft03_point_to_string(pi, &Gamma_point); /* pi[0:32] = point_to_string(Gamma) */
    _vrf_ietfdraft03_point_to_string(pi + 32, &kB_point); /* pi[32:64] = point_to_string(kB_point) */
    _vrf_ietfdraft03_point_to_string(pi + 64, &kH_point); /* pi[64:96] = point_to_string(kH_point) */
    sc25519_muladd(pi+96, c_scalar, x_scalar, k_scalar); /* pi[96:128] = s = c*x + k (mod q) */

    sodium_memzero(k_scalar, sizeof k_scalar); /* k must remain secret */
    /* erase other non-sensitive intermediate state for good measure */
    sodium_memzero(h_string, sizeof h_string);
    sodium_memzero(c_scalar, sizeof c_scalar);
    sodium_memzero(&H_point, sizeof H_point);
    sodium_memzero(&Gamma_point, sizeof Gamma_point);
    sodium_memzero(&kB_point, sizeof kB_point);
    sodium_memzero(&kH_point, sizeof kH_point);
}

/*
 * Prove VRF function using Blake2b
 */
static void
vrf_prove_blake(unsigned char pi[80], const ge25519_p3 *Y_point,
          const unsigned char x_scalar[32],
          const unsigned char truncated_hashed_sk_string[32],
          const unsigned char *alpha, unsigned long long alphalen)
{
    /* c fits in 16 bytes, but we store it in a 32-byte array because
     * sc25519_muladd expects a 32-byte scalar */
    unsigned char h_string[32], k_scalar[32], c_scalar[32];
    ge25519_p3    H_point, Gamma_point, kB_point, kH_point;

    _vrf_ietfdraft03_hash_to_curve_elligator2_25519_blake(h_string, Y_point, alpha, alphalen);
    ge25519_frombytes(&H_point, h_string);

    ge25519_scalarmult(&Gamma_point, x_scalar, &H_point); /* Gamma = x*H */
    vrf_nonce_generation_blake(k_scalar, truncated_hashed_sk_string, h_string);
    ge25519_scalarmult_base(&kB_point, k_scalar); /* compute k*B */
    ge25519_scalarmult(&kH_point, k_scalar, &H_point); /* compute k*H */

    /* c = ECVRF_hash_points(h, gamma, k*B, k*H)
     * (writes only to the first 16 bytes of c_scalar */
    _vrf_ietfdraft03_hash_points_blake(c_scalar, &H_point, &Gamma_point, &kB_point, &kH_point);
    memset(c_scalar+16, 0, 16); /* zero the remaining 16 bytes of c_scalar */

    /* output pi */
    _vrf_ietfdraft03_point_to_string(pi, &Gamma_point); /* pi[0:32] = point_to_string(Gamma) */
    memmove(pi+32, c_scalar, 16); /* pi[32:48] = c (16 bytes) */
    sc25519_muladd(pi+48, c_scalar, x_scalar, k_scalar); /* pi[48:80] = s = c*x + k (mod q) */

    sodium_memzero(k_scalar, sizeof k_scalar); /* k must remain secret */
    /* erase other non-sensitive intermediate state for good measure */
    sodium_memzero(h_string, sizeof h_string);
    sodium_memzero(c_scalar, sizeof c_scalar);
    sodium_memzero(&H_point, sizeof H_point);
    sodium_memzero(&Gamma_point, sizeof Gamma_point);
    sodium_memzero(&kB_point, sizeof kB_point);
    sodium_memzero(&kH_point, sizeof kH_point);
}

/* Construct a VRF proof given a secret key and a message.
 *
 * The "secret key" is 64 bytes long -- 32 byte secret seed concatenated
 * with 32 byte precomputed public key. Our keygen functions return secret keys
 * of this form.
 *
 * Returns 0 on success, nonzero on failure decoding the public key.
 *
 * Constant time in everything except msglen, unless decoding the public key
 * fails.
 */
int
crypto_vrf_ietfdraft03_prove(unsigned char proof[crypto_vrf_ietfdraft03_PROOFBYTES],
			     const unsigned char skpk[crypto_vrf_ietfdraft03_SECRETKEYBYTES],
			     const unsigned char *msg,
			     unsigned long long msglen)
{
    ge25519_p3    Y_point;
    unsigned char x_scalar[32], truncated_hashed_sk_string[32];

    if (vrf_expand_sk(&Y_point, x_scalar, truncated_hashed_sk_string, skpk) != 0) {
	sodium_memzero(x_scalar, 32);
	sodium_memzero(truncated_hashed_sk_string, 32);
	sodium_memzero(&Y_point, sizeof Y_point); /* for good measure */
	return -1;
    }
    vrf_prove(proof, &Y_point, x_scalar, truncated_hashed_sk_string, msg, msglen);
    sodium_memzero(x_scalar, 32);
    sodium_memzero(truncated_hashed_sk_string, 32);
    sodium_memzero(&Y_point, sizeof Y_point); /* for good measure */
    return 0;
}

/*
 * VRF using Blake2b
 */
int
crypto_vrf_ietfdraft03_prove_blake(unsigned char proof[crypto_vrf_ietfdraft03_PROOFBYTES],
                             const unsigned char skpk[crypto_vrf_ietfdraft03_SECRETKEYBYTES],
                             const unsigned char *msg,
                             unsigned long long msglen)
{
    ge25519_p3    Y_point;
    unsigned char x_scalar[32], truncated_hashed_sk_string[32];

    if (vrf_expand_sk(&Y_point, x_scalar, truncated_hashed_sk_string, skpk) != 0) {
        sodium_memzero(x_scalar, 32);
        sodium_memzero(truncated_hashed_sk_string, 32);
        sodium_memzero(&Y_point, sizeof Y_point); /* for good measure */
        return -1;
    }
    vrf_prove_blake(proof, &Y_point, x_scalar, truncated_hashed_sk_string, msg, msglen);
    sodium_memzero(x_scalar, 32);
    sodium_memzero(truncated_hashed_sk_string, 32);
    sodium_memzero(&Y_point, sizeof Y_point); /* for good measure */
    return 0;
}

/*
 * Generate proof using try_increment for the `hash_to_curve` function.
 */
int
crypto_vrf_ietfdraft03_prove_try_inc(unsigned char proof[crypto_vrf_ietfdraft03_PROOFBYTES],
                             const unsigned char skpk[crypto_vrf_ietfdraft03_SECRETKEYBYTES],
                             const unsigned char *msg,
                             unsigned long long msglen)
{
    ge25519_p3    Y_point;
    unsigned char x_scalar[32], truncated_hashed_sk_string[32];

    if (vrf_expand_sk(&Y_point, x_scalar, truncated_hashed_sk_string, skpk) != 0) {
        sodium_memzero(x_scalar, 32);
        sodium_memzero(truncated_hashed_sk_string, 32);
        sodium_memzero(&Y_point, sizeof Y_point); /* for good measure */
        return -1;
    }
    vrf_prove_try_inc(proof, &Y_point, x_scalar, truncated_hashed_sk_string, msg, msglen);
    sodium_memzero(x_scalar, 32);
    sodium_memzero(truncated_hashed_sk_string, 32);
    sodium_memzero(&Y_point, sizeof Y_point); /* for good measure */
    return 0;
}

/*
 * Generate proof following the batch-compatible technique.
 */
int
crypto_vrf_ietfdraft03_prove_batch_compatible(unsigned char proof[crypto_vrf_ietfdraft03_BATCH_PROOFBYTES],
                                     const unsigned char skpk[crypto_vrf_ietfdraft03_SECRETKEYBYTES],
                                     const unsigned char *msg,
                                     unsigned long long msglen)
{
    ge25519_p3    Y_point;
    unsigned char x_scalar[32], truncated_hashed_sk_string[32];

    if (vrf_expand_sk(&Y_point, x_scalar, truncated_hashed_sk_string, skpk) != 0) {
        sodium_memzero(x_scalar, 32);
        sodium_memzero(truncated_hashed_sk_string, 32);
        sodium_memzero(&Y_point, sizeof Y_point); /* for good measure */
        return -1;
    }
    vrf_prove_batch_compatible(proof, &Y_point, x_scalar, truncated_hashed_sk_string, msg, msglen);
    sodium_memzero(x_scalar, 32);
    sodium_memzero(truncated_hashed_sk_string, 32);
    sodium_memzero(&Y_point, sizeof Y_point); /* for good measure */
    return 0;
}
