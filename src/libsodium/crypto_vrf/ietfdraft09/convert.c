/*
Slight modification of document ./../ietfdraft03/convert.c to follow the
latest version of the standard, using the "Try and Increment" hash_to_curve
function. We reproduce the copyright notice.

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

#include "crypto_hash_sha512.h"
#include "crypto_vrf_ietfdraft09.h"
#include "private/ed25519_ref10.h"
#include "crypto_core_ed25519.h"
#include "vrf_ietfdraft09.h"

static const unsigned char ZERO = 0x00;
static const unsigned char ONE = 0x01;
static const unsigned char TWO = 0x02;
static const unsigned char FOUR = 0x04;

/* Utility function to multiply a point by the cofactor (8) in place. */
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

/* Encode elliptic curve point into a 32-byte octet string per RFC8032 section
 * 5.1.2.
 */
void
_vrf_ietfdraft09_point_to_string(unsigned char string[32], const ge25519_p3 *point)
{
    ge25519_p3_tobytes(string, point);
}

/* Decode elliptic curve point from 32-byte octet string per RFC8032 section
 * 5.1.3.
 *
 * In particular we must reject non-canonical encodings (i.e., when the encoded
 * y coordinate is not reduced mod p). We do not check whether the point is on
 * the main subgroup or whether it is of low order. Returns 0 on success (and
 * stores decoded point in *point), nonzero if decoding fails.
 */
int
_vrf_ietfdraft09_string_to_point(ge25519_p3 *point, const unsigned char string[32])
{
    if (ge25519_is_canonical(string) == 0 ||
	ge25519_frombytes(point, string) != 0) {
	return -1;
    }
    return 0;
}

/*
 * Computing the `hash_to_curve` using try and increment
 */
int
_vrf_ietfdraft09_hash_to_curve_try_inc(unsigned char H_string[32],
                                       const ge25519_p3 *Y_point,
                                       const unsigned char *alpha,
                                       const unsigned long long alphalen)
{
    unsigned char            Y_string[32], r_string[64];

    _vrf_ietfdraft09_point_to_string(Y_string, Y_point);

    ge25519_p3 p3;
    int check = 64;
    unsigned char value = ZERO;
    while (check > 0) {
        crypto_hash_sha512_state hs;
        crypto_hash_sha512_init(&hs);
        crypto_hash_sha512_update(&hs, &SUITE, 1);
        crypto_hash_sha512_update(&hs, &ONE, 1);
        crypto_hash_sha512_update(&hs, Y_string, 32);
        crypto_hash_sha512_update(&hs, alpha, alphalen);
        crypto_hash_sha512_update(&hs, &value, 1);
        crypto_hash_sha512_update(&hs, &ZERO, 1);
        crypto_hash_sha512_final(&hs, r_string);

        if (ge25519_frombytes(&p3, r_string) == 0) {
            multiply_by_cofactor(&p3);
            ge25519_p3_tobytes(H_string, &p3);
            return 0;
        };

        value += ONE;
        check -= 1;
    }
    return -1;
}

/* Subroutine specified in draft spec section 5.4.3.
 * Hashes four points to a 16-byte string.
 * Constant time. For optimised calls*/
void
_vrf_ietfdraft09_hash_points(unsigned char c[16], const ge25519_p3 *P1,
                                 const ge25519_p3 *P2, const unsigned char P3[32],
                                 const unsigned char P4[32])
{
    unsigned char str[3+32*4], c1[64];

    str[0] = SUITE;
    str[1] = TWO;
    _vrf_ietfdraft09_point_to_string(str+2+32*0, P1);
    _vrf_ietfdraft09_point_to_string(str+2+32*1, P2);
    memmove(str+2+32*2, P3, 32);
    memmove(str+2+32*3, P4, 32);
    str[2 + 32*4] = ZERO;
    crypto_hash_sha512(c1, str, sizeof str);
    memmove(c, c1, 16);
    sodium_memzero(c1, 64);
}

/* Decode an 128-byte batch compatible proof pi into a point gamma, a point U, a point V, and a
 * 32-byte scalar s.
 * Returns 0 on success, nonzero on failure.
 */
int
_vrf_ietfdraft09_decode_proof(ge25519_p3 *Gamma, unsigned char U[32], unsigned char V[32],
                                               unsigned char s[32], const unsigned char pi[128])
{
    if (_vrf_ietfdraft09_string_to_point(Gamma, pi) != 0)
    {
        return -1;
    }
    memmove(U, pi+32, 32);
    memmove(V, pi+64, 32);
    memmove(s, pi+96, 32);
    return 0;
}
