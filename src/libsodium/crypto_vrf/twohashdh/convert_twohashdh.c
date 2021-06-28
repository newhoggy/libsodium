#include <string.h>

#include "crypto_hash_sha512.h"
#include "private/ed25519_ref10.h"
#include "crypto_vrf_twohashdh.h"
#include "vrf_twohashdh.h"

/* Hash a message to a curve point using Elligator2.
 * Specified in VRF draft spec section 5.4.1.2.
 * The actual elligator2 implementation is ge25519_from_uniform.
 * Runtime depends only on alphalen (the message length)
 */
void
_vrf_twohashdh_hash_to_curve_elligator2_25519(unsigned char H_string[32],
//                                                const ge25519_p3 *Y_point, // we probably want to add this eventually
                                                const unsigned char *alpha,
                                                const unsigned long long alphalen)
{
    crypto_hash_sha512_state hs;
    unsigned char            r_string[64]; //Y_string[32],

//    _vrf_ietfdraft03_point_to_string(Y_string, Y_point);

    /* r = first 32 bytes of SHA512(suite || 0x01 || Y || alpha) */
    crypto_hash_sha512_init(&hs);
//    crypto_hash_sha512_update(&hs, &SUITE, 1);
//    crypto_hash_sha512_update(&hs, &ONE, 1);
//    crypto_hash_sha512_update(&hs, Y_string, 32);
    crypto_hash_sha512_update(&hs, alpha, alphalen);
    crypto_hash_sha512_final(&hs, r_string);

    r_string[31] &= 0x7f; /* clear sign bit */
    ge25519_from_uniform(H_string, r_string); /* elligator2 */
}

/* Subroutine specified in draft spec section 5.4.3.
 * Hashes four points to a 16-byte string.
 * Constant time. */
void
_vrf_twohashdh_hash_points(unsigned char challenge_scalar[32], const ge25519_p3 *Y_point,
                           const ge25519_p3 *H_point, const ge25519_p3 *U_point,
                           const ge25519_p3 *Announcement_one, const ge25519_p3 *Announcement_two)
{
    unsigned char str[32*5], c1[64];

    ge25519_p3_tobytes(str+32*0, Y_point);
    ge25519_p3_tobytes(str+32*1, H_point);
    ge25519_p3_tobytes(str+32*2, U_point);
    ge25519_p3_tobytes(str+32*3, Announcement_one);
    ge25519_p3_tobytes(str+32*4, Announcement_two);
    crypto_hash_sha512(c1, str, sizeof str);
    sc25519_reduce(c1);
    memmove(challenge_scalar, c1, 32);
    sodium_memzero(c1, 64);
}

void
_vrf_twohashdh_hash_points_verif(unsigned char challenge_scalar[32], const ge25519_p3 *Y_point,
                        const ge25519_p3 *H_point, const ge25519_p3 *U_point,
                        const ge25519_p2 *Announcement_one, const ge25519_p2 *Announcement_two) {
    unsigned char str[32*5], c1[64];

    ge25519_p3_tobytes(str+32*0, Y_point);
    ge25519_p3_tobytes(str+32*1, H_point);
    ge25519_p3_tobytes(str+32*2, U_point);
    ge25519_tobytes(str+32*3, Announcement_one);
    ge25519_tobytes(str+32*4, Announcement_two);
    crypto_hash_sha512(c1, str, sizeof str);
    sc25519_reduce(c1);
    memmove(challenge_scalar, c1, 32);
    sodium_memzero(c1, 64);
}

/* Subroutine to compute the value outputed by the VRF */
void
_vrf_twohashdh_generate_output(unsigned char output[64], const ge25519_p3 *U_point,
                               const unsigned char *message, unsigned long long messagelen)
{
    unsigned char str[32 + messagelen];

    ge25519_p3_tobytes(str, U_point);
    memmove(str + 32, message, messagelen);
    crypto_hash_sha512(output, str, sizeof str);
}

int
_vrf_twohashdh_decode_proof(ge25519_p3 *U_point, unsigned char challenge[32],
                              unsigned char response[32], const unsigned char pi[crypto_vrf_twohashdh_PROOFBYTES])
{
    if (ge25519_is_canonical(pi) == 0) {
        printf("not canonical \n");
    }

    if (ge25519_frombytes(U_point, pi) != 0) {
        printf("failed from bytes\n");
    }
    /* gamma = decode_point(pi[0:32]) */
    if (ge25519_is_canonical(pi) == 0 ||
        ge25519_frombytes(U_point, pi) != 0) {
        return -1;
    }

    // todo: challenge should be 32
    memmove(challenge, pi+32, 32); /* c = pi[32:64] */
    memmove(response, pi+64, 32); /* s = pi[64:96] */
    return 0;
}