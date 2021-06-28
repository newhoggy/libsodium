#include <string.h>
#include <time.h>

#include "crypto_hash_sha512.h"
#include "crypto_verify_32.h"
#include "crypto_vrf_twohashdh.h"
#include "private/ed25519_ref10.h"
#include "crypto_core_ed25519.h"
#include "vrf_twohashdh.h"

static const unsigned char THREE = 0x03;

/*
 * Convert a VRF proof pi into a VRF output hash
 */
int
crypto_vrf_twohashdh_proof_to_hash(unsigned char beta[crypto_vrf_twohashdh_OUTPUTBYTES],
                                     const unsigned char pi[crypto_vrf_twohashdh_PROOFBYTES],
                                   const unsigned char *msg, const unsigned long long msglen)
{
    unsigned char hash_input[32 + msglen];

    memmove(hash_input, pi, 32); /* Move point U from the proof */
    memmove(hash_input + 32, msg, msglen); /* move message */

    crypto_hash_sha512(beta, hash_input, sizeof hash_input);

    return 0;
}

static int
vrf_validate_key(ge25519_p3 *y_out, const unsigned char pk_string[32])
{
    if (ge25519_has_small_order(pk_string) != 0 ||
            ge25519_is_canonical(pk_string) == 0 ||
            ge25519_frombytes(y_out, pk_string) != 0) {
        return -1;
    }
    return 0;
}

/* Validate an untrusted public key as specified in the draft spec section
 * 5.6.1. Return 1 if the key is valid, 0 otherwise.
 */
int
crypto_vrf_twohashdh_is_valid_key(const unsigned char pk[crypto_vrf_twohashdh_PUBLICKEYBYTES])
{
    ge25519_p3 point; /* unused */
    return (vrf_validate_key(&point, pk) == 0);
}

/* Verify a proof per draft section 5.3. Return 0 on success, -1 on failure.
 * We assume Y_point has passed public key validation already.
 * Assuming verification succeeds, runtime does not depend on the message alpha
 * (but does depend on its length alphalen)
 */
static int
vrf_verify(const ge25519_p3 *Y_point, const unsigned char pi[crypto_vrf_twohashdh_PROOFBYTES],
           const unsigned char *alpha, const unsigned long long alphalen)
{
    /* Note: c fits in 16 bytes, but ge25519_scalarmult expects a 32-byte scalar.
     * Similarly, s_scalar fits in 32 bytes but sc25519_reduce takes in 64 bytes. */
    unsigned char h_string[32], challenge_check[32], challenge_scalar[32], response_scalar[32],Y_bytes;

    ge25519_p3     H_point, U_point, V_point, tmp_p3_point,
                    pk_negate, U_point_negate;
    ge25519_p2 Announcement_one, Announcement_two;
    ge25519_p1p1   tmp_p1p1_point;
    ge25519_cached tmp_cached_point;

    if (_vrf_twohashdh_decode_proof(&U_point, challenge_scalar, response_scalar, pi) != 0) {
        printf("decoding proof\n");
        return -1;
    }
    /* vrf_decode_proof writes to the first 16 bytes of c_scalar; we zero the
     * second 16 bytes ourselves, as ge25519_scalarmult expects a 32-byte scalar.
     */
//    memset(challenge_scalar+16, 0, 16);
//
    /* vrf_decode_proof sets only the first 32 bytes of s_scalar; we zero the
     * second 32 bytes ourselves, as sc25519_reduce expects a 64-byte scalar.
     * Reducing the scalar s mod q ensures the high order bit of s is 0, which
     * ref10's scalarmult functions require.
     */

    _vrf_twohashdh_hash_to_curve_elligator2_25519(h_string, alpha, alphalen);

    ge25519_frombytes(&H_point, h_string);
    ge25519_p3_tobytes(&Y_bytes, Y_point);

    if (ge25519_frombytes_negate_vartime(&pk_negate, &Y_bytes) != 0) {
        printf("negating 1\n");
        return -1;
    }

    if (ge25519_frombytes_negate_vartime(&U_point_negate, pi) != 0) {
        printf("negating 2\n");
        return -1;
    }

    ge25519_double_scalarmult_vartime(&Announcement_one, challenge_scalar, &pk_negate, response_scalar);
    ge25519_double_scalarmult_vartime_variable(&Announcement_two, challenge_scalar, &U_point_negate, response_scalar, &H_point);

    unsigned char u_string[32], a_one[32], a_two[32];
    /* challenge = hash_points(Y_point, H_point, U_point, Announcement_one, Announcement_two) */
    printf("H_point (verif):");
    for (int i = 0; i<32; i++) {
        printf("%c", h_string[i]);
    }
    printf("\n");
    ge25519_tobytes(u_string, &U_point);
    printf("U_point (verif):");
    for (int i = 0; i<32; i++) {
        printf("%c", u_string[i]);
    }
    printf("\n");
    ge25519_tobytes(a_one, &Announcement_one);
    printf("Announcement1 (verif):");
    for (int i = 0; i<32; i++) {
        printf("%c", a_one[i]);
    }
    printf("\n");
    ge25519_tobytes(a_two, &Announcement_two);
    printf("Announcement2 (verif):");
    for (int i = 0; i<32; i++) {
        printf("%c", a_two[i]);
    }
    printf("\n");
    _vrf_twohashdh_hash_points_verif(challenge_check, Y_point, &H_point, &U_point, &Announcement_one, &Announcement_two);

    printf("in the comparison\n");
    return crypto_verify_32(challenge_scalar, challenge_check);
}

int
crypto_vrf_twohashdh_verify(unsigned char output[crypto_vrf_twohashdh_OUTPUTBYTES],
                              const unsigned char pk[crypto_vrf_twohashdh_PUBLICKEYBYTES],
                              const unsigned char proof[crypto_vrf_twohashdh_PROOFBYTES],
                              const unsigned char *msg, const unsigned long long msglen)
{
    ge25519_p3 Y;
    if (vrf_validate_key(&Y, pk) != 0) {
        printf("failed with key\n");
    }

    if (vrf_verify(&Y, proof, msg, msglen) != 0) {
        printf("failed proof\n");
    }

    if ((vrf_validate_key(&Y, pk) == 0) && (vrf_verify(&Y, proof, msg, msglen) == 0)) {
        return crypto_vrf_twohashdh_proof_to_hash(output, proof, msg, msglen);
    } else {
        return -1;
    }
}