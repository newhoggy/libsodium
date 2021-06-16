
#include <string.h>

#include "crypto_hash_sha512.h"
#include "crypto_vrf_twohashdh.h"
#include "crypto_core_ed25519.h"
#include "private/ed25519_ref10.h"
#include "randombytes.h"
#include "utils.h"

void
crypto_vrf_twohashdh_keypair(unsigned char pk[crypto_vrf_twohashdh_PUBLICKEYBYTES],
                               unsigned char sk[crypto_vrf_twohashdh_SECRETKEYBYTES])
{
    ge25519_p3 pk_p3;
    crypto_core_ed25519_scalar_random(sk);
    ge25519_scalarmult_base(&pk_p3, sk);

    ge25519_p3_tobytes(pk, &pk_p3);
}
