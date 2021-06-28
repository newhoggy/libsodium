
#ifndef crypto_vrf_twohashdh_H
#define crypto_vrf_twohashdh_H

#include <stddef.h>

#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define crypto_vrf_twohashdh_PUBLICKEYBYTES 32U
SODIUM_EXPORT
size_t crypto_vrf_twohashdh_publickeybytes(void);

#define crypto_vrf_twohashdh_SECRETKEYBYTES 64U
SODIUM_EXPORT
size_t crypto_vrf_twohashdh_secretkeybytes(void);

//#define crypto_vrf_ietfdraft03_SEEDBYTES 32U
//SODIUM_EXPORT
//size_t crypto_vrf_ietfdraft03_seedbytes(void);

#define crypto_vrf_twohashdh_PROOFBYTES 96U
SODIUM_EXPORT
size_t crypto_vrf_twohashdh_proofbytes(void);

#define crypto_vrf_twohashdh_OUTPUTBYTES 64U
SODIUM_EXPORT
size_t crypto_vrf_twohashdh_outputbytes(void);

// Generate a keypair.
//
// Thread-safe if sodium_init() has been called first.
SODIUM_EXPORT
void crypto_vrf_twohashdh_keypair(unsigned char *sk);

//
//SODIUM_EXPORT
//int crypto_vrf_ietfdraft03_keypair_from_seed(unsigned char *pk,
//                                             unsigned char *sk,
//                                             const unsigned char *seed);

// Returns 1 if public key is valid (per IETF spec section 5.6.1); 0 if invalid.
SODIUM_EXPORT
int crypto_vrf_twohashdh_is_valid_key(const unsigned char *pk)
__attribute__ ((warn_unused_result));

// Generate a VRF proof for a message using a secret key.
//
// The VRF output hash can be obtained by calling crypto_vrf_proof_to_hash(proof).
//
// Returns 0 on success, -1 on error decoding the (augmented) secret key
//
// This runs in time constant with respect to sk and, fixing a value of mlen,
// runs in time constant with respect to m.
SODIUM_EXPORT
int crypto_vrf_twohashdh_prove(unsigned char *proof, const unsigned char *sk,
                                 const unsigned char *m,
                                 unsigned long long mlen);

// Verify a VRF proof (for a given a public key and message) and validate the
// public key.
//
// For a given public key and message, there are many possible proofs but only
// one possible output hash.
//
// Returns 0 if verification succeeds and -1 on failure. If the public key is
// valid and verification succeeds, the output hash is stored in output.
SODIUM_EXPORT
int crypto_vrf_twohashdh_verify(unsigned char *output,
                                  const unsigned char *pk,
                                  const unsigned char *proof,
                                  const unsigned char *m,
                                  unsigned long long mlen)
__attribute__ ((warn_unused_result));

// Convert a VRF proof to a VRF output.
//
// This function does not verify the proof.
//
// Returns 0 on success, nonzero on error decoding.
SODIUM_EXPORT
int crypto_vrf_twohashdh_proof_to_hash(unsigned char beta[crypto_vrf_twohashdh_OUTPUTBYTES],
                                   const unsigned char pi[crypto_vrf_twohashdh_PROOFBYTES],
                                   const unsigned char *msg, const unsigned long long msglen);

//// Convert a secret key to a public key.
////
//// Constant time.
//SODIUM_EXPORT
//void crypto_vrf_ietfdraft03_sk_to_pk(unsigned char *pk,
//                                     const unsigned char *sk);
//
//// Convert a secret key to the seed that generated it.
////
//// Constant time.
//SODIUM_EXPORT
//void crypto_vrf_ietfdraft03_sk_to_seed(unsigned char *seed,
//                                       const unsigned char *sk);

#ifdef __cplusplus
}
#endif

#endif
