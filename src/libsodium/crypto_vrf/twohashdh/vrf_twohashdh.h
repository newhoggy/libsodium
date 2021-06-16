#ifndef vrf_twohashdh_H
#define vrf_twohashdh_H

static const unsigned char SUITE = 0x04; /* ECVRF-ED25519-SHA512-Elligator2 */

int _vrf_twohashdh_decode_proof(ge25519_p3 *Gamma, unsigned char c[16],
                                  unsigned char s[32],
                                  const unsigned char pi[96]);

void _vrf_twohashdh_hash_to_curve_elligator2_25519(unsigned char H_string[32],
//                                                     const ge25519_p3 *Y_point,
                                                     const unsigned char *alpha,
                                                     const unsigned long long alphalen);

void
_vrf_twohashdh_hash_points(unsigned char challenge_scalar[16], const ge25519_p3 *Y_point,
                           const ge25519_p3 *H_point, const ge25519_p3 *U_point,
                           const ge25519_p3 *Announcement_one, const ge25519_p3 *Announcement_two);

// todo: probably find an alternative
void
_vrf_twohashdh_hash_points_verif(unsigned char challenge_scalar[16], const ge25519_p3 *Y_point,
                        const ge25519_p3 *H_point, const ge25519_p3 *U_point,
                        const ge25519_p2 *Announcement_one, const ge25519_p2 *Announcement_two);

#endif