/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef OTRNG_CLIENT_PROFILE_H
#define OTRNG_CLIENT_PROFILE_H

#include <stdint.h>

#include <libotr/privkey.h>

#include "keys.h"
#include "mpi.h"
#include "shared.h"
#include "str.h"

#define OTRNG_DH1536_MOD_LEN_BYTES 192

#define DSA_PUBKEY_MAX_BYTES (2 + 4 * (4 + OTRNG_DH1536_MOD_LEN_BYTES))
#define OTRv3_DSA_SIG_BYTES 40

#define OTRNG_CLIENT_PROFILE_FIELDS_MAX_BYTES(v)                               \
  (2 + 4                      /* instance tag */                               \
   + 2 + ED448_PUBKEY_BYTES   /* Ed448 pub key */                              \
   + 2 + v                    /* Versions */                                   \
   + 2 + 8                    /* Expiration */                                 \
   + 2 + DSA_PUBKEY_MAX_BYTES /* DSA pubkey */                                 \
   + 2 + OTRv3_DSA_SIG_BYTES  /* Transitional signature */                     \
  )

#define OTRNG_CLIENT_PROFILE_MAX_BYTES(v)                                      \
  (4 +                                      /* num fields */                   \
   OTRNG_CLIENT_PROFILE_FIELDS_MAX_BYTES(v) /* Fields */                       \
   + ED448_SIGNATURE_BYTES                  /* Client Profile Signature */     \
  )

typedef struct client_profile_s {
  uint32_t sender_instance_tag;
  otrng_public_key_p long_term_pub_key;
  char *versions;
  uint64_t expires;
  uint8_t *dsa_key;
  size_t dsa_key_len;
  uint8_t *transitional_signature;

  eddsa_signature_p signature;
} client_profile_s, client_profile_p[1];

INTERNAL void otrng_client_profile_copy(client_profile_s *dst,
                                        const client_profile_s *src);

INTERNAL void otrng_client_profile_destroy(client_profile_s *profile);

INTERNAL void otrng_client_profile_free(client_profile_s *profile);

INTERNAL otrng_result otrng_client_profile_deserialize(client_profile_s *target,
                                                       const uint8_t *buffer,
                                                       size_t buflen,
                                                       size_t *nread);

INTERNAL otrng_result otrng_client_profile_asprintf(
    uint8_t **dst, size_t *nbytes, const client_profile_s *profile);

INTERNAL client_profile_s *
otrng_client_profile_build(uint32_t instance_tag, const char *versions,
                           const otrng_keypair_s *keypair);

INTERNAL otrng_bool otrng_client_profile_valid(
    const client_profile_s *profile, const uint32_t sender_instance_tag);

INTERNAL otrng_result otrng_client_profile_set_dsa_key_mpis(
    client_profile_s *profile, const uint8_t *mpis, size_t mpis_len);

INTERNAL otrng_result otrng_client_profile_transitional_sign(
    client_profile_s *profile, OtrlPrivKey *privkey);

#ifdef OTRNG_USER_PROFILE_PRIVATE

tstatic client_profile_s *client_profile_new(const char *versions);

tstatic otrng_result client_profile_sign(client_profile_s *profile,
                                         const otrng_keypair_s *keypair);

tstatic otrng_result client_profile_body_asprintf(
    uint8_t **dst, size_t *nbytes, const client_profile_s *profile);

tstatic otrng_bool
client_profile_verify_signature(const client_profile_s *profile);

tstatic otrng_result
client_profile_verify_transitional_signature(const client_profile_s *profile);

#endif

#endif
