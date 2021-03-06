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

#ifndef OTRNG_KEYS_H
#define OTRNG_KEYS_H

#include <goldilocks.h>
#include <goldilocks/ed448.h>

#include "dh.h"
#include "ed448.h"
#include "shared.h"

#define ED448_PUBKEY_TYPE 0x0010
#define ED448_PUBKEY_BYTES 2 + ED448_POINT_BYTES
#define ED448_SHARED_PREKEY_TYPE 0x0011
#define ED448_SHARED_PREKEY_BYTES 2 + ED448_POINT_BYTES

typedef ec_point_p otrng_public_key_p;
typedef ec_scalar_p otrng_private_key_p;
typedef ec_point_p otrng_shared_prekey_pub_p;
typedef ec_scalar_p otrng_shared_prekey_priv_p;

/* @secret_information: the long-term key pair lives for as long the client
   decides */
typedef struct otrng_keypair_s {
  uint8_t sym[ED448_PRIVATE_BYTES];

  otrng_public_key_p pub;
  otrng_private_key_p priv;
} otrng_keypair_s, otrng_keypair_p[1];

// TODO: @refactoring @spec implement correctly when the spec comes
typedef struct otrng_shared_prekey_pair_s {
  uint8_t sym[ED448_PRIVATE_BYTES];

  otrng_shared_prekey_pub_p pub;
  otrng_shared_prekey_priv_p priv;
} otrng_shared_prekey_pair_s, otrng_shared_prekey_pair_p[1];

INTERNAL otrng_keypair_s *otrng_keypair_new(void);

INTERNAL void otrng_keypair_generate(otrng_keypair_s *keypair,
                                     const uint8_t sym[ED448_PRIVATE_BYTES]);

INTERNAL void otrng_keypair_free(otrng_keypair_s *keypair);

INTERNAL otrng_result otrng_symmetric_key_serialize(
    char **buffer, size_t *buffer_size, const uint8_t sym[ED448_PRIVATE_BYTES]);

INTERNAL otrng_shared_prekey_pair_s *otrng_shared_prekey_pair_new(void);

INTERNAL void
otrng_shared_prekey_pair_generate(otrng_shared_prekey_pair_s *prekey_pair,
                                  const uint8_t sym[ED448_PRIVATE_BYTES]);

INTERNAL void
otrng_shared_prekey_pair_free(otrng_shared_prekey_pair_s *prekey_pair);

INTERNAL otrng_result otrng_generate_ephemeral_keys(ecdh_keypair_p ecdh,
                                                    dh_keypair_p dh);

/**
 * @brief Derive keys from the extra symmetric key.
 *
 * @param [usage]          The usage for the KDF.
 * @param [use_data]       The context from the TLV 7.
 * @param [use_data_len]   The length of the context.
 * @param [extra_symm_key] The extra symmetric key.
 */
API uint8_t *otrng_derive_key_from_extra_symm_key(
    uint8_t usage, const unsigned char *use_data, size_t use_data_len,
    const unsigned char *extra_symm_key);

#ifdef OTRNG_KEYS_PRIVATE

tstatic void keypair_destroy(otrng_keypair_s *keypair);

tstatic void
shared_prekey_pair_destroy(otrng_shared_prekey_pair_s *prekey_pair);

#endif

#endif
