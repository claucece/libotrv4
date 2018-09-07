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

#include "prekey_messages.h"
#include "client_profile.h"
#include "deserialize.h"
#include "prekey_client.h"

INTERNAL otrng_result otrng_prekey_success_message_deserialize(
    otrng_prekey_success_message_s *dst, const uint8_t *src, size_t src_len) {
  const uint8_t *cursor = src;
  int64_t len = src_len;
  size_t read = 0;

  uint16_t protocol_version = 0;
  if (!otrng_deserialize_uint16(&protocol_version, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (protocol_version != OTRNG_PROTOCOL_VERSION_4) {
    return OTRNG_ERROR;
  }

  uint8_t message_type = 0;
  if (!otrng_deserialize_uint8(&message_type, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (message_type != OTRNG_PREKEY_SUCCESS_MSG) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&dst->client_instance_tag, cursor, len,
                                &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  return otrng_deserialize_bytes_array(dst->success_mac, HASH_BYTES, cursor,
                                       len);
}

INTERNAL otrng_result otrng_prekey_dake3_message_deserialize(
    otrng_prekey_dake3_message_s *dst, const uint8_t *src, size_t src_len) {
  const uint8_t *cursor = src;
  int64_t len = src_len;
  size_t read = 0;

  uint16_t protocol_version = 0;
  if (!otrng_deserialize_uint16(&protocol_version, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (protocol_version != OTRNG_PROTOCOL_VERSION_4) {
    return OTRNG_ERROR;
  }

  uint8_t message_type = 0;
  if (!otrng_deserialize_uint8(&message_type, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (message_type != OTRNG_PREKEY_DAKE3_MSG) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&dst->client_instance_tag, cursor, len,
                                &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (!otrng_deserialize_ring_sig(dst->sigma, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (!otrng_deserialize_data(&dst->message, &dst->message_len, cursor, len,
                              &read)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_prekey_publication_message_deserialize(
    otrng_prekey_publication_message_s *dst, const uint8_t *src,
    size_t src_len) {
  const uint8_t *cursor = src;
  int64_t len = src_len;
  size_t read = 0;

  uint16_t protocol_version = 0;
  if (!otrng_deserialize_uint16(&protocol_version, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (protocol_version != OTRNG_PROTOCOL_VERSION_4) {
    return OTRNG_ERROR;
  }

  uint8_t message_type = 0;
  if (!otrng_deserialize_uint8(&message_type, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (message_type != OTRNG_PREKEY_PUBLICATION_MSG) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint8(&dst->num_prekey_messages, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  dst->prekey_messages =
      malloc(dst->num_prekey_messages * sizeof(dake_prekey_message_s *));
  if (!dst->prekey_messages) {
    return OTRNG_ERROR;
  }

  for (int i = 0; i < dst->num_prekey_messages; i++) {
    dst->prekey_messages[i] = NULL;
  }

  for (int i = 0; i < dst->num_prekey_messages; i++) {
    dst->prekey_messages[i] = malloc(sizeof(dake_prekey_message_s));
    if (!dst->prekey_messages[i]) {
      return OTRNG_ERROR;
    }
    if (!otrng_dake_prekey_message_deserialize(dst->prekey_messages[i], cursor,
                                               len, &read)) {
      return OTRNG_ERROR;
    }

    cursor += read;
    len -= read;
  }

  // TODO: we are assuming there is a client profile
  uint8_t num_client_profile;
  if (!otrng_deserialize_uint8(&num_client_profile, cursor, len, &read)) {
    return OTRNG_ERROR;
  }
  cursor += read;
  len -= read;

  dst->client_profile = malloc(OTRNG_CLIENT_PROFILE_MAX_BYTES(4));
  if (!dst->client_profile) {
    return OTRNG_ERROR;
  }

  if (!otrng_client_profile_deserialize(dst->client_profile, cursor, len,
                                        &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  // TODO: we are assuming there is a prekey profile
  uint8_t num_prekey_profile;
  if (!otrng_deserialize_uint8(&num_prekey_profile, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  dst->prekey_profile = malloc(len - HASH_BYTES);
  if (!dst->prekey_profile) {
    return OTRNG_ERROR;
  }

  if (!otrng_prekey_profile_deserialize(dst->prekey_profile, cursor, len,
                                        &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  uint8_t mac[HASH_BYTES];

  if (!otrng_deserialize_bytes_array(mac, HASH_BYTES, cursor, len)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}
