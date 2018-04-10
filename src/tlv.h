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

#ifndef OTRNG_TLV_H
#define OTRNG_TLV_H

#include <stddef.h>
#include <stdint.h>

#include "shared.h"

typedef enum {
  OTRNG_TLV_NONE = -1,
  OTRNG_TLV_PADDING = 0,
  OTRNG_TLV_DISCONNECTED = 1,
  OTRNG_TLV_SMP_MSG_1 = 2,
  OTRNG_TLV_SMP_MSG_2 = 3,
  OTRNG_TLV_SMP_MSG_3 = 4,
  OTRNG_TLV_SMP_MSG_4 = 5,
  OTRNG_TLV_SMP_ABORT = 6,
  OTRNG_TLV_SYM_KEY = 7
} tlv_type_t;

// TODO: do we really want the TLVs to be a linked list?
typedef struct tlv_s {
  tlv_type_t type;
  uint16_t len;
  uint8_t *data;
} tlv_t;

typedef struct tlv_list_s {
  tlv_t *data;
  struct tlv_list_s *next;
} tlv_list_t;

INTERNAL void otrng_tlv_list_free(tlv_list_t *tlvs);

INTERNAL tlv_list_t *otrng_tlv_list_one(tlv_t *tlv);

INTERNAL tlv_t *otrng_tlv_disconnected_new(void);

INTERNAL tlv_list_t *otrng_parse_tlvs(const uint8_t *src, size_t len);

INTERNAL tlv_t *otrng_tlv_new(const uint16_t type, const uint16_t len,
                              const uint8_t *data);

INTERNAL tlv_list_t *otrng_append_tlv(tlv_list_t *tlvs, tlv_t *tlv);

INTERNAL tlv_list_t *otrng_append_padding_tlv(tlv_list_t *tlvs,
                                              int message_len);

#ifdef OTRNG_TLV_PRIVATE

tstatic void tlv_free(tlv_t *tlv);

#endif

#endif
