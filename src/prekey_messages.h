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

#ifndef OTRNG_PREKEY_MESSAGES_H
#define OTRNG_PREKEY_MESSAGES_H

#include "prekey_client.h"

INTERNAL otrng_result otrng_prekey_success_message_deserialize(
    otrng_prekey_success_message_s *dst, const uint8_t *src, size_t src_len);

INTERNAL otrng_result otrng_prekey_dake3_message_deserialize(
    otrng_prekey_dake3_message_s *dst, const uint8_t *src, size_t src_len);

INTERNAL otrng_result otrng_prekey_publication_message_deserialize(
    otrng_prekey_publication_message_s *dst, const uint8_t *src,
    size_t src_len);

#endif
