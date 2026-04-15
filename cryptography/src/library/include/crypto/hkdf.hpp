#pragma once

#include "ec/point.hpp"

/**
 * @brief HKDF-SHA256 key derivation (RFC 5869).
 *
 * Derives cryptographically strong key material from a shared secret (IKM).
 * Built on OpenSSL's HMAC-SHA256.
 */
namespace HKDF {

/**
 * @brief Derives @p output_len bytes of key material from @p ikm.
 *
 * Implements RFC 5869 in two phases:
 *   1. Extract: PRK = HMAC-SHA256(salt, ikm)
 *   2. Expand:  T(i) = HMAC-SHA256(PRK, T(i-1) || info || i),
 *               output = T(1) || T(2) || ... truncated to output_len bytes.
 *
 * @param ikm        Input key material (e.g. ECDH shared secret).
 * @param salt       Optional salt; use an empty span for the zero-salt default.
 * @param info       Context/application-specific string (e.g. "ECIES").
 * @param output_len Number of bytes to produce. Must be ≤ 255 * 32.
 *
 * @throws std::invalid_argument if output_len exceeds the RFC 5869 limit.
 * @throws std::runtime_error    on internal HMAC failure.
 */
std::vector<uint8_t> derive(
    std::span<const uint8_t> ikm,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    size_t                   output_len);

} // namespace HKDF
