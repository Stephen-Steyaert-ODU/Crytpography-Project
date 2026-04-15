#pragma once

#include "ec/point.hpp"

/**
 * @brief ECDSA (Elliptic Curve Digital Signature Algorithm) over P-256.
 *
 * Signing and verification are performed entirely with hand-rolled EC
 * arithmetic. OpenSSL is used only for SHA-256 hashing of messages.
 */
namespace ECDSA {

/** @brief A P-256 ECDSA signature (r, s). */
struct Signature {
    mpz_class r;
    mpz_class s;
};

/**
 * @brief Computes SHA-256 of @p data using OpenSSL EVP.
 * @return 32-byte digest.
 * @throws std::runtime_error on OpenSSL failure.
 */
std::vector<uint8_t> sha256(std::span<const uint8_t> data);

/**
 * @brief Signs a 32-byte message hash with @p priv.
 *
 * Algorithm:
 *   1. k = random scalar in [1, n-1] from /dev/urandom.
 *   2. R = k·G;  r = R.x mod n  (retry if r = 0).
 *   3. s = k⁻¹·(hash + r·priv) mod n  (retry if s = 0).
 *
 * @param priv     Private scalar k ∈ [1, n-1].
 * @param msg_hash 32-byte SHA-256 digest of the message.
 *
 * @throws std::runtime_error on /dev/urandom failure.
 */
Signature sign(const mpz_class& priv, std::span<const uint8_t> msg_hash);

/**
 * @brief Verifies a signature against a public key and message hash.
 *
 * Algorithm:
 *   1. w  = s⁻¹ mod n.
 *   2. u1 = hash·w mod n,  u2 = r·w mod n.
 *   3. R  = u1·G + u2·pub.
 *   4. Accept iff r ≡ R.x (mod n).
 *
 * @param pub      Signer's public key.
 * @param msg_hash 32-byte SHA-256 digest of the message.
 * @param sig      Signature to verify.
 *
 * @return true if the signature is valid, false otherwise.
 */
bool verify(const AffinePoint& pub, std::span<const uint8_t> msg_hash, const Signature& sig);

/**
 * @brief Writes the signature to @p path as r (32 bytes) || s (32 bytes) = 64 bytes.
 * @throws std::runtime_error on I/O failure.
 */
void save_signature(const std::string& path, const Signature& sig);

/**
 * @brief Reads a 64-byte signature from @p path.
 * @throws std::runtime_error on I/O failure or wrong file size.
 */
Signature load_signature(const std::string& path);

} // namespace ECDSA
