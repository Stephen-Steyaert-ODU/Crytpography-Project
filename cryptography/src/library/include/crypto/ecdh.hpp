#pragma once

#include "ec/point.hpp"

/**
 * @brief ECDH (Elliptic Curve Diffie-Hellman) over P-256.
 *
 * Private keys are scalars in [1, n-1]. Public keys are uncompressed P-256
 * points serialised as 0x04 || x (32 bytes) || y (32 bytes) = 65 bytes.
 * Shared secrets are the x-coordinate of the resulting point, as 32
 * big-endian bytes.
 */
namespace ECDH {

/** @brief A P-256 keypair. */
struct KeyPair {
    mpz_class   priv; ///< Private scalar k ∈ [1, n-1].
    AffinePoint pub;  ///< Public point Q = k·G.
};

/**
 * @brief Generates a random P-256 keypair.
 *
 * Reads 32 bytes from /dev/urandom and reduces mod n. Retries if the
 * result is zero (astronomically unlikely in practice).
 *
 * @throws std::runtime_error if /dev/urandom cannot be read.
 */
KeyPair generate_keypair();

/**
 * @brief Derives the public key from a private scalar.
 * @return Q = priv · G on P-256.
 */
AffinePoint public_from_private(const mpz_class& priv);

/**
 * @brief Computes the ECDH shared secret.
 *
 * @return x-coordinate of (priv · peer_pub) as 32 big-endian bytes.
 * @throws std::invalid_argument if peer_pub is not on the P-256 curve.
 */
std::vector<uint8_t> shared_secret(const mpz_class& priv, const AffinePoint& peer_pub);

/**
 * @brief Writes the private key to @p path as 32 big-endian bytes.
 * @throws std::runtime_error on I/O failure.
 */
void save_private_key(const std::string& path, const mpz_class& priv);

/**
 * @brief Writes the public key to @p path as 0x04 || x (32) || y (32) = 65 bytes.
 * @throws std::runtime_error on I/O failure.
 */
void save_public_key(const std::string& path, const AffinePoint& pub);

/**
 * @brief Reads a 32-byte private key from @p path.
 * @throws std::runtime_error on I/O failure or wrong file size.
 */
mpz_class load_private_key(const std::string& path);

/**
 * @brief Reads a 65-byte uncompressed public key from @p path.
 * @throws std::runtime_error on I/O failure, wrong size, or invalid 0x04 prefix.
 */
AffinePoint load_public_key(const std::string& path);

} // namespace ECDH
