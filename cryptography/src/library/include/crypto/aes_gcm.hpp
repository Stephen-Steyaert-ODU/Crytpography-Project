#pragma once

#include "ec/point.hpp"

/**
 * @brief AES-256-GCM authenticated encryption via OpenSSL EVP.
 *
 * Uses a 256-bit key and a 96-bit (12-byte) IV, which is the recommended
 * nonce size for GCM. Produces a 128-bit (16-byte) authentication tag.
 */
namespace AesGcm {

/** @brief Result of an encryption: ciphertext paired with its auth tag. */
struct Ciphertext {
    std::vector<uint8_t>   data; ///< Encrypted bytes (same length as plaintext).
    std::array<uint8_t,16> tag;  ///< 128-bit GCM authentication tag.
};

/**
 * @brief Encrypts @p plaintext with AES-256-GCM.
 *
 * @param key       32-byte encryption key.
 * @param iv        12-byte initialisation vector (must be unique per key).
 * @param plaintext Data to encrypt.
 *
 * @throws std::runtime_error on OpenSSL failure.
 */
Ciphertext encrypt(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> iv,
    std::span<const uint8_t>     plaintext);

/**
 * @brief Decrypts and authenticates @p ciphertext with AES-256-GCM.
 *
 * @param key        32-byte decryption key.
 * @param iv         12-byte initialisation vector (must match encryption).
 * @param ciphertext Encrypted data.
 * @param tag        16-byte authentication tag produced during encryption.
 *
 * @return Recovered plaintext.
 * @throws std::runtime_error    on OpenSSL failure.
 * @throws std::invalid_argument if authentication fails (data was tampered).
 */
std::vector<uint8_t> decrypt(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> iv,
    std::span<const uint8_t>     ciphertext,
    std::span<const uint8_t, 16> tag);

} // namespace AesGcm
