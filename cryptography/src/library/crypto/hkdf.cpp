#include "common/common.hpp"
#include "crypto/hkdf.hpp"

namespace HKDF {

// SHA-256 digest length in bytes.
static constexpr size_t HASH_LEN = 32;

/**
 * Computes HMAC-SHA256(key, data) into @p out (must be at least 32 bytes).
 * @throws std::runtime_error on OpenSSL failure.
 */
static void hmac_sha256(
    const uint8_t* key,  size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t out[HASH_LEN])
{
    unsigned int len = HASH_LEN;
    if (!HMAC(EVP_sha256(), key, static_cast<int>(key_len),
              data, data_len, out, &len))
        throw std::runtime_error("HKDF: HMAC-SHA256 failed");
}

std::vector<uint8_t> derive(
    std::span<const uint8_t> ikm,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    size_t                   output_len)
{
    if (output_len > 255 * HASH_LEN)
        throw std::invalid_argument("HKDF::derive: requested output_len exceeds RFC 5869 limit");

    // ── Extract ───────────────────────────────────────────────────────────────
    // PRK = HMAC-SHA256(salt, ikm)
    // If salt is empty, RFC 5869 specifies using a zero-filled key of HASH_LEN bytes.
    uint8_t prk[HASH_LEN];
    if (salt.empty()) {
        const uint8_t zero_salt[HASH_LEN] = {};
        hmac_sha256(zero_salt, HASH_LEN, ikm.data(), ikm.size(), prk);
    } else {
        hmac_sha256(salt.data(), salt.size(), ikm.data(), ikm.size(), prk);
    }

    // ── Expand ────────────────────────────────────────────────────────────────
    // T(0) = ""
    // T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
    // OKM  = T(1) || T(2) || ... truncated to output_len bytes
    std::vector<uint8_t> okm;
    okm.reserve(output_len);

    uint8_t t[HASH_LEN] = {};
    size_t  t_len = 0;          // length of T(i-1); 0 for the first iteration
    uint8_t counter = 1;

    while (okm.size() < output_len) {
        // Build the HMAC input: T(i-1) || info || counter
        std::vector<uint8_t> input;
        input.reserve(t_len + info.size() + 1);
        input.insert(input.end(), t, t + t_len);
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter++);

        hmac_sha256(prk, HASH_LEN, input.data(), input.size(), t);
        t_len = HASH_LEN;

        size_t to_copy = std::min(HASH_LEN, output_len - okm.size());
        okm.insert(okm.end(), t, t + to_copy);
    }

    return okm;
}

} // namespace HKDF
