#include "common/common.hpp"
#include "crypto/aes_gcm.hpp"

namespace AesGcm {

Ciphertext encrypt(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> iv,
    std::span<const uint8_t>     plaintext)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("AesGcm::encrypt: failed to create EVP context");

    Ciphertext result;
    result.data.resize(plaintext.size());

    auto cleanup = [&] { EVP_CIPHER_CTX_free(ctx); };

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        cleanup(); throw std::runtime_error("AesGcm::encrypt: EVP_EncryptInit_ex failed");
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr)) {
        cleanup(); throw std::runtime_error("AesGcm::encrypt: failed to set IV length");
    }
    if (!EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())) {
        cleanup(); throw std::runtime_error("AesGcm::encrypt: failed to set key/IV");
    }

    int out_len = 0;
    if (!EVP_EncryptUpdate(ctx, result.data.data(), &out_len,
                           plaintext.data(), static_cast<int>(plaintext.size()))) {
        cleanup(); throw std::runtime_error("AesGcm::encrypt: EVP_EncryptUpdate failed");
    }

    int final_len = 0;
    if (!EVP_EncryptFinal_ex(ctx, result.data.data() + out_len, &final_len)) {
        cleanup(); throw std::runtime_error("AesGcm::encrypt: EVP_EncryptFinal_ex failed");
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, result.tag.data())) {
        cleanup(); throw std::runtime_error("AesGcm::encrypt: failed to retrieve auth tag");
    }

    cleanup();
    return result;
}

std::vector<uint8_t> decrypt(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> iv,
    std::span<const uint8_t>     ciphertext,
    std::span<const uint8_t, 16> tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("AesGcm::decrypt: failed to create EVP context");

    std::vector<uint8_t> plaintext(ciphertext.size());
    auto cleanup = [&] { EVP_CIPHER_CTX_free(ctx); };

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        cleanup(); throw std::runtime_error("AesGcm::decrypt: EVP_DecryptInit_ex failed");
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr)) {
        cleanup(); throw std::runtime_error("AesGcm::decrypt: failed to set IV length");
    }
    if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())) {
        cleanup(); throw std::runtime_error("AesGcm::decrypt: failed to set key/IV");
    }

    int out_len = 0;
    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                           ciphertext.data(), static_cast<int>(ciphertext.size()))) {
        cleanup(); throw std::runtime_error("AesGcm::decrypt: EVP_DecryptUpdate failed");
    }

    // Set the expected tag before calling Final.
    // The cast to void* is required by the OpenSSL API (tag is read, not written).
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                              const_cast<uint8_t*>(tag.data()))) {
        cleanup(); throw std::runtime_error("AesGcm::decrypt: failed to set auth tag");
    }

    int final_len = 0;
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len);
    cleanup();

    if (ret <= 0)
        throw std::invalid_argument("AesGcm::decrypt: authentication failed — data may be tampered");

    return plaintext;
}

} // namespace AesGcm
