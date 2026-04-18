#include "common/common.hpp"
#include "crypto/aes_gcm.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("AES-GCM: encrypt/decrypt round-trip", "[aesgcm]") {
    std::array<uint8_t,32> key{}; key.fill(0x42);
    std::array<uint8_t,12> iv{};  iv.fill(0x24);
    std::vector<uint8_t> plaintext = {'h','e','l','l','o'};

    auto ct        = AesGcm::encrypt(key, iv, plaintext);
    auto recovered = AesGcm::decrypt(key, iv, ct.data, ct.tag);

    REQUIRE(recovered == plaintext);
}

TEST_CASE("AES-GCM: ciphertext differs from plaintext", "[aesgcm]") {
    std::array<uint8_t,32> key{}; key.fill(0x11);
    std::array<uint8_t,12> iv{};  iv.fill(0x22);
    std::vector<uint8_t> plaintext = {'s','e','c','r','e','t'};

    auto ct = AesGcm::encrypt(key, iv, plaintext);
    REQUIRE(ct.data != plaintext);
}

TEST_CASE("AES-GCM: tampered ciphertext fails authentication", "[aesgcm]") {
    std::array<uint8_t,32> key{}; key.fill(0x11);
    std::array<uint8_t,12> iv{};  iv.fill(0x22);
    std::vector<uint8_t> plaintext = {'s','e','c','r','e','t'};

    auto ct = AesGcm::encrypt(key, iv, plaintext);
    ct.data[0] ^= 0xFF;

    REQUIRE_THROWS_AS(AesGcm::decrypt(key, iv, ct.data, ct.tag),
                      std::invalid_argument);
}

TEST_CASE("AES-GCM: tampered tag fails authentication", "[aesgcm]") {
    std::array<uint8_t,32> key{}; key.fill(0x33);
    std::array<uint8_t,12> iv{};  iv.fill(0x44);
    std::vector<uint8_t> plaintext = {'d','a','t','a'};

    auto ct = AesGcm::encrypt(key, iv, plaintext);
    ct.tag[0] ^= 0xFF;

    REQUIRE_THROWS_AS(AesGcm::decrypt(key, iv, ct.data, ct.tag),
                      std::invalid_argument);
}

TEST_CASE("AES-GCM: different keys produce different ciphertext", "[aesgcm]") {
    std::array<uint8_t,32> key_a{}; key_a.fill(0xAA);
    std::array<uint8_t,32> key_b{}; key_b.fill(0xBB);
    std::array<uint8_t,12> iv{};    iv.fill(0x00);
    std::vector<uint8_t> plaintext(16, 0x01);

    REQUIRE(AesGcm::encrypt(key_a, iv, plaintext).data !=
            AesGcm::encrypt(key_b, iv, plaintext).data);
}

TEST_CASE("AES-GCM: empty plaintext round-trip", "[aesgcm]") {
    std::array<uint8_t,32> key{}; key.fill(0x55);
    std::array<uint8_t,12> iv{};  iv.fill(0x66);
    std::vector<uint8_t> plaintext;

    auto ct        = AesGcm::encrypt(key, iv, plaintext);
    auto recovered = AesGcm::decrypt(key, iv, ct.data, ct.tag);

    REQUIRE(recovered.empty());
}
