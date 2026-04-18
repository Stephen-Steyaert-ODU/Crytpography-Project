#include "common/common.hpp"
#include "crypto/hkdf.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("HKDF: RFC 5869 test vector 1", "[hkdf]") {
    // https://www.rfc-editor.org/rfc/rfc5869 Appendix A.1
    std::vector<uint8_t> ikm = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    std::vector<uint8_t> salt = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c
    };
    std::vector<uint8_t> info = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9
    };
    std::vector<uint8_t> expected = {
        0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,
        0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
        0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,
        0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
        0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,
        0x58,0x65
    };

    REQUIRE(HKDF::derive(ikm, salt, info, 42) == expected);
}

TEST_CASE("HKDF: output length is respected", "[hkdf]") {
    std::vector<uint8_t> ikm(32, 0x42);
    REQUIRE(HKDF::derive(ikm, {}, {}, 16).size() == 16);
    REQUIRE(HKDF::derive(ikm, {}, {}, 64).size() == 64);
}

TEST_CASE("HKDF: different info produces different output", "[hkdf]") {
    std::vector<uint8_t> ikm(32, 0x01);
    std::vector<uint8_t> info_a = {'A'};
    std::vector<uint8_t> info_b = {'B'};
    REQUIRE(HKDF::derive(ikm, {}, info_a, 32) != HKDF::derive(ikm, {}, info_b, 32));
}

TEST_CASE("HKDF: different salt produces different output", "[hkdf]") {
    std::vector<uint8_t> ikm(32, 0x01);
    std::vector<uint8_t> salt_a = {0xAA};
    std::vector<uint8_t> salt_b = {0xBB};
    REQUIRE(HKDF::derive(ikm, salt_a, {}, 32) != HKDF::derive(ikm, salt_b, {}, 32));
}

TEST_CASE("HKDF: output limit is enforced", "[hkdf]") {
    std::vector<uint8_t> ikm(32, 0x01);
    REQUIRE_THROWS(HKDF::derive(ikm, {}, {}, 255 * 32 + 1));
}
