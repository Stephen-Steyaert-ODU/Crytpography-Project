#include "common/common.hpp"
#include "field/field_element.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("FieldElement: basic arithmetic", "[field]") {
    FieldElement a(mpz_class(7));
    FieldElement b(mpz_class(3));

    REQUIRE((a + b).raw() == 10);
    REQUIRE((a - b).raw() == 4);
    REQUIRE((a * b).raw() == 21);
    REQUIRE((b - a).raw() == FieldElement::prime() - 4); // wraps mod p
}

TEST_CASE("FieldElement: modular inverse", "[field]") {
    FieldElement a(mpz_class(7));
    REQUIRE((a * a.inv()).raw() == 1);
}

TEST_CASE("FieldElement: negation", "[field]") {
    FieldElement a(mpz_class(42));
    REQUIRE((a + (-a)).is_zero());
}

TEST_CASE("FieldElement: zero edge cases", "[field]") {
    FieldElement zero;
    REQUIRE(zero.is_zero());
    REQUIRE((-zero).is_zero());
    REQUIRE_THROWS(zero.inv());
}

TEST_CASE("FieldElement: square root", "[field]") {
    FieldElement four(mpz_class(4));
    REQUIRE(four.is_square());
    FieldElement r = four.sqrt();
    REQUIRE(r * r == four);
}

TEST_CASE("FieldElement: non-residue is not a square", "[field]") {
    // 3 is not a quadratic residue mod P-256's prime.
    FieldElement three(mpz_class(3));
    REQUIRE_FALSE(three.is_square());
}

TEST_CASE("FieldElement: byte round-trip", "[field]") {
    FieldElement orig(mpz_class("DEADBEEFCAFE1234", 16));
    unsigned char buf[32];
    orig.to_bytes(buf);
    REQUIRE(FieldElement::from_bytes(buf) == orig);
}

TEST_CASE("FieldElement: hex round-trip", "[field]") {
    FieldElement orig(mpz_class("AABBCCDD", 16));
    // to_hex produces 64-char zero-padded string
    REQUIRE(orig.to_hex().size() == 64);
    REQUIRE(FieldElement(orig.to_hex()) == orig);
}
