#include "common/common.hpp"
#include "crypto/ecdh.hpp"
#include "crypto/ecdsa.hpp"
#include "ec/curve.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("ECDSA: sign and verify", "[ecdsa]") {
    auto kp  = ECDH::generate_keypair();
    std::vector<uint8_t> msg = {'h','e','l','l','o'};
    auto hash = ECDSA::sha256(msg);
    auto sig  = ECDSA::sign(kp.priv, hash);
    REQUIRE(ECDSA::verify(kp.pub, hash, sig));
}

TEST_CASE("ECDSA: modified message fails verification", "[ecdsa]") {
    auto kp = ECDH::generate_keypair();
    std::vector<uint8_t> msg     = {'h','e','l','l','o'};
    std::vector<uint8_t> msg_bad = {'H','e','l','l','o'};
    auto hash     = ECDSA::sha256(msg);
    auto hash_bad = ECDSA::sha256(msg_bad);
    auto sig = ECDSA::sign(kp.priv, hash);
    REQUIRE_FALSE(ECDSA::verify(kp.pub, hash_bad, sig));
}

TEST_CASE("ECDSA: wrong public key fails verification", "[ecdsa]") {
    auto alice = ECDH::generate_keypair();
    auto bob   = ECDH::generate_keypair();
    std::vector<uint8_t> msg = {'t','e','s','t'};
    auto hash = ECDSA::sha256(msg);
    auto sig  = ECDSA::sign(alice.priv, hash);
    REQUIRE_FALSE(ECDSA::verify(bob.pub, hash, sig));
}

TEST_CASE("ECDSA: r and s are in [1, n-1]", "[ecdsa]") {
    auto kp = ECDH::generate_keypair();
    std::vector<uint8_t> msg = {'m','s','g'};
    auto hash = ECDSA::sha256(msg);
    auto sig  = ECDSA::sign(kp.priv, hash);
    REQUIRE(sig.r >= 1);  REQUIRE(sig.r < P256::n);
    REQUIRE(sig.s >= 1);  REQUIRE(sig.s < P256::n);
}

TEST_CASE("ECDSA: signature file round-trip", "[ecdsa]") {
    auto kp = ECDH::generate_keypair();
    std::vector<uint8_t> msg = {'r','o','u','n','d'};
    auto hash = ECDSA::sha256(msg);
    auto sig  = ECDSA::sign(kp.priv, hash);

    ECDSA::save_signature("/tmp/test.sig", sig);
    auto sig2 = ECDSA::load_signature("/tmp/test.sig");

    REQUIRE(sig2.r == sig.r);
    REQUIRE(sig2.s == sig.s);
    REQUIRE(ECDSA::verify(kp.pub, hash, sig2));
}

TEST_CASE("ECDSA: sha256 produces 32 bytes", "[ecdsa]") {
    std::vector<uint8_t> msg = {'a','b','c'};
    REQUIRE(ECDSA::sha256(msg).size() == 32);
}

TEST_CASE("ECDSA: sha256 is deterministic", "[ecdsa]") {
    std::vector<uint8_t> msg = {'h','e','l','l','o'};
    REQUIRE(ECDSA::sha256(msg) == ECDSA::sha256(msg));
}
