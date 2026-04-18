#include "common/common.hpp"
#include "crypto/ecdh.hpp"
#include "ec/curve.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("ECDH: generated public key is on curve", "[ecdh]") {
    auto kp = ECDH::generate_keypair();
    REQUIRE(P256::on_curve(kp.pub));
}

TEST_CASE("ECDH: private key is in [1, n-1]", "[ecdh]") {
    auto kp = ECDH::generate_keypair();
    REQUIRE(kp.priv >= 1);
    REQUIRE(kp.priv < P256::n);
}

TEST_CASE("ECDH: shared secret is symmetric", "[ecdh]") {
    auto alice = ECDH::generate_keypair();
    auto bob   = ECDH::generate_keypair();

    REQUIRE(ECDH::shared_secret(alice.priv, bob.pub) ==
            ECDH::shared_secret(bob.priv, alice.pub));
}

TEST_CASE("ECDH: different pairs produce different secrets", "[ecdh]") {
    auto alice = ECDH::generate_keypair();
    auto bob   = ECDH::generate_keypair();
    auto carol = ECDH::generate_keypair();

    REQUIRE(ECDH::shared_secret(alice.priv, bob.pub) !=
            ECDH::shared_secret(alice.priv, carol.pub));
}

TEST_CASE("ECDH: shared secret is 32 bytes", "[ecdh]") {
    auto alice = ECDH::generate_keypair();
    auto bob   = ECDH::generate_keypair();
    REQUIRE(ECDH::shared_secret(alice.priv, bob.pub).size() == 32);
}

TEST_CASE("ECDH: key file round-trip", "[ecdh]") {
    auto kp = ECDH::generate_keypair();

    ECDH::save_private_key("/tmp/test_priv.key", kp.priv);
    ECDH::save_public_key("/tmp/test_pub.key",  kp.pub);

    mpz_class   priv2 = ECDH::load_private_key("/tmp/test_priv.key");
    AffinePoint pub2  = ECDH::load_public_key("/tmp/test_pub.key");

    REQUIRE(priv2 == kp.priv);
    REQUIRE(pub2  == kp.pub);
}
