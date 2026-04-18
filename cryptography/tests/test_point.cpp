#include "common/common.hpp"
#include "ec/curve.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("P-256: generator is on curve", "[ec]") {
    REQUIRE(P256::on_curve(P256::G));
}

TEST_CASE("P-256: point at infinity is identity", "[ec]") {
    JacobianPoint G(P256::G);
    JacobianPoint inf;

    REQUIRE((G + inf).to_affine() == P256::G);
    REQUIRE((inf + G).to_affine() == P256::G);
}

TEST_CASE("P-256: point negation yields infinity", "[ec]") {
    JacobianPoint G(P256::G);
    REQUIRE((G + (-G)).is_inf());
}

TEST_CASE("P-256: doubling matches addition", "[ec]") {
    JacobianPoint G(P256::G);
    REQUIRE(G.doubled().to_affine() == (G + G).to_affine());
}

TEST_CASE("P-256: scalar multiplication — 1*G == G", "[ec]") {
    JacobianPoint G(P256::G);
    REQUIRE((G * mpz_class(1)).to_affine() == P256::G);
}

TEST_CASE("P-256: scalar multiplication — 2*G == G+G", "[ec]") {
    JacobianPoint G(P256::G);
    REQUIRE((G * mpz_class(2)).to_affine() == (G + G).to_affine());
}

TEST_CASE("P-256: scalar multiplication — n*G == infinity", "[ec]") {
    JacobianPoint G(P256::G);
    REQUIRE((G * P256::n).is_inf());
}

TEST_CASE("P-256: result of scalar multiplication is on curve", "[ec]") {
    JacobianPoint G(P256::G);
    AffinePoint R = (G * mpz_class(42)).to_affine();
    REQUIRE(P256::on_curve(R));
}

TEST_CASE("P-256: (n-1)*G == -G", "[ec]") {
    // (n-1)*G must equal -G: same x-coordinate, negated y-coordinate.
    // This follows directly from the group order: n*G = O, so (n-1)*G = -G.
    JacobianPoint G(P256::G);
    AffinePoint result = (G * (P256::n - 1)).to_affine();

    REQUIRE(result.x == P256::G.x);
    REQUIRE(result.y == -P256::G.y);
}
