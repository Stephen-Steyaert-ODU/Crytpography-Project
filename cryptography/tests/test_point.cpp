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

TEST_CASE("P-256: NIST test vector — 2*G coordinates", "[ec]") {
    // Known coordinates of 2*G on P-256 (NIST FIPS 186-4).
    JacobianPoint G(P256::G);
    AffinePoint two_G = (G * mpz_class(2)).to_affine();

    FieldElement expected_x("7CF27B188D034F7E8A52380304B51AC3C74355B0A6B48EE64B0CE280B93A59E");
    FieldElement expected_y("07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1");

    REQUIRE(two_G.x == expected_x);
    REQUIRE(two_G.y == expected_y);
}
