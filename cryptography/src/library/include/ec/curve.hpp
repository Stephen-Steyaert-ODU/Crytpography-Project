#pragma once

#include "ec/point.hpp"

/**
 * @brief P-256 (secp256r1 / prime256v1) curve parameters and utilities.
 *
 * Domain parameters as specified in NIST FIPS 186-4, Appendix D.1.2.3.
 * The curve equation is: y² ≡ x³ + ax + b  (mod p)
 */
namespace P256 {

/** @brief Curve coefficient a = p - 3  (i.e. -3 mod p). */
extern const FieldElement a;

/** @brief Curve coefficient b. */
extern const FieldElement b;

/** @brief Base point / generator G. */
extern const AffinePoint G;

/** @brief Group order n (number of points on the curve). */
extern const mpz_class n;

/**
 * @brief Returns true iff @p pt lies on the P-256 curve.
 *
 * Checks the Weierstrass equation: y² ≡ x³ + ax + b (mod p).
 * The point at infinity always passes.
 */
bool on_curve(const AffinePoint& pt);

} // namespace P256
