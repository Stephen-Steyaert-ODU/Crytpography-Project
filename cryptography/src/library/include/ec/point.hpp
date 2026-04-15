#pragma once

#include "field/field_element.hpp"
#include "common/common.hpp"

/**
 * @brief A point on P-256 in affine coordinates (x, y), or the point at infinity.
 *
 * Affine points are used for input/output and serialisation. All heavy
 * arithmetic is done in Jacobian coordinates via JacobianPoint.
 */
struct AffinePoint {
    FieldElement x;
    FieldElement y;
    bool inf; ///< True if this is the point at infinity (the group identity).

    /** @brief Constructs the point at infinity. */
    AffinePoint() : inf(true) {}

    /** @brief Constructs the affine point (x, y). */
    AffinePoint(FieldElement x, FieldElement y)
        : x(std::move(x)), y(std::move(y)), inf(false) {}

    bool operator==(const AffinePoint& o) const;
    bool operator!=(const AffinePoint& o) const { return !(*this == o); }
};

/**
 * @brief A point on P-256 in Jacobian projective coordinates (X : Y : Z).
 *
 * The affine point (x, y) is represented as (X/Z², Y/Z³, Z) with Z ≠ 0.
 * Z = 0 is the conventional representation of the point at infinity.
 *
 * All arithmetic uses formulas optimised for the P-256 curve coefficient a = -3:
 *   - Doubling:  dbl-2001-b  (https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html)
 *   - Addition:  add-2007-bl (same source)
 */
class JacobianPoint {
public:
    FieldElement X, Y, Z;

    /** @brief Constructs the point at infinity (Z = 0). */
    JacobianPoint();

    /** @brief Lifts an affine point into Jacobian coordinates (Z = 1). */
    explicit JacobianPoint(const AffinePoint& p);

    /** @brief Constructs directly from Jacobian coordinates. */
    JacobianPoint(FieldElement X, FieldElement Y, FieldElement Z);

    /** @brief Returns true if this is the point at infinity (Z = 0). */
    bool is_inf() const;

    /** @brief Converts to affine by computing (X/Z², Y/Z³). */
    AffinePoint to_affine() const;

    /**
     * @brief Point doubling: returns 2·P.
     *
     * Uses the dbl-2001-b formula with the a = -3 optimisation:
     *   alpha = 3·(X - Z²)·(X + Z²)  instead of  3·X² + a·Z⁴.
     */
    JacobianPoint doubled() const;

    /**
     * @brief Point addition: returns P + Q.
     *
     * Uses the add-2007-bl formula. Handles the degenerate cases:
     *   - P = O or Q = O  →  returns the other operand.
     *   - P = Q           →  delegates to doubled().
     *   - P = -Q          →  returns the point at infinity.
     */
    JacobianPoint operator+(const JacobianPoint& rhs) const;

    /**
     * @brief Scalar multiplication via the Montgomery ladder.
     *
     * Processes scalar bits from MSB to LSB, performing the same sequence
     * of operations regardless of each bit value — providing constant-time
     * execution with respect to the scalar's bit pattern.
     */
    JacobianPoint operator*(const mpz_class& k) const;

    /** @brief Negation: returns -P = (X : -Y : Z). */
    JacobianPoint operator-() const;
};
