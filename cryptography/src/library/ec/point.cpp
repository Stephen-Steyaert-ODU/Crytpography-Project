#include "ec/point.hpp"

// ── AffinePoint ───────────────────────────────────────────────────────────────

bool AffinePoint::operator==(const AffinePoint& o) const {
    if (inf && o.inf) return true;
    if (inf != o.inf) return false;
    return x == o.x && y == o.y;
}

// ── JacobianPoint — constructors ──────────────────────────────────────────────

JacobianPoint::JacobianPoint()
    // Canonical infinity: Z = 0. X and Y are arbitrary; set to (0:1:0).
    : X(FieldElement(0L)), Y(FieldElement(1L)), Z(FieldElement(0L)) {}

JacobianPoint::JacobianPoint(const AffinePoint& p) {
    if (p.inf) {
        X = FieldElement(0L);
        Y = FieldElement(1L);
        Z = FieldElement(0L);
    } else {
        X = p.x;
        Y = p.y;
        Z = FieldElement(1L);
    }
}

JacobianPoint::JacobianPoint(FieldElement x, FieldElement y, FieldElement z)
    : X(std::move(x)), Y(std::move(y)), Z(std::move(z)) {}

// ── JacobianPoint — utilities ─────────────────────────────────────────────────

bool JacobianPoint::is_inf() const {
    return Z.is_zero();
}

AffinePoint JacobianPoint::to_affine() const {
    if (is_inf()) return AffinePoint{};
    FieldElement zi  = Z.inv();
    FieldElement zi2 = zi * zi;
    FieldElement zi3 = zi2 * zi;
    return AffinePoint(X * zi2, Y * zi3);
}

// ── JacobianPoint — arithmetic ────────────────────────────────────────────────

/**
 * Point doubling using formula dbl-2001-b, optimised for a = -3.
 *
 * Source: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
 *
 *   delta = Z1²
 *   gamma = Y1²
 *   beta  = X1·gamma
 *   alpha = 3·(X1 - delta)·(X1 + delta)   ← a=-3 shortcut
 *   X3    = alpha² - 8·beta
 *   Z3    = (Y1 + Z1)² - gamma - delta
 *   Y3    = alpha·(4·beta - X3) - 8·gamma²
 */
JacobianPoint JacobianPoint::doubled() const {
    if (is_inf() || Y.is_zero()) return JacobianPoint{};

    FieldElement delta = Z * Z;
    FieldElement gamma = Y * Y;
    FieldElement beta  = X * gamma;
    FieldElement alpha = FieldElement(3L) * (X - delta) * (X + delta);

    FieldElement X3 = alpha * alpha - FieldElement(8L) * beta;
    FieldElement Z3 = (Y + Z) * (Y + Z) - gamma - delta;
    FieldElement Y3 = alpha * (FieldElement(4L) * beta - X3) - FieldElement(8L) * gamma * gamma;

    return JacobianPoint(X3, Y3, Z3);
}

/**
 * Point addition using formula add-2007-bl.
 *
 * Source: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
 *
 *   Z1Z1 = Z1²,   Z2Z2 = Z2²
 *   U1 = X1·Z2Z2, U2 = X2·Z1Z1
 *   S1 = Y1·Z2·Z2Z2, S2 = Y2·Z1·Z1Z1
 *   H  = U2 - U1
 *   I  = (2H)²,  J = H·I
 *   r  = 2·(S2 - S1)
 *   V  = U1·I
 *   X3 = r² - J - 2V
 *   Y3 = r·(V - X3) - 2·S1·J
 *   Z3 = ((Z1+Z2)² - Z1Z1 - Z2Z2)·H
 */
JacobianPoint JacobianPoint::operator+(const JacobianPoint& rhs) const {
    if (is_inf()) return rhs;
    if (rhs.is_inf()) return *this;

    FieldElement Z1Z1 = Z     * Z;
    FieldElement Z2Z2 = rhs.Z * rhs.Z;
    FieldElement U1   = X     * Z2Z2;
    FieldElement U2   = rhs.X * Z1Z1;
    FieldElement S1   = Y     * rhs.Z * Z2Z2;
    FieldElement S2   = rhs.Y * Z     * Z1Z1;
    FieldElement H    = U2 - U1;
    FieldElement R    = FieldElement(2L) * (S2 - S1);  // r = 2*(S2-S1) per add-2007-bl

    if (H.is_zero()) {
        // Same x-coordinate: either P = Q (double) or P = -Q (infinity).
        return R.is_zero() ? doubled() : JacobianPoint{};
    }

    FieldElement I  = FieldElement(4L) * H * H;    // (2H)²
    FieldElement J  = H * I;
    FieldElement V  = U1 * I;

    FieldElement X3 = R * R - J - FieldElement(2L) * V;
    FieldElement Y3 = R * (V - X3) - FieldElement(2L) * S1 * J;
    FieldElement Z3 = ((Z + rhs.Z) * (Z + rhs.Z) - Z1Z1 - Z2Z2) * H;

    return JacobianPoint(X3, Y3, Z3);
}

JacobianPoint JacobianPoint::operator-() const {
    return JacobianPoint(X, -Y, Z);
}

/**
 * Scalar multiplication via the Montgomery ladder.
 *
 * Processes bits from MSB to LSB. At each step the same pair of operations
 * (one addition, one doubling) is performed regardless of the bit value,
 * making the runtime independent of the scalar's bit pattern.
 *
 * Invariant: R1 = R0 + P throughout, where P is the initial point.
 */
JacobianPoint JacobianPoint::operator*(const mpz_class& k) const {
    if (k == 0 || is_inf()) return JacobianPoint{};
    if (k < 0) return (-*this) * (-k);

    JacobianPoint R0;        // point at infinity
    JacobianPoint R1 = *this;

    int bits = static_cast<int>(mpz_sizeinbase(k.get_mpz_t(), 2));
    for (int i = bits - 1; i >= 0; --i) {
        if (mpz_tstbit(k.get_mpz_t(), i)) {
            R0 = R0 + R1;
            R1 = R1.doubled();
        } else {
            R1 = R0 + R1;
            R0 = R0.doubled();
        }
    }
    return R0;
}
