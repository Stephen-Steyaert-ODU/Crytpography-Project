#include "ec/curve.hpp"

namespace P256 {

// a = -3 mod p  =  p - 3
// Hex: FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
const FieldElement a(
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");

// Curve coefficient b (NIST FIPS 186-4, D.1.2.3)
const FieldElement b(
    "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");

// Generator / base point G (NIST FIPS 186-4, D.1.2.3)
const AffinePoint G(
    FieldElement("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
    FieldElement("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));

// Group order n (NIST FIPS 186-4, D.1.2.3)
const mpz_class n(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

bool on_curve(const AffinePoint& pt) {
    if (pt.inf) return true;
    // Check: y² ≡ x³ + ax + b  (mod p)
    FieldElement lhs = pt.y * pt.y;
    FieldElement rhs = pt.x * pt.x * pt.x + a * pt.x + b;
    return lhs == rhs;
}

} // namespace P256
