#include "field/field_element.hpp"

#include <iomanip>
#include <sstream>
#include <stdexcept>

// ── prime ─────────────────────────────────────────────────────────────────────

const mpz_class& FieldElement::prime() {
    // P-256 prime: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    static const mpz_class p(
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    return p;
}

// ── constructors ──────────────────────────────────────────────────────────────

FieldElement::FieldElement() : v_(0) {}

FieldElement::FieldElement(long val) {
    v_ = val;
    v_ = ((v_ % prime()) + prime()) % prime();
}

FieldElement::FieldElement(const mpz_class& val) {
    v_ = ((val % prime()) + prime()) % prime();
}

FieldElement::FieldElement(std::string_view hex) {
    v_.set_str(std::string(hex), 16);
    v_ = ((v_ % prime()) + prime()) % prime();
}

// ── arithmetic ────────────────────────────────────────────────────────────────

FieldElement FieldElement::operator+(const FieldElement& rhs) const {
    mpz_class r = v_ + rhs.v_;
    if (r >= prime()) r -= prime();
    return make_raw(std::move(r));
}

FieldElement FieldElement::operator-(const FieldElement& rhs) const {
    mpz_class r = v_ - rhs.v_;
    if (r < 0) r += prime();
    return make_raw(std::move(r));
}

FieldElement FieldElement::operator*(const FieldElement& rhs) const {
    mpz_class r;
    mpz_mul(r.get_mpz_t(), v_.get_mpz_t(), rhs.v_.get_mpz_t());
    mpz_mod(r.get_mpz_t(), r.get_mpz_t(), prime().get_mpz_t());
    return make_raw(std::move(r));
}

FieldElement FieldElement::operator-() const {
    if (v_ == 0) return *this;
    return make_raw(prime() - v_);
}

// ── field operations ──────────────────────────────────────────────────────────

FieldElement FieldElement::inv() const {
    if (v_ == 0)
        throw std::domain_error("FieldElement::inv: cannot invert zero");
    mpz_class r;
    if (!mpz_invert(r.get_mpz_t(), v_.get_mpz_t(), prime().get_mpz_t()))
        throw std::domain_error("FieldElement::inv: no inverse exists");
    return make_raw(std::move(r));
}

FieldElement FieldElement::sqrt() const {
    // p ≡ 3 (mod 4)  →  sqrt(v) = v^((p+1)/4) mod p
    static const mpz_class exp = (prime() + 1) / 4;
    mpz_class r;
    mpz_powm(r.get_mpz_t(), v_.get_mpz_t(), exp.get_mpz_t(), prime().get_mpz_t());
    FieldElement candidate = make_raw(std::move(r));
    if (candidate * candidate != *this)
        throw std::domain_error("FieldElement::sqrt: not a quadratic residue");
    return candidate;
}

bool FieldElement::is_square() const {
    if (v_ == 0) return true;
    // Euler's criterion: v^((p-1)/2) ≡ 1 (mod p)
    static const mpz_class exp = (prime() - 1) / 2;
    mpz_class r;
    mpz_powm(r.get_mpz_t(), v_.get_mpz_t(), exp.get_mpz_t(), prime().get_mpz_t());
    return r == 1;
}

// ── encoding ──────────────────────────────────────────────────────────────────

std::string FieldElement::to_hex() const {
    // Zero-pad to 64 hex characters (32 bytes).
    std::string s = v_.get_str(16);
    if (s.size() < 64) s.insert(0, 64 - s.size(), '0');
    return s;
}

void FieldElement::to_bytes(unsigned char out[32]) const {
    // Export as big-endian, zero-padded to exactly 32 bytes.
    size_t count = 0;
    mpz_export(out, &count, 1 /*big-endian*/, 1 /*byte*/, 0, 0, v_.get_mpz_t());
    if (count < 32) {
        // Shift right and zero-fill the leading bytes.
        std::memmove(out + (32 - count), out, count);
        std::memset(out, 0, 32 - count);
    }
}

FieldElement FieldElement::from_bytes(const unsigned char in[32]) {
    mpz_class r;
    mpz_import(r.get_mpz_t(), 32, 1 /*big-endian*/, 1 /*byte*/, 0, 0, in);
    return FieldElement(r);
}
