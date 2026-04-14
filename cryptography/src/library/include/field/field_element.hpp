#pragma once

/**
 * @brief An element of GF(p) — the prime field underlying P-256.
 *
 * Wraps a GMP `mpz_class` and keeps the value reduced into [0, p-1] at all
 * times. All arithmetic operators return new reduced elements; no raw GMP
 * value ever escapes unreduced.
 */
class FieldElement {
public:
    /**
     * @brief Returns the P-256 prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
     *
     * Returned by const reference to a function-local static to avoid the
     * static-initialisation-order-fiasco across translation units.
     */
    static const mpz_class& prime();

    /** @brief Constructs the zero element. */
    FieldElement();

    /** @brief Constructs from a signed long (may be negative; reduced mod p). */
    explicit FieldElement(long val);

    /** @brief Constructs from an arbitrary-precision integer (reduced mod p). */
    explicit FieldElement(const mpz_class& val);

    /**
     * @brief Constructs from a big-endian hex string (no "0x" prefix).
     * @param hex Even-length hex string, e.g. "FFFFFFFF00000001...".
     */
    explicit FieldElement(std::string_view hex);

    /** @brief Returns the underlying GMP value (always in [0, p-1]). */
    const mpz_class& raw() const { return v_; }

    FieldElement operator+(const FieldElement& rhs) const;
    FieldElement operator-(const FieldElement& rhs) const;
    FieldElement operator*(const FieldElement& rhs) const;
    FieldElement operator-() const;

    /** @brief Division: multiplies by the modular inverse of rhs. */
    FieldElement operator/(const FieldElement& rhs) const { return *this * rhs.inv(); }

    FieldElement& operator+=(const FieldElement& rhs) { return *this = *this + rhs; }
    FieldElement& operator-=(const FieldElement& rhs) { return *this = *this - rhs; }
    FieldElement& operator*=(const FieldElement& rhs) { return *this = *this * rhs; }

    bool operator==(const FieldElement& rhs) const { return v_ == rhs.v_; }
    bool operator!=(const FieldElement& rhs) const { return v_ != rhs.v_; }

    bool is_zero() const { return v_ == 0; }

    /**
     * @brief Modular inverse via GMP's extended Euclidean algorithm.
     * @throws std::domain_error if this element is zero.
     */
    FieldElement inv() const;

    /**
     * @brief Modular square root: computes v^((p+1)/4) mod p.
     *
     * Valid because the P-256 prime satisfies p ≡ 3 (mod 4).
     * @throws std::domain_error if this element is not a quadratic residue.
     */
    FieldElement sqrt() const;

    /**
     * @brief Returns true iff this element is a quadratic residue mod p
     *        (i.e. a perfect square in GF(p)).
     *
     * Uses Euler's criterion: v^((p-1)/2) ≡ 1 (mod p).
     */
    bool is_square() const;

    /**
     * @brief Encodes the element as a 64-character zero-padded hex string.
     * @return Uppercase hex string of exactly 64 characters.
     */
    std::string to_hex() const;

    /**
     * @brief Serialises the element as 32 big-endian bytes into @p out.
     * @param out Output buffer of at least 32 bytes.
     */
    void to_bytes(unsigned char out[32]) const;

    /**
     * @brief Deserialises from 32 big-endian bytes.
     * @param in Input buffer of at least 32 bytes.
     */
    static FieldElement from_bytes(const unsigned char in[32]);

private:
    mpz_class v_;

    // Skips reduction — caller must guarantee v is already in [0, p).
    struct RawTag {};
    FieldElement(mpz_class v, RawTag) : v_(std::move(v)) {}
    static FieldElement make_raw(mpz_class v) { return FieldElement(std::move(v), RawTag{}); }
};
