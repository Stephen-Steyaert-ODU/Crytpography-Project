#include "common/common.hpp"
#include "crypto/ecdsa.hpp"
#include "ec/curve.hpp"

namespace ECDSA {

// ── SHA-256 ───────────────────────────────────────────────────────────────────

std::vector<uint8_t> sha256(std::span<const uint8_t> data) {
    std::vector<uint8_t> digest(32);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("ECDSA::sha256: failed to create EVP_MD_CTX");

    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) ||
        !EVP_DigestUpdate(ctx, data.data(), data.size()) ||
        !EVP_DigestFinal_ex(ctx, digest.data(), nullptr))
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("ECDSA::sha256: digest computation failed");
    }
    EVP_MD_CTX_free(ctx);
    return digest;
}

// ── helpers ───────────────────────────────────────────────────────────────────

/**
 * Reads exactly @p n bytes from /dev/urandom into @p buf.
 * @throws std::runtime_error on failure.
 */
static void read_urandom(uint8_t* buf, size_t n) {
    std::ifstream f("/dev/urandom", std::ios::binary);
    if (!f) throw std::runtime_error("ECDSA: cannot open /dev/urandom");
    f.read(reinterpret_cast<char*>(buf), static_cast<std::streamsize>(n));
    if (!f) throw std::runtime_error("ECDSA: failed to read from /dev/urandom");
}

/** Generates a random scalar in [1, n-1]. */
static mpz_class random_scalar() {
    uint8_t buf[32];
    mpz_class k;
    do {
        read_urandom(buf, sizeof(buf));
        mpz_import(k.get_mpz_t(), 32, 1 /*big-endian*/, 1 /*byte*/, 0, 0, buf);
        k %= P256::n;
    } while (k == 0);
    return k;
}

/** Encodes a 256-bit scalar as 32 big-endian bytes. */
static void scalar_to_bytes(const mpz_class& v, uint8_t out[32]) {
    size_t count = 0;
    uint8_t tmp[32] = {};
    mpz_export(tmp, &count, 1 /*big-endian*/, 1 /*byte*/, 0, 0, v.get_mpz_t());
    std::memset(out, 0, 32);
    std::memcpy(out + (32 - count), tmp, count);
}

// ── sign ──────────────────────────────────────────────────────────────────────

Signature sign(const mpz_class& priv, std::span<const uint8_t> msg_hash) {
    // Interpret the 32-byte hash as a big-endian integer.
    mpz_class e;
    mpz_import(e.get_mpz_t(), msg_hash.size(), 1 /*big-endian*/, 1 /*byte*/, 0, 0, msg_hash.data());
    e %= P256::n;

    mpz_class r, s;
    do {
        mpz_class k = random_scalar();
        AffinePoint R = (JacobianPoint(P256::G) * k).to_affine();

        r = R.x.raw() % P256::n;
        if (r == 0) continue;

        // s = k⁻¹ · (e + r·priv) mod n
        mpz_class k_inv;
        mpz_invert(k_inv.get_mpz_t(), k.get_mpz_t(), P256::n.get_mpz_t());
        s = (k_inv * (e + r * priv)) % P256::n;
    } while (s == 0);

    return Signature{r, s};
}

// ── verify ────────────────────────────────────────────────────────────────────

bool verify(const AffinePoint& pub, std::span<const uint8_t> msg_hash, const Signature& sig) {
    const mpz_class& n = P256::n;

    // Reject out-of-range r or s.
    if (sig.r <= 0 || sig.r >= n) return false;
    if (sig.s <= 0 || sig.s >= n) return false;

    mpz_class e;
    mpz_import(e.get_mpz_t(), msg_hash.size(), 1 /*big-endian*/, 1 /*byte*/, 0, 0, msg_hash.data());
    e %= n;

    // w = s⁻¹ mod n
    mpz_class w;
    mpz_invert(w.get_mpz_t(), sig.s.get_mpz_t(), n.get_mpz_t());

    mpz_class u1 = (e       * w) % n;
    mpz_class u2 = (sig.r   * w) % n;

    // R = u1·G + u2·pub
    JacobianPoint R = JacobianPoint(P256::G) * u1 + JacobianPoint(pub) * u2;
    if (R.is_inf()) return false;

    AffinePoint Raff = R.to_affine();
    mpz_class rx = Raff.x.raw() % n;
    return rx == sig.r;
}

// ── serialisation ─────────────────────────────────────────────────────────────

void save_signature(const std::string& path, const Signature& sig) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("ECDSA: cannot write signature to " + path);

    uint8_t r[32], s[32];
    scalar_to_bytes(sig.r, r);
    scalar_to_bytes(sig.s, s);
    f.write(reinterpret_cast<const char*>(r), 32);
    f.write(reinterpret_cast<const char*>(s), 32);
}

Signature load_signature(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("ECDSA: cannot read signature from " + path);

    uint8_t buf[64];
    f.read(reinterpret_cast<char*>(buf), 64);
    if (f.gcount() != 64)
        throw std::runtime_error("ECDSA: signature file must be exactly 64 bytes: " + path);

    Signature sig;
    mpz_import(sig.r.get_mpz_t(), 32, 1 /*big-endian*/, 1 /*byte*/, 0, 0, buf);
    mpz_import(sig.s.get_mpz_t(), 32, 1 /*big-endian*/, 1 /*byte*/, 0, 0, buf + 32);
    return sig;
}

} // namespace ECDSA
