#include "common/common.hpp"
#include "crypto/ecdh.hpp"
#include "ec/curve.hpp"

namespace ECDH {

// ── helpers ───────────────────────────────────────────────────────────────────

/**
 * Reads exactly @p n bytes from /dev/urandom into @p buf.
 * @throws std::runtime_error on failure.
 */
static void read_urandom(uint8_t* buf, size_t n) {
    std::ifstream f("/dev/urandom", std::ios::binary);
    if (!f) throw std::runtime_error("ECDH: cannot open /dev/urandom");
    f.read(reinterpret_cast<char*>(buf), static_cast<std::streamsize>(n));
    if (!f) throw std::runtime_error("ECDH: failed to read from /dev/urandom");
}

// ── key generation ────────────────────────────────────────────────────────────

AffinePoint public_from_private(const mpz_class& priv) {
    return (JacobianPoint(P256::G) * priv).to_affine();
}

KeyPair generate_keypair() {
    uint8_t buf[32];
    mpz_class k;

    // Rejection sample: retry until k ∈ [1, n-1].
    do {
        read_urandom(buf, sizeof(buf));
        mpz_import(k.get_mpz_t(), 32, 1 /*big-endian*/, 1 /*byte*/, 0, 0, buf);
        k %= P256::n;
    } while (k == 0);

    return KeyPair{k, public_from_private(k)};
}

// ── shared secret ─────────────────────────────────────────────────────────────

std::vector<uint8_t> shared_secret(const mpz_class& priv, const AffinePoint& peer_pub) {
    if (!P256::on_curve(peer_pub))
        throw std::invalid_argument("ECDH::shared_secret: peer public key is not on P-256");

    AffinePoint R = (JacobianPoint(peer_pub) * priv).to_affine();

    // The shared secret is the x-coordinate of R, encoded as 32 big-endian bytes.
    std::vector<uint8_t> secret(32);
    R.x.to_bytes(secret.data());
    return secret;
}

// ── key serialisation ─────────────────────────────────────────────────────────

void save_private_key(const std::string& path, const mpz_class& priv) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("ECDH: cannot write private key to " + path);

    uint8_t buf[32] = {};
    size_t count = 0;
    mpz_export(buf, &count, 1 /*big-endian*/, 1 /*byte*/, 0, 0, priv.get_mpz_t());
    // Zero-pad to 32 bytes (mpz_export omits leading zero bytes).
    uint8_t padded[32] = {};
    std::memcpy(padded + (32 - count), buf, count);
    f.write(reinterpret_cast<const char*>(padded), 32);
}

void save_public_key(const std::string& path, const AffinePoint& pub) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("ECDH: cannot write public key to " + path);

    uint8_t x[32], y[32];
    pub.x.to_bytes(x);
    pub.y.to_bytes(y);

    f.put(0x04);                                       // uncompressed point prefix
    f.write(reinterpret_cast<const char*>(x), 32);
    f.write(reinterpret_cast<const char*>(y), 32);
}

mpz_class load_private_key(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("ECDH: cannot read private key from " + path);

    uint8_t buf[32];
    f.read(reinterpret_cast<char*>(buf), 32);
    if (f.gcount() != 32)
        throw std::runtime_error("ECDH: private key file must be exactly 32 bytes: " + path);

    mpz_class k;
    mpz_import(k.get_mpz_t(), 32, 1 /*big-endian*/, 1 /*byte*/, 0, 0, buf);
    return k;
}

AffinePoint load_public_key(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("ECDH: cannot read public key from " + path);

    uint8_t buf[65];
    f.read(reinterpret_cast<char*>(buf), 65);
    if (f.gcount() != 65)
        throw std::runtime_error("ECDH: public key file must be exactly 65 bytes: " + path);
    if (buf[0] != 0x04)
        throw std::runtime_error("ECDH: public key must use uncompressed format (0x04 prefix)");

    AffinePoint pub(
        FieldElement::from_bytes(buf + 1),
        FieldElement::from_bytes(buf + 33));

    if (!P256::on_curve(pub))
        throw std::runtime_error("ECDH: loaded public key is not on P-256");

    return pub;
}

} // namespace ECDH
