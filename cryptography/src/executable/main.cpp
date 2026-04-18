#include "common/common.hpp"
#include "crypto/aes_gcm.hpp"
#include "crypto/ecdh.hpp"
#include "crypto/ecdsa.hpp"
#include "crypto/hkdf.hpp"

// ── I/O helpers ───────────────────────────────────────────────────────────────

/** Reads all bytes from @p path, or stdin if path is "-". */
static std::vector<uint8_t> read_file(const std::string& path) {
    std::istream* in;
    std::ifstream file;
    if (path == "-") {
        in = &std::cin;
    } else {
        file.open(path, std::ios::binary);
        if (!file) throw std::runtime_error("cannot open input file: " + path);
        in = &file;
    }
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(*in), {});
}

/** Writes @p data to @p path, or stdout if path is "-". */
static void write_file(const std::string& path, std::span<const uint8_t> data) {
    std::ostream* out;
    std::ofstream file;
    if (path == "-") {
        out = &std::cout;
    } else {
        file.open(path, std::ios::binary);
        if (!file) throw std::runtime_error("cannot open output file: " + path);
        out = &file;
    }
    out->write(reinterpret_cast<const char*>(data.data()),
               static_cast<std::streamsize>(data.size()));
}

// ── ECIES helpers ─────────────────────────────────────────────────────────────

/**
 * Derives a 32-byte AES key and 12-byte IV from a shared secret via HKDF-SHA256.
 * Uses the fixed info string "ECIES" to bind the output to this scheme.
 */
static std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 12>>
derive_key_iv(const std::vector<uint8_t>& secret) {
    const std::string info_str = "ECIES";
    std::span<const uint8_t> info{
        reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size()};

    auto material = HKDF::derive(secret, {}, info, 44);

    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> iv;
    std::copy(material.begin(),      material.begin() + 32, key.begin());
    std::copy(material.begin() + 32, material.end(),        iv.begin());
    return {key, iv};
}

// ── subcommands ───────────────────────────────────────────────────────────────

static int cmd_keygen(const std::string& priv_path, const std::string& pub_path) {
    auto kp = ECDH::generate_keypair();
    ECDH::save_private_key(priv_path, kp.priv);
    ECDH::save_public_key(pub_path,   kp.pub);
    std::cerr << "keygen: wrote " << priv_path << " and " << pub_path << "\n";
    return 0;
}

static int cmd_encrypt(const std::string& pub_path,
                       const std::string& in_path,
                       const std::string& out_path) {
    auto recipient_pub = ECDH::load_public_key(pub_path);
    auto plaintext     = read_file(in_path);

    // Ephemeral keypair — fresh for every message.
    auto eph    = ECDH::generate_keypair();
    auto secret = ECDH::shared_secret(eph.priv, recipient_pub);
    auto [key, iv] = derive_key_iv(secret);
    auto ct = AesGcm::encrypt(key, iv, plaintext);

    // Output format: ephemeral_pub (65) || tag (16) || ciphertext
    std::vector<uint8_t> out;
    out.reserve(65 + 16 + ct.data.size());

    uint8_t pub_bytes[65];
    pub_bytes[0] = 0x04;
    eph.pub.x.to_bytes(pub_bytes + 1);
    eph.pub.y.to_bytes(pub_bytes + 33);
    out.insert(out.end(), pub_bytes, pub_bytes + 65);
    out.insert(out.end(), ct.tag.begin(), ct.tag.end());
    out.insert(out.end(), ct.data.begin(), ct.data.end());

    write_file(out_path, out);
    return 0;
}

static int cmd_decrypt(const std::string& priv_path,
                       const std::string& in_path,
                       const std::string& out_path) {
    auto priv = ECDH::load_private_key(priv_path);
    auto blob = read_file(in_path);

    if (blob.size() < 65 + 16)
        throw std::runtime_error("decrypt: input too short to be a valid ciphertext");
    if (blob[0] != 0x04)
        throw std::runtime_error("decrypt: missing uncompressed point prefix (0x04)");

    // Parse: ephemeral_pub (65) || tag (16) || ciphertext
    AffinePoint eph_pub(
        FieldElement::from_bytes(blob.data() + 1),
        FieldElement::from_bytes(blob.data() + 33));

    std::array<uint8_t, 16> tag;
    std::copy(blob.begin() + 65, blob.begin() + 81, tag.begin());

    std::span<const uint8_t> ciphertext{blob.data() + 81, blob.size() - 81};

    auto secret = ECDH::shared_secret(priv, eph_pub);
    auto [key, iv] = derive_key_iv(secret);
    auto plaintext = AesGcm::decrypt(key, iv, ciphertext, tag);

    write_file(out_path, plaintext);
    return 0;
}

static int cmd_sign(const std::string& priv_path,
                    const std::string& in_path,
                    const std::string& sig_path) {
    auto priv    = ECDH::load_private_key(priv_path);
    auto message = read_file(in_path);
    auto hash    = ECDSA::sha256(message);
    auto sig     = ECDSA::sign(priv, hash);
    ECDSA::save_signature(sig_path, sig);
    return 0;
}

static int cmd_verify(const std::string& pub_path,
                      const std::string& in_path,
                      const std::string& sig_path) {
    auto pub     = ECDH::load_public_key(pub_path);
    auto message = read_file(in_path);
    auto hash    = ECDSA::sha256(message);
    auto sig     = ECDSA::load_signature(sig_path);

    if (ECDSA::verify(pub, hash, sig)) {
        std::cout << "OK\n";
        return 0;
    }
    std::cout << "FAIL\n";
    return 1;
}

// ── usage ─────────────────────────────────────────────────────────────────────

static void usage(const char* prog) {
    std::cerr <<
        "Usage: " << prog << " <command> [options]\n"
        "\n"
        "Commands:\n"
        "  keygen\n"
        "    -k, --priv <file>    private key output  (default: key.priv)\n"
        "    -K, --pub  <file>    public key output   (default: key.pub)\n"
        "\n"
        "  encrypt\n"
        "    -K, --pub  <file>    recipient public key (default: key.pub)\n"
        "    -i, --in   <file>    plaintext input      (default: stdin)\n"
        "    -o, --out  <file>    ciphertext output    (default: stdout)\n"
        "\n"
        "  decrypt\n"
        "    -k, --priv <file>    private key          (default: key.priv)\n"
        "    -i, --in   <file>    ciphertext input     (default: stdin)\n"
        "    -o, --out  <file>    plaintext output     (default: stdout)\n"
        "\n"
        "  sign\n"
        "    -k, --priv <file>    private key          (default: key.priv)\n"
        "    -i, --in   <file>    message input        (default: stdin)\n"
        "    -o, --out  <file>    signature output     (default: msg.sig)\n"
        "\n"
        "  verify\n"
        "    -K, --pub  <file>    public key           (default: key.pub)\n"
        "    -i, --in   <file>    message input        (default: stdin)\n"
        "    -s, --sig  <file>    signature file       (default: msg.sig)\n";
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) { usage(argv[0]); return 1; }

    const std::string cmd = argv[1];
    // Shift argv so getopt sees only the subcommand's arguments.
    argc--; argv++;

    std::string priv_path = "key.priv";
    std::string pub_path  = "key.pub";
    std::string in_path   = "-";
    std::string out_path  = "-";
    std::string sig_path  = "msg.sig";

    // Short options: -k (priv), -K (pub), -i (in), -o (out), -s (sig)
    // Long options map to the same single-char vals.
    static const option long_opts[] = {
        {"priv", required_argument, nullptr, 'k'},
        {"pub",  required_argument, nullptr, 'K'},
        {"in",   required_argument, nullptr, 'i'},
        {"out",  required_argument, nullptr, 'o'},
        {"sig",  required_argument, nullptr, 's'},
        {nullptr, 0, nullptr, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "k:K:i:o:s:", long_opts, nullptr)) != -1) {
        switch (opt) {
            case 'k': priv_path = optarg; break;
            case 'K': pub_path  = optarg; break;
            case 'i': in_path   = optarg; break;
            case 'o': out_path  = optarg; break;
            case 's': sig_path  = optarg; break;
            default:  usage(argv[0]); return 1;
        }
    }

    try {
        if      (cmd == "keygen")  return cmd_keygen(priv_path, pub_path);
        else if (cmd == "encrypt") return cmd_encrypt(pub_path,  in_path, out_path);
        else if (cmd == "decrypt") return cmd_decrypt(priv_path, in_path, out_path);
        else if (cmd == "sign")    return cmd_sign(priv_path, in_path,
                                       out_path == "-" ? sig_path : out_path);
        else if (cmd == "verify")  return cmd_verify(pub_path, in_path, sig_path);
        else {
            std::cerr << "unknown command: " << cmd << "\n";
            usage(argv[0]);
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
