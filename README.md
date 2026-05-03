# Open Sourced:

[Linked here](https://github.com/Stephen-Steyaert-ODU/Crytpography-Project)

# ECIES + ECDSA over P-256

Implements ECIES (Elliptic Curve Integrated Encryption Scheme) and ECDSA from scratch in C++20 over the NIST P-256 curve. All elliptic curve arithmetic is hand-rolled on top of GMP's big integer primitives. OpenSSL is used only for AES-256-GCM and HMAC-SHA256, consistent with standard practice of not reimplementing well-audited symmetric primitives.

## Features and design

- **Hand-rolled EC arithmetic** — prime field elements (`FieldElement`), affine and Jacobian projective point representations, point addition and doubling with the `dbl-2001-b` / `add-2007-bl` formulas (optimised for P-256's a = −3 coefficient), and scalar multiplication via the Montgomery ladder for side-channel resistance
- **Full ECIES pipeline** — ephemeral ECDH key exchange → HKDF-SHA256 key derivation → AES-256-GCM authenticated encryption, with the output format `ephemeral_pub (65 B) || GCM tag (16 B) || ciphertext`
- **ECDSA** — sign and verify with hand-rolled modular arithmetic; SHA-256 via OpenSSL
- **Single binary, five subcommands** — `keygen`, `encrypt`, `decrypt`, `sign`, `verify`, `clean`; all flags optional with sensible defaults, supports both short (`-i`) and long (`--in`) forms
- **Docker-first** — runs on any platform with Docker; no native toolchain required; CI via GitHub Actions builds, tests, and publishes to GHCR

## Dependencies

An `install.sh` script is included to install dependencies automatically:

```sh
# Install Docker (recommended — default)
./install.sh

# Or install native build tools (CMake, GMP, OpenSSL, etc.)
./install.sh --native
```

The script detects macOS, Debian/Ubuntu, Alpine, and WSL automatically.

**Windows**: the script does not run natively on Windows. Use one of:
- **WSL** (recommended) — open a WSL terminal and run `./install.sh` as normal
- **winget** — `winget install Docker.DockerDesktop`
- **Chocolatey** — `choco install docker-desktop`

- **Docker install**: on macOS it prints the Homebrew/Docker Desktop instructions; on Linux it runs the official Docker install script
- **Native install**: installs CMake, Ninja, GCC, GMP, and OpenSSL via the system package manager; Catch2 is fetched automatically by CMake at configure time via `FetchContent`

## Running with Docker Compose (recommended)

The default `docker-compose.yml` pulls the pre-built image from GHCR — no local build needed.

Create the data directory (must exist before any command):
```sh
mkdir -p data
```

Run commands — all files are read from and written to `./data/`:
```sh
docker compose run crypto keygen
docker compose run crypto encrypt -i plaintext.txt -o msg.enc
docker compose run crypto decrypt -i msg.enc -o plaintext.txt
docker compose run crypto sign    -i msg.enc
docker compose run crypto verify  -i msg.enc
docker compose run crypto clean
```

## Development (build locally)

Use `docker-compose.dev.yml` to build from source instead of pulling from GHCR:

```sh
docker compose -f docker-compose.dev.yml build

docker compose -f docker-compose.dev.yml run crypto keygen
docker compose -f docker-compose.dev.yml run test
```

## Running without Docker Compose

```sh
docker pull ghcr.io/stephen-steyaert-odu/crytpography-project/cryptography-course-project:latest

mkdir -p data   # must exist before mounting

docker run --rm -v "$(pwd)/data":/data -w /data \
  ghcr.io/stephen-steyaert-odu/crytpography-project/cryptography-course-project:latest keygen
```

## CLI reference

```
Usage: cryptography <command> [options]

Commands:
  keygen
    -k, --priv <file>    private key output   (default: key.priv)
    -K, --pub  <file>    public key output    (default: key.pub)

  encrypt
    -K, --pub  <file>    recipient public key (default: key.pub)
    -i, --in   <file>    plaintext input      (default: stdin)
    -o, --out  <file>    ciphertext output    (default: stdout)

  decrypt
    -k, --priv <file>    private key          (default: key.priv)
    -i, --in   <file>    ciphertext input     (default: stdin)
    -o, --out  <file>    plaintext output     (default: stdout)

  sign
    -k, --priv <file>    private key          (default: key.priv)
    -i, --in   <file>    message input        (default: stdin)
    -o, --out  <file>    signature output     (default: msg.sig)

  verify
    -K, --pub  <file>    public key           (default: key.pub)
    -i, --in   <file>    message input        (default: stdin)
    -s, --sig  <file>    signature file       (default: msg.sig)

  clean                  remove all .enc .dec .sig .priv .pub files in the current directory
```

## Key file format

| File | Size | Format |
|------|------|--------|
| Private key | 32 bytes | Big-endian scalar |
| Public key | 65 bytes | `0x04` \|\| x (32) \|\| y (32) — uncompressed point |
| Signature | 64 bytes | r (32) \|\| s (32) |

## Libraries

| Library | Role |
|---------|------|
| [GMP](https://gmplib.org/) | Big integer arithmetic underlying all field operations |
| [OpenSSL](https://www.openssl.org/) | AES-256-GCM and HMAC-SHA256 only |
| [Catch2](https://github.com/catchorg/Catch2) | Unit testing (fetched automatically by CMake) |
