# ECIES + ECDSA over P-256

Implements ECIES (Elliptic Curve Integrated Encryption Scheme) and ECDSA from scratch in C++20 over the NIST P-256 curve. All elliptic curve arithmetic is hand-rolled; GMP provides big integer primitives and OpenSSL provides AES-256-GCM and HMAC-SHA256.

## Programs

| Command   | Description |
|-----------|-------------|
| `keygen`  | Generate a P-256 keypair and write to files |
| `encrypt` | ECIES encrypt: ECDH → HKDF → AES-256-GCM |
| `decrypt` | ECIES decrypt and authenticate |
| `sign`    | ECDSA sign a file with a private key |
| `verify`  | ECDSA verify a file against a public key and signature |

## Running with Docker Compose (recommended)

Build both images:
```sh
docker compose build
```

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
```

Run tests:
```sh
docker compose run test
```

## Running without Docker Compose

```sh
docker build --target runtime -t crypto .
docker build --target test    -t crypto-test .

mkdir -p data   # must exist before mounting

docker run --rm -v "$(pwd)/data":/data -w /data crypto keygen
docker run --rm -v "$(pwd)/data":/data -w /data crypto encrypt -i plaintext.txt -o msg.enc
docker run --rm -v "$(pwd)/data":/data -w /data crypto decrypt -i msg.enc -o plaintext.txt
docker run --rm -v "$(pwd)/data":/data -w /data crypto sign    -i msg.enc
docker run --rm -v "$(pwd)/data":/data -w /data crypto verify  -i msg.enc

docker run --rm crypto-test
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
| [Catch2](https://github.com/catchorg/Catch2) | Unit testing |
