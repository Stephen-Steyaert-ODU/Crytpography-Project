#pragma once

// ── Standard library ──────────────────────────────────────────────────────────
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// ── GMP — big integer arithmetic ─────────────────────────────────────────────
#include <gmpxx.h>

// ── OpenSSL — hash / MAC / symmetric primitives ───────────────────────────────
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
