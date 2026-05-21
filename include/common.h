#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <openssl/evp.h>

// ─────────────────────────────────────────────
//  Password search domain
// ─────────────────────────────────────────────
const std::string CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789";
const int CHARSET_SIZE    = static_cast<int>(CHARSET.size());

// ─────────────────────────────────────────────
//  Input validation
// ─────────────────────────────────────────────

/**
 * Returns true if 'hash' is a valid lower-case SHA-256 hex string (64 chars).
 */
inline bool isValidSHA256(const std::string& hash) {
    if (hash.size() != 64) return false;
    for (char c : hash) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

/**
 * Convert any hex string to lower-case in-place so comparisons always work
 * regardless of whether the user passed upper or lower-case hex.
 */
inline std::string normaliseHash(std::string hash) {
    for (char& c : hash) c = static_cast<char>(std::tolower(c));
    return hash;
}

// ─────────────────────────────────────────────
//  SHA-256 via OpenSSL EVP API (OpenSSL 3.0+)
// ─────────────────────────────────────────────

/**
 * Returns the lower-case hex SHA-256 digest of 'str'.
 * Throws std::runtime_error if OpenSSL context allocation fails.
 */
inline std::string sha256(const std::string& str) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int  hashLen = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        throw std::runtime_error("EVP_MD_CTX_new() failed: out of memory");

    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, str.c_str(), str.size());
    EVP_DigestFinal_ex(ctx, hash, &hashLen);
    EVP_MD_CTX_free(ctx);

    std::ostringstream ss;
    for (unsigned int i = 0; i < hashLen; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    return ss.str();
}

#endif // COMMON_H
