/// @file SHA.hpp
/// @brief SHA-256 message digests.
///
/// A hash detects accidental changes and identifies content, but it is *not* a MAC:
/// anyone can recompute it. To detect deliberate tampering use HMAC (HMAC.hpp) or a
/// signature (RSA.hpp / ECDSA.hpp). Never store passwords as plain hashes; use KDF::pbkdf2.

#ifndef CRYPTO_SHA_HPP
#define CRYPTO_SHA_HPP

#include <vector>
#include <string>
#include <cstdint>

namespace Crypto
{
    /// SHA-256 (FIPS 180-4) helpers (all members are static).
    class SHA256
    {
    public:
        /// Computes SHA-256 of @p data.
        /// @param data Any length, including empty.
        /// @return The 32-byte digest.
        /// @throws std::runtime_error if OpenSSL fails.
        static std::vector<uint8_t> hash(const std::vector<uint8_t>& data);

        /// Computes SHA-256 of @p data as lower-case hex, 64 characters
        /// (e.g. "ba7816bf..." for "abc"), matching tools such as sha256sum.
        /// @throws std::runtime_error if OpenSSL fails.
        static std::string hashToHex(const std::vector<uint8_t>& data);
    };
}

#endif // CRYPTO_SHA_HPP
