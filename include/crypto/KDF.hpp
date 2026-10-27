/// @file KDF.hpp
/// @brief Password-based key derivation (PBKDF2-HMAC-SHA256).
///
/// Turns a human password into a fixed-length key suitable for AES. The iteration count
/// makes each guess expensive, which slows down brute-force attacks on stolen hashes.
///
/// Typical use:
/// @code
///   auto salt = Crypto::Random::generateBytes(16);          // store next to the result
///   auto key  = Crypto::KDF::pbkdf2(password, salt);        // 100,000 iterations, 32 bytes
/// @endcode

#ifndef CRYPTO_KDF_HPP
#define CRYPTO_KDF_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <cstddef>

namespace Crypto
{
    /// Key derivation functions (all members are static).
    class KDF
    {
    public:
        /// Derives a key from a password using PBKDF2-HMAC-SHA256 (RFC 8018).
        ///
        /// The result is deterministic: the same password, salt, iterations and length always
        /// give the same key, so the salt and iteration count must be stored to re-derive it.
        ///
        /// @param password   The password bytes (no character-set conversion is applied).
        /// @param salt       Random, unique per password; at least 16 bytes is recommended.
        /// @param iterations Work factor, >= 1. 100,000 or more is recommended for passwords;
        ///                   raise it as hardware gets faster.
        /// @param keyLength  Output length in bytes, >= 1 (32 for an AES-256 key).
        /// @return The derived key. Wipe it with Random::secureCleanse when done.
        /// @throws std::invalid_argument if @p iterations < 1 or @p keyLength == 0.
        /// @throws std::runtime_error if OpenSSL fails.
        static std::vector<uint8_t> pbkdf2(const std::string& password,
            const std::vector<uint8_t>& salt,
            int iterations = 100000,
            std::size_t keyLength = 32);
    };
}

#endif // CRYPTO_KDF_HPP
