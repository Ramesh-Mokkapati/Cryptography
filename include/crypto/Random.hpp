/// @file Random.hpp
/// @brief Cryptographically secure random numbers and secure memory wiping.
///
/// Use generateBytes() for every key, IV, nonce and salt in this library: it draws from
/// OpenSSL's CSPRNG (seeded from the operating system), unlike rand() or std::mt19937,
/// which are predictable and must never be used for cryptography.

#ifndef CRYPTO_RANDOM_HPP
#define CRYPTO_RANDOM_HPP

#include <vector>
#include <cstdint>
#include <cstddef>

namespace Crypto
{
    /// Random bytes and secret-wiping helpers (all members are static).
    class Random
    {
    public:
        /// Generates cryptographically secure random bytes via OpenSSL RAND_bytes.
        /// @param count Number of bytes to generate; 0 returns an empty vector.
        /// @return A vector of exactly @p count random bytes.
        /// @throws std::runtime_error if the CSPRNG fails (e.g. it could not be seeded).
        /// @throws std::invalid_argument if @p count exceeds INT_MAX.
        static std::vector<uint8_t> generateBytes(std::size_t count);

        /// Securely wipes a memory buffer to prevent secret leakage.
        ///
        /// Unlike memset(), OPENSSL_cleanse cannot be removed by the optimiser when the buffer
        /// is about to be freed. Call it on keys, passwords and plaintext once they are no
        /// longer needed. A null pointer or zero size is a no-op.
        /// @param ptr  Start of the buffer.
        /// @param size Number of bytes to overwrite with zeros.
        static void secureCleanse(void* ptr, std::size_t size);
    };
}

#endif // CRYPTO_RANDOM_HPP
