/// @file HMAC.hpp
/// @brief HMAC-SHA256 message authentication codes.
///
/// An HMAC proves that a message came from someone holding the shared secret key and was
/// not modified. Sender and receiver share the key; the receiver recomputes the MAC and
/// compares it with verifySHA256 (constant time).

#ifndef CRYPTO_HMAC_HPP
#define CRYPTO_HMAC_HPP

#include <vector>
#include <cstdint>

namespace Crypto
{
    /// HMAC helpers (all members are static).
    class HMAC
    {
    public:
        /// Computes HMAC-SHA256(key, data) as defined in RFC 2104.
        /// @param data The message to authenticate; any length.
        /// @param key  Secret key; any length (32 random bytes is recommended). Keys longer
        ///             than 64 bytes are hashed first, as the standard requires.
        /// @return The 32-byte MAC.
        /// @throws std::runtime_error if OpenSSL fails.
        static std::vector<uint8_t> calculateSHA256(const std::vector<uint8_t>& data,
            const std::vector<uint8_t>& key);

        /// Checks a received MAC in constant time.
        ///
        /// Use this instead of operator== so the comparison time does not reveal how many
        /// leading bytes matched (which would let an attacker forge a MAC byte by byte).
        /// @param data        The received message.
        /// @param key         The shared secret key.
        /// @param expectedMac The MAC that arrived with the message.
        /// @return true only if @p expectedMac is the full, correct 32-byte MAC.
        /// @throws std::runtime_error if OpenSSL fails.
        static bool verifySHA256(const std::vector<uint8_t>& data,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& expectedMac);
    };
}

#endif // CRYPTO_HMAC_HPP
