// KDF.cpp
// PBKDF2-HMAC-SHA256 password-based key derivation (RFC 8018).

#include "crypto/KDF.hpp"
#include "Internal.hpp"

#include <openssl/evp.h>
#include <stdexcept>

namespace Crypto
{
    std::vector<uint8_t> KDF::pbkdf2(const std::string& password,
        const std::vector<uint8_t>& salt,
        int iterations,
        std::size_t keyLength)
    {
        // Reject inputs that OpenSSL would either refuse with an unhelpful error or accept
        // with a meaningless result.
        if (iterations < 1)
        {
            throw std::invalid_argument("PBKDF2: iterations must be at least 1");
        }

        if (keyLength == 0)
        {
            throw std::invalid_argument("PBKDF2: key length must be at least 1");
        }

        std::vector<uint8_t> derivedKey(keyLength);

        // PBKDF2 runs HMAC-SHA256(password, salt || counter) `iterations` times per 32-byte
        // output block and XORs the results. The salt makes identical passwords produce
        // different keys; the iteration count sets how expensive each guess is.
        int res = PKCS5_PBKDF2_HMAC(
            password.c_str(),
            detail::toInt(password.length(), "PBKDF2 password"),
            salt.data(),
            detail::toInt(salt.size(), "PBKDF2 salt"),
            iterations,
            EVP_sha256(),
            detail::toInt(keyLength, "PBKDF2 key length"),
            derivedKey.data()
        );

        if (res != 1)
        {
            detail::throwOpenSSL("PBKDF2 key derivation failed");
        }

        return derivedKey;
    }

} // namespace Crypto
