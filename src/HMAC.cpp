// HMAC.cpp
// HMAC-SHA256 and constant-time MAC verification.

#include "crypto/HMAC.hpp"
#include "Internal.hpp"

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <stdexcept>

namespace Crypto
{
    std::vector<uint8_t> HMAC::calculateSHA256(const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& key)
    {
        // Allocate the largest digest OpenSSL can produce; HMAC() reports the real length (32).
        unsigned int len = EVP_MAX_MD_SIZE;
        std::vector<uint8_t> result(len);

        // An empty key is valid HMAC input, but OpenSSL needs a non-null pointer for it.
        static const unsigned char emptyKey[1] = { 0 };
        const unsigned char* keyPtr = key.empty() ? emptyKey : key.data();

        // `::HMAC` is OpenSSL's one-shot function; the leading :: distinguishes it from this
        // class (Crypto::HMAC). It is not deprecated in OpenSSL 3.x (unlike HMAC_CTX).
        if (!::HMAC(EVP_sha256(), keyPtr, detail::toInt(key.size(), "HMAC key"),
            data.data(), data.size(), result.data(), &len))
        {
            detail::throwOpenSSL("HMAC calculation failed");
        }

        result.resize(len);
        return result;
    }

    bool HMAC::verifySHA256(const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& expectedMac)
    {
        const std::vector<uint8_t> actual = calculateSHA256(data, key);

        // The length check first: a truncated MAC is rejected outright (and the lengths are
        // public anyway). CRYPTO_memcmp always compares every byte, so its running time does
        // not depend on where the first difference is.
        return expectedMac.size() == actual.size() &&
            CRYPTO_memcmp(actual.data(), expectedMac.data(), actual.size()) == 0;
    }

} // namespace Crypto
