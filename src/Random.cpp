// Random.cpp
// CSPRNG output and secure wiping, both delegated to OpenSSL.

#include "crypto/Random.hpp"
#include "Internal.hpp"

#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdexcept>

namespace Crypto
{
    std::vector<uint8_t> Random::generateBytes(std::size_t count)
    {
        std::vector<uint8_t> buffer(count);
        if (count == 0)
        {
            // An empty vector has no data() pointer to hand to OpenSSL.
            return buffer;
        }

        // RAND_bytes uses OpenSSL's DRBG, seeded from the OS (BCryptGenRandom on Windows,
        // getrandom()/dev/urandom on Linux). It returns 1 only when the output is
        // cryptographically strong, so any other value is treated as fatal.
        if (RAND_bytes(buffer.data(), detail::toInt(count, "CSPRNG")) != 1)
        {
            detail::throwOpenSSL("CSPRNG: Failed to generate random bytes");
        }

        return buffer;
    }

    void Random::secureCleanse(void* ptr, std::size_t size)
    {
        if (ptr && size > 0)
        {
            // OPENSSL_cleanse (assembly on x86/x64, a volatile memset pointer elsewhere) cannot
            // be removed by the compiler as a "dead store" the way a plain memset() may be.
            OPENSSL_cleanse(ptr, size);
        }
    }

} // namespace Crypto
