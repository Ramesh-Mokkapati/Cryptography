// SHA.cpp
// SHA-256 through OpenSSL's EVP digest API (Init -> Update -> Final).

#include "crypto/SHA.hpp"
#include "Internal.hpp"

#include <openssl/evp.h>
#include <stdexcept>

namespace Crypto
{
    std::vector<uint8_t> SHA256::hash(const std::vector<uint8_t>& data)
    {
        detail::MdCtxPtr ctx(EVP_MD_CTX_new());
        if (!ctx)
        {
            detail::throwOpenSSL("Failed to create EVP_MD_CTX");
        }

        // EVP_MD_size gives the digest length (32 bytes for SHA-256).
        std::vector<uint8_t> digest(static_cast<std::size_t>(EVP_MD_size(EVP_sha256())));
        unsigned int hash_len = 0;

        // For large or streamed input, Update could be called repeatedly with chunks;
        // here the whole buffer is hashed in one call.
        if (1 != EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) ||
            1 != EVP_DigestUpdate(ctx.get(), data.data(), data.size()) ||
            1 != EVP_DigestFinal_ex(ctx.get(), digest.data(), &hash_len))
        {
            detail::throwOpenSSL("SHA256 calculation failed");
        }

        digest.resize(hash_len);
        return digest;
    }

    std::string SHA256::hashToHex(const std::vector<uint8_t>& data)
    {
        // Table lookup instead of iostream formatting: simpler and locale-independent.
        static const char hex[] = "0123456789abcdef";
        const std::vector<uint8_t> digest = hash(data);
        std::string out;
        out.reserve(digest.size() * 2);
        for (std::size_t i = 0; i < digest.size(); ++i)
        {
            out += hex[digest[i] >> 4];     // high nibble
            out += hex[digest[i] & 0x0F];   // low nibble
        }

        return out;
    }

} // namespace Crypto
