// ECDSA.cpp
// ECDSA over NIST P-256 with SHA-256, through OpenSSL's EVP_PKEY / EVP_DigestSign API.
//
// The structure mirrors RSA.cpp's sign/verify; the differences are that no padding has to
// be configured, and the signature is DER-encoded (r, s), so its length varies slightly.

#include "crypto/ECDSA.hpp"
#include "Internal.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <stdexcept>

namespace Crypto
{
    using namespace detail;

    namespace
    {
        // PEM parsing accepts any key type; make sure we were given an EC key.
        void requireEc(EVP_PKEY* key)
        {
            if (EVP_PKEY_base_id(key) != EVP_PKEY_EC)
            {
                throw std::invalid_argument("Key is not an EC key");
            }
        }
    } // namespace

    ECKeyPair ECDSA::generateKeyPair()
    {
        // The curve is chosen on the keygen context. P-256 (prime256v1 / secp256r1) is the
        // most widely supported curve (TLS, X.509, JWT "ES256", hardware tokens).
        PkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
        if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) <= 0)
        {
            throwOpenSSL("ECDSA keygen initialization failed");
        }

        EVP_PKEY* raw = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0)
        {
            throwOpenSSL("ECDSA Key generation failed");
        }

        PkeyPtr pkey(raw);   // take ownership before anything else can throw

        ECKeyPair keys;
        keys.publicKeyPEM = writePublicKey(pkey.get());
        keys.privateKeyPEM = writePrivateKey(pkey.get());
        return keys;
    }

    std::vector<uint8_t> ECDSA::sign(const std::vector<uint8_t>& data, const std::string& privateKeyPEM)
    {
        PkeyPtr pkey = readPrivateKey(privateKeyPEM);
        requireEc(pkey.get());

        // Hash with SHA-256 and sign the digest in one operation.
        MdCtxPtr mdCtx(EVP_MD_CTX_new());
        if (!mdCtx || EVP_DigestSignInit(mdCtx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) <= 0)
        {
            throwOpenSSL("ECDSA DigestSignInit failed");
        }

        if (EVP_DigestSignUpdate(mdCtx.get(), data.data(), data.size()) <= 0)
        {
            throwOpenSSL("ECDSA DigestSignUpdate failed");
        }

        // Pass 1: the *maximum* DER signature size (72 bytes for P-256).
        std::size_t sigLen = 0;
        if (EVP_DigestSignFinal(mdCtx.get(), nullptr, &sigLen) <= 0)
        {
            throwOpenSSL("ECDSA signature size query failed");
        }

        // Pass 2: sign; sigLen is updated to the actual length.
        std::vector<uint8_t> signature(sigLen);
        if (EVP_DigestSignFinal(mdCtx.get(), signature.data(), &sigLen) <= 0)
        {
            throwOpenSSL("ECDSA DigestSignFinal failed");
        }

        signature.resize(sigLen);   // DER length varies with the size of r and s
        return signature;
    }

    bool ECDSA::verify(const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& signature,
        const std::string& publicKeyPEM)
    {
        PkeyPtr pkey = readPublicKey(publicKeyPEM);
        requireEc(pkey.get());

        MdCtxPtr mdCtx(EVP_MD_CTX_new());
        if (!mdCtx || EVP_DigestVerifyInit(mdCtx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) <= 0)
        {
            throwOpenSSL("ECDSA DigestVerifyInit failed");
        }

        if (EVP_DigestVerifyUpdate(mdCtx.get(), data.data(), data.size()) <= 0)
        {
            throwOpenSSL("ECDSA DigestVerifyUpdate failed");
        }

        // 1 = valid, 0 = invalid, < 0 = malformed DER. Only 1 counts as valid.
        const int res = EVP_DigestVerifyFinal(mdCtx.get(), signature.data(), signature.size());

        clearErrors();   // a malformed signature is a "false", not an exception
        return res == 1;
    }

} // namespace Crypto
