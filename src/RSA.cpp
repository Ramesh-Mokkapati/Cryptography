// RSA.cpp
// RSA key generation, OAEP encryption and PSS signatures through OpenSSL's EVP_PKEY API.
//
// The EVP_PKEY API is algorithm-neutral: the algorithm comes from the key, and RSA-specific
// choices (padding, hashes) are set on the operation's EVP_PKEY_CTX after the *_init call.
// Several calls are made twice: first with a null output buffer to learn the output size,
// then again to write the result.

#include "crypto/RSA.hpp"
#include "crypto/Random.hpp"
#include "Internal.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdexcept>

namespace Crypto
{
    using namespace detail;

    namespace
    {
        // PEM parsing accepts any key type; refuse non-RSA keys with a clear message instead
        // of letting OpenSSL fail later with a confusing padding error.
        void requireRsa(EVP_PKEY* key)
        {
            if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
            {
                throw std::invalid_argument("Key is not an RSA key");
            }
        }

        // OAEP with SHA-256 instead of OpenSSL's SHA-1 default.
        // Both sides must agree on these settings, so encryptPublicKey and decryptPrivateKey
        // share this one function.
        void setOaep(EVP_PKEY_CTX* ctx)
        {
            if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
                EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 ||   // hash of the (empty) OAEP label
                EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0)     // hash used by the mask generation function
            {
                throwOpenSSL("Failed to configure RSA-OAEP");
            }
        }

        // The header promises PSS; EVP_DigestSign* would otherwise default to PKCS#1 v1.5.
        // Salt length = digest length (32 bytes) is the most widely interoperable PSS setting.
        // Returns false (instead of throwing) so callers can fold it into their init check.
        bool setPss(EVP_PKEY_CTX* ctx)
        {
            return EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) > 0 &&
                EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) > 0 &&
                EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST) > 0;
        }

    } // namespace

    RSAKeyPair RSA::generateKeyPair(int bits)
    {
        // Below 2048 bits RSA is considered breakable (NIST SP 800-131A).
        if (bits < 2048)
        {
            throw std::invalid_argument("RSA keys must be at least 2048 bits");
        }

        PkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
        if (!ctx)
        {
            throwOpenSSL("Failed to create RSA context");
        }

        // The public exponent is left at OpenSSL's default of 65537.
        if (EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0)
        {
            throwOpenSSL("RSA key generation setup failed");
        }

        // Finding two large primes is the slow part (tens to hundreds of ms for 2048 bits).
        EVP_PKEY* raw = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0)
        {
            throwOpenSSL("RSA Keygen execution failed");
        }

        PkeyPtr pkey(raw);   // take ownership before anything else can throw

        RSAKeyPair keys;
        keys.publicKeyPEM = writePublicKey(pkey.get());
        keys.privateKeyPEM = writePrivateKey(pkey.get());
        return keys;
    }

    std::vector<uint8_t> RSA::encryptPublicKey(const std::vector<uint8_t>& plaintext,
        const std::string& publicKeyPEM)
    {
        PkeyPtr pkey = readPublicKey(publicKeyPEM);
        requireRsa(pkey.get());

        PkeyCtxPtr ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
        if (!ctx || EVP_PKEY_encrypt_init(ctx.get()) <= 0)
        {
            throwOpenSSL("Failed to setup RSA encryption context");
        }

        // Padding must be configured after encrypt_init (init resets the context).
        setOaep(ctx.get());

        // Pass 1: ask for the output size (always the modulus size, e.g. 256 bytes).
        std::size_t outLen = 0;
        if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outLen, plaintext.data(), plaintext.size()) <= 0)
        {
            throwOpenSSL("RSA Encryption size query failed");
        }

        // Pass 2: encrypt. This is where an over-long plaintext is rejected.
        std::vector<uint8_t> ciphertext(outLen);
        if (EVP_PKEY_encrypt(ctx.get(), ciphertext.data(), &outLen, plaintext.data(), plaintext.size()) <= 0)
        {
            throwOpenSSL("RSA Encryption process failed (plaintext too long for this key?)");
        }

        ciphertext.resize(outLen);
        return ciphertext;
    }

    std::vector<uint8_t> RSA::decryptPrivateKey(const std::vector<uint8_t>& ciphertext,
        const std::string& privateKeyPEM)
    {
        PkeyPtr pkey = readPrivateKey(privateKeyPEM);
        requireRsa(pkey.get());

        PkeyCtxPtr ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
        if (!ctx || EVP_PKEY_decrypt_init(ctx.get()) <= 0)
        {
            throwOpenSSL("Failed to setup RSA decryption context");
        }

        setOaep(ctx.get());   // must match the settings used to encrypt

        // Pass 1: maximum possible plaintext size (the real size is known only after pass 2).
        std::size_t outLen = 0;
        if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outLen, ciphertext.data(), ciphertext.size()) <= 0)
        {
            throwOpenSSL("RSA Decryption size query failed");
        }

        // Pass 2: decrypt and check the OAEP structure; a wrong key or modified ciphertext fails here.
        std::vector<uint8_t> plaintext(outLen);
        if (EVP_PKEY_decrypt(ctx.get(), plaintext.data(), &outLen, ciphertext.data(), ciphertext.size()) <= 0)
        {
            Random::secureCleanse(plaintext.data(), plaintext.size());
            throwOpenSSL("RSA Decryption process failed");
        }

        plaintext.resize(outLen);
        return plaintext;
    }

    std::vector<uint8_t> RSA::sign(const std::vector<uint8_t>& data, const std::string& privateKeyPEM)
    {
        PkeyPtr pkey = readPrivateKey(privateKeyPEM);
        requireRsa(pkey.get());

        // EVP_DigestSign* hashes the data with SHA-256 and signs the digest in one operation.
        // DigestSignInit hands back the key context (pctx) so the padding can be set to PSS.
        MdCtxPtr mdCtx(EVP_MD_CTX_new());
        EVP_PKEY_CTX* pctx = nullptr;   // owned by mdCtx
        if (!mdCtx || EVP_DigestSignInit(mdCtx.get(), &pctx, EVP_sha256(), nullptr, pkey.get()) <= 0 || !setPss(pctx))
        {
            throwOpenSSL("Failed to initialize RSA signature");
        }

        if (EVP_DigestSignUpdate(mdCtx.get(), data.data(), data.size()) <= 0)
        {
            throwOpenSSL("RSA DigestSignUpdate failed");
        }

        // Pass 1: signature size (the modulus size).
        std::size_t sigLen = 0;
        if (EVP_DigestSignFinal(mdCtx.get(), nullptr, &sigLen) <= 0)
        {
            throwOpenSSL("RSA signature size query failed");
        }

        // Pass 2: produce the signature.
        std::vector<uint8_t> signature(sigLen);
        if (EVP_DigestSignFinal(mdCtx.get(), signature.data(), &sigLen) <= 0)
        {
            throwOpenSSL("RSA DigestSignFinal failed");
        }

        signature.resize(sigLen);
        return signature;
    }

    bool RSA::verify(const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& signature,
        const std::string& publicKeyPEM)
    {
        PkeyPtr pkey = readPublicKey(publicKeyPEM);
        requireRsa(pkey.get());

        // Same PSS parameters as sign(); a signature made with different ones will not verify.
        MdCtxPtr mdCtx(EVP_MD_CTX_new());
        EVP_PKEY_CTX* pctx = nullptr;   // owned by mdCtx
        if (!mdCtx || EVP_DigestVerifyInit(mdCtx.get(), &pctx, EVP_sha256(), nullptr, pkey.get()) <= 0 || !setPss(pctx))
        {
            throwOpenSSL("Failed to initialize RSA verification");
        }

        if (EVP_DigestVerifyUpdate(mdCtx.get(), data.data(), data.size()) <= 0)
        {
            throwOpenSSL("RSA DigestVerifyUpdate failed");
        }

        // 1 = valid, 0 = invalid signature, < 0 = malformed input. Only 1 counts as valid.
        const int res = EVP_DigestVerifyFinal(mdCtx.get(), signature.data(), signature.size());

        // A bad signature leaves reasons on the error queue; it is an answer, not an error.
        clearErrors();
        return res == 1;
    }

} // namespace Crypto
