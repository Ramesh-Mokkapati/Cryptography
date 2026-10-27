// AES.cpp
// AES-256 in CBC and GCM modes through OpenSSL's EVP cipher API.
//
// Every function follows the same EVP pattern:
//   1. EVP_*Init_ex   - choose the cipher and load key + IV
//   2. EVP_*Update    - process the data (may be called repeatedly; here once)
//   3. EVP_*Final_ex  - flush the last block (CBC padding) or finish the tag (GCM)
// Each Update/Final call reports how many bytes it wrote through `len`, and the running
// total gives the real output size; the buffers are allocated generously and trimmed.

#include "crypto/AES.hpp"
#include "crypto/Random.hpp"
#include "Internal.hpp"

#include <openssl/evp.h>
#include <stdexcept>

namespace Crypto
{

    // C++11 needs namespace-scope definitions for static constexpr members that are odr-used.
    // (Without them, binding AES256::KEY_SIZE to a const reference can fail to link; C++17
    // made such members implicitly inline, so these lines are harmless there.)
    constexpr std::size_t AES256::KEY_SIZE;
    constexpr std::size_t AES256::CBC_IV_SIZE;
    constexpr std::size_t AES256::GCM_IV_SIZE;
    constexpr std::size_t AES256::GCM_TAG_SIZE;

    using detail::CipherCtxPtr;
    using detail::throwOpenSSL;
    using detail::toInt;

    namespace
    {
        // Allocates a cipher context owned by a unique_ptr (freed automatically).
        CipherCtxPtr newCipherCtx()
        {
            CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
            if (!ctx)
            {
                throwOpenSSL("Failed to create EVP_CIPHER_CTX");
            }

            return ctx;
        }
    } // namespace

    // --- AES CBC ---
    // Cipher Block Chaining: each 16-byte block is XORed with the previous ciphertext block
    // before encryption. OpenSSL applies PKCS#7 padding by default, so the output is always
    // 1-16 bytes longer than the input and a whole number of blocks.

    std::vector<uint8_t> AES256::encryptCBC(const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv)
    {
        // OpenSSL reads exactly 32 key bytes and 16 IV bytes from the pointers it is given,
        // so the sizes must be checked here to avoid reading past short buffers.
        if (key.size() != KEY_SIZE || iv.size() != CBC_IV_SIZE)
        {
            throw std::invalid_argument("Invalid Key or IV size for AES-256-CBC.");
        }

        CipherCtxPtr ctx = newCipherCtx();
        // Room for the input plus one full padding block.
        std::vector<uint8_t> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        int len = 0, ciphertext_len = 0;

        if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) ||
            1 != EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, plaintext.data(), toInt(plaintext.size(), "AES-CBC plaintext")))
        {
            throwOpenSSL("AES-CBC Encryption failed");
        }

        ciphertext_len = len;

        // Final encrypts the last partial block together with its padding.
        if (1 != EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len))
        {
            throwOpenSSL("AES-CBC Finalization failed");
        }

        ciphertext_len += len;

        ciphertext.resize(static_cast<std::size_t>(ciphertext_len));
        return ciphertext;
    }

    std::vector<uint8_t> AES256::decryptCBC(const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv)
    {
        if (key.size() != KEY_SIZE || iv.size() != CBC_IV_SIZE)
        {
            throw std::invalid_argument("Invalid Key or IV size for AES-256-CBC.");
        }

        // Padded CBC output is always at least one whole 16-byte block; anything else is
        // truncated or corrupt, so fail early with a clear message.
        if (ciphertext.empty() || ciphertext.size() % 16 != 0)
        {
            throw std::invalid_argument("AES-256-CBC ciphertext must be a non-empty multiple of 16 bytes.");
        }

        CipherCtxPtr ctx = newCipherCtx();
        std::vector<uint8_t> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
        int len = 0, plaintext_len = 0;

        // On any failure the partially decrypted buffer is wiped before throwing.
        if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) ||
            1 != EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(), toInt(ciphertext.size(), "AES-CBC ciphertext")))
        {
            Random::secureCleanse(plaintext.data(), plaintext.size());
            throwOpenSSL("AES-CBC Decryption failed");
        }

        plaintext_len = len;

        // Final decrypts the last block and checks/removes the PKCS#7 padding. A wrong key or
        // modified ciphertext usually breaks the padding and fails here (but not always).
        if (1 != EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len))
        {
            Random::secureCleanse(plaintext.data(), plaintext.size());
            throwOpenSSL("AES-CBC Finalization failed (invalid padding or key)");
        }

        plaintext_len += len;

        plaintext.resize(static_cast<std::size_t>(plaintext_len));
        return plaintext;
    }

    // --- AES GCM ---
    // Galois/Counter Mode: AES in counter mode (a stream cipher, so no padding) plus a
    // GHASH-based authentication tag over the AAD and the ciphertext.
    // Order of operations matters: AAD must be supplied before the plaintext/ciphertext.

    GCMResult AES256::encryptGCM(const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& aad)
    {
        if (key.size() != KEY_SIZE || iv.size() != GCM_IV_SIZE)
        {
            throw std::invalid_argument("Invalid Key or IV size for AES-256-GCM.");
        }

        CipherCtxPtr ctx = newCipherCtx();

        GCMResult result;
        // One spare block: GCM is a stream mode, but Final may be handed an end pointer.
        result.ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        result.tag.resize(GCM_TAG_SIZE);

        int len = 0, total = 0;

        // GCM is initialised in two steps: select the cipher, set the IV length (12 bytes is
        // the default, but setting it keeps this correct if GCM_IV_SIZE ever changes), and
        // only then load the key and IV.
        if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ||
            1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) ||
            1 != EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()))
        {
            throwOpenSSL("AES-GCM Init failed");
        }

        // A null output pointer tells OpenSSL this Update is AAD: it is authenticated only.
        if (!aad.empty())
        {
            if (1 != EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), toInt(aad.size(), "AES-GCM AAD")))
            {
                throwOpenSSL("AES-GCM AAD Update failed");
            }
        }

        // Skipped for empty input: with a null output pointer the call would be taken as AAD.
        if (!plaintext.empty())
        {
            if (1 != EVP_EncryptUpdate(ctx.get(), result.ciphertext.data(), &len, plaintext.data(), toInt(plaintext.size(), "AES-GCM plaintext")))
            {
                throwOpenSSL("AES-GCM Encryption update failed");
            }

            total = len;
        }

        // For GCM, Final writes no ciphertext (len == 0); it completes the tag computation.
        if (1 != EVP_EncryptFinal_ex(ctx.get(), result.ciphertext.data() + total, &len))
        {
            throwOpenSSL("AES-GCM Finalization failed");
        }

        total += len;

        // The tag can only be read after Final.
        if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(GCM_TAG_SIZE), result.tag.data()))
        {
            throwOpenSSL("Failed to retrieve GCM authentication tag");
        }

        result.ciphertext.resize(static_cast<std::size_t>(total));
        return result;
    }

    std::vector<uint8_t> AES256::decryptGCM(const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& tag,
        const std::vector<uint8_t>& aad)
    {
        // A short tag would weaken authentication, so only the full 16-byte tag is accepted.
        if (key.size() != KEY_SIZE || iv.size() != GCM_IV_SIZE || tag.size() != GCM_TAG_SIZE)
        {
            throw std::invalid_argument("Invalid Key, IV, or Tag size for AES-256-GCM.");
        }

        CipherCtxPtr ctx = newCipherCtx();
        std::vector<uint8_t> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
        int len = 0, total = 0;

        // Same two-step initialisation as encryptGCM.
        if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ||
            1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) ||
            1 != EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()))
        {
            throwOpenSSL("AES-GCM Decrypt Init failed");
        }

        // AAD first, exactly as on the encrypting side.
        if (!aad.empty())
        {
            if (1 != EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), toInt(aad.size(), "AES-GCM AAD")))
            {
                throwOpenSSL("AES-GCM AAD Update failed");
            }
        }

        // This produces plaintext *before* it is authenticated; it stays in this function
        // until the tag check below succeeds.
        if (!ciphertext.empty())
        {
            if (1 != EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(), toInt(ciphertext.size(), "AES-GCM ciphertext")))
            {
                Random::secureCleanse(plaintext.data(), plaintext.size());
                throwOpenSSL("AES-GCM Decryption update failed");
            }

            total = len;
        }

        // Give OpenSSL the expected tag; Final compares it with the one it computed.
        if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<uint8_t*>(tag.data())))
        {
            Random::secureCleanse(plaintext.data(), plaintext.size());
            throwOpenSSL("Failed to set expected GCM tag");
        }

        // Returns <= 0 when the tag does not match (comparison is constant time inside OpenSSL).
        if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + total, &len) <= 0)
        {
            // Unauthenticated plaintext must not escape: wipe it before reporting the failure.
            Random::secureCleanse(plaintext.data(), plaintext.size());
            detail::clearErrors();
            throw std::runtime_error("AES-GCM Tag verification failed! Data modified or wrong key.");
        }

        total += len;

        plaintext.resize(static_cast<std::size_t>(total));
        return plaintext;
    }

} // namespace Crypto
