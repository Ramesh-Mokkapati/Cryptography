/// @file AES.hpp
/// @brief AES-256 symmetric encryption in CBC and GCM modes.
///
/// Which mode to use:
///  - **GCM** (recommended): encrypts *and* authenticates. Any change to the ciphertext,
///    tag, IV or associated data is detected on decryption.
///  - **CBC**: encrypts only. An attacker can modify the ciphertext undetected (and padding
///    errors can leak information), so CBC must be combined with a MAC — e.g. HMAC-SHA256
///    over IV + ciphertext, checked *before* decrypting ("encrypt-then-MAC").
///
/// Keys and IVs should come from Random::generateBytes (or KDF::pbkdf2 for keys).

#ifndef CRYPTO_AES_HPP
#define CRYPTO_AES_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <cstddef>

namespace Crypto
{
    /// Output of AES256::encryptGCM. Both parts (plus the IV) are needed to decrypt.
    struct GCMResult
    {
        std::vector<uint8_t> ciphertext;  ///< Same length as the plaintext (GCM adds no padding).
        std::vector<uint8_t> tag;         ///< 16-byte authentication tag; send/store it with the ciphertext.
    };

    /// AES with a 256-bit key (all members are static).
    class AES256
    {
    public:
        static constexpr std::size_t KEY_SIZE = 32;     ///< 256-bit key, in bytes.
        static constexpr std::size_t CBC_IV_SIZE = 16;  ///< 128-bit CBC IV (one AES block), in bytes.
        static constexpr std::size_t GCM_IV_SIZE = 12;  ///< 96-bit GCM IV, the size GCM is designed for.
        static constexpr std::size_t GCM_TAG_SIZE = 16; ///< 128-bit GCM tag, the full (strongest) length.

        /// Encrypts with AES-256-CBC and PKCS#7 padding.
        ///
        /// CBC gives confidentiality only: authenticate the ciphertext separately
        /// (e.g. HMAC over IV + ciphertext) or prefer GCM.
        /// @param plaintext Any length, including empty.
        /// @param key       KEY_SIZE (32) bytes.
        /// @param iv        CBC_IV_SIZE (16) bytes. Must be unpredictable (use Random::generateBytes)
        ///                  and never reused with the same key. It is not secret: store it with the ciphertext.
        /// @return Ciphertext, always a multiple of 16 bytes and 1-16 bytes longer than the plaintext.
        /// @throws std::invalid_argument for a wrong key or IV size.
        /// @throws std::runtime_error if OpenSSL fails.
        static std::vector<uint8_t> encryptCBC(const std::vector<uint8_t>& plaintext,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& iv);

        /// Decrypts AES-256-CBC and removes the PKCS#7 padding.
        /// @param ciphertext A non-empty multiple of 16 bytes, as produced by encryptCBC.
        /// @param key        The key used to encrypt.
        /// @param iv         The IV used to encrypt.
        /// @return The original plaintext.
        /// @throws std::invalid_argument for wrong key/IV sizes or a ciphertext that is not whole blocks.
        /// @throws std::runtime_error if the padding is invalid. A wrong key *usually* ends up here,
        ///         but not always (CBC is unauthenticated), so never treat "no exception" as
        ///         proof that the key or data is genuine.
        static std::vector<uint8_t> decryptCBC(const std::vector<uint8_t>& ciphertext,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& iv);

        /// Encrypts and authenticates with AES-256-GCM.
        ///
        /// A (key, IV) pair must NEVER be used twice: reuse breaks both confidentiality and
        /// authenticity. Use a fresh random 12-byte IV per message and rotate the key well
        /// before 2^32 messages.
        /// @param plaintext Any length, including empty.
        /// @param key       KEY_SIZE (32) bytes.
        /// @param iv        GCM_IV_SIZE (12) bytes, unique per message under this key. Not secret.
        /// @param aad       Optional "additional authenticated data": authenticated but not encrypted
        ///                  (e.g. a header or record ID). The same bytes must be passed to decryptGCM.
        /// @return Ciphertext and 16-byte tag.
        /// @throws std::invalid_argument for a wrong key or IV size.
        /// @throws std::runtime_error if OpenSSL fails.
        static GCMResult encryptGCM(const std::vector<uint8_t>& plaintext,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& iv,
            const std::vector<uint8_t>& aad = {});

        /// Verifies and decrypts AES-256-GCM.
        ///
        /// Throws std::runtime_error if the tag does not verify (wrong key, IV, AAD or modified data);
        /// no plaintext is returned in that case.
        /// @param ciphertext Ciphertext from encryptGCM.
        /// @param key        The key used to encrypt.
        /// @param iv         The IV used to encrypt.
        /// @param tag        The 16-byte tag from encryptGCM.
        /// @param aad        The same additional data passed to encryptGCM (or empty).
        /// @return The original plaintext, only after the tag has been verified.
        /// @throws std::invalid_argument for wrong key, IV or tag sizes.
        /// @throws std::runtime_error if authentication fails or OpenSSL fails.
        static std::vector<uint8_t> decryptGCM(const std::vector<uint8_t>& ciphertext,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& iv,
            const std::vector<uint8_t>& tag,
            const std::vector<uint8_t>& aad = {});
    };
}

#endif // CRYPTO_AES_HPP
