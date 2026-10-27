/// @file RSA.hpp
/// @brief RSA key generation, encryption (OAEP) and digital signatures (PSS).
///
/// Keys are passed around as PEM text so they can be stored in files or configuration:
///  - public key:  "-----BEGIN PUBLIC KEY-----"  (SubjectPublicKeyInfo / X.509)
///  - private key: "-----BEGIN PRIVATE KEY-----" (PKCS#8, **unencrypted**)
///
/// RSA can only encrypt a few hundred bytes. To protect larger data use "hybrid"
/// encryption: generate a random AES key, encrypt the data with AES256::encryptGCM,
/// and encrypt only the AES key with RSA::encryptPublicKey.

#ifndef CRYPTO_RSA_HPP
#define CRYPTO_RSA_HPP

#include <vector>
#include <string>
#include <cstdint>

namespace Crypto
{
    /// A matching RSA public/private key pair in PEM form.
    struct RSAKeyPair
    {
        std::string publicKeyPEM;    ///< SubjectPublicKeyInfo ("BEGIN PUBLIC KEY"); safe to share.
        std::string privateKeyPEM;   ///< Unencrypted PKCS#8 ("BEGIN PRIVATE KEY"): protect it like a password.
    };

    /// RSA operations (all members are static). Every padding and hash choice is fixed
    /// to modern defaults so callers cannot pick weak ones by accident.
    class RSA
    {
    public:
        /// Generates a new RSA key pair (public exponent 65537).
        /// @param bits Modulus size, at least 2048. 3072 or more is advised for keys that must
        ///             stay secure beyond 2030. Larger keys are much slower to generate.
        /// @return The key pair as PEM strings.
        /// @throws std::invalid_argument if @p bits < 2048.
        /// @throws std::runtime_error if key generation fails.
        static RSAKeyPair generateKeyPair(int bits = 2048);

        /// Encrypts with RSA-OAEP (SHA-256 for both the label hash and MGF1).
        ///
        /// The plaintext limit is keyBytes - 66 (190 bytes for RSA-2048); encrypt a random
        /// AES key with RSA and the data with AES-GCM for anything larger.
        /// OAEP is randomised: encrypting the same plaintext twice gives different ciphertexts.
        /// @param plaintext    Data to encrypt, at most keyBytes - 66 bytes.
        /// @param publicKeyPEM Recipient's public key.
        /// @return Ciphertext, exactly the key size in bytes (256 for RSA-2048).
        /// @throws std::invalid_argument if the key is not an RSA key.
        /// @throws std::runtime_error if the PEM cannot be parsed or the plaintext is too long.
        static std::vector<uint8_t> encryptPublicKey(const std::vector<uint8_t>& plaintext,
            const std::string& publicKeyPEM);

        /// Decrypts RSA-OAEP (SHA-256) ciphertext produced by encryptPublicKey.
        /// @param ciphertext    Ciphertext of exactly the key size.
        /// @param privateKeyPEM The matching private key (unencrypted PKCS#8 or traditional PEM).
        /// @return The original plaintext.
        /// @throws std::invalid_argument if the key is not an RSA key.
        /// @throws std::runtime_error if the PEM cannot be parsed, or the ciphertext is corrupt
        ///         or was made with a different key.
        static std::vector<uint8_t> decryptPrivateKey(const std::vector<uint8_t>& ciphertext,
            const std::string& privateKeyPEM);

        /// Signs data with RSA-PSS (SHA-256, MGF1-SHA-256, salt length = digest length).
        ///
        /// PSS is randomised: signing the same data twice gives different, equally valid signatures.
        /// @param data          Data to sign (hashed internally; pass the whole message).
        /// @param privateKeyPEM Signer's private key.
        /// @return Signature, exactly the key size in bytes.
        /// @throws std::invalid_argument if the key is not an RSA key.
        /// @throws std::runtime_error if the PEM cannot be parsed or signing fails.
        static std::vector<uint8_t> sign(const std::vector<uint8_t>& data,
            const std::string& privateKeyPEM);

        /// Verifies an RSA-PSS signature produced by sign().
        ///
        /// Returns false for a wrong or malformed signature; throws only for an unusable key.
        /// @param data         The data that was signed.
        /// @param signature    The signature to check.
        /// @param publicKeyPEM Signer's public key.
        /// @return true only if the signature is valid for exactly this data and key.
        /// @throws std::invalid_argument if the key is not an RSA key.
        /// @throws std::runtime_error if the PEM cannot be parsed.
        static bool verify(const std::vector<uint8_t>& data,
            const std::vector<uint8_t>& signature,
            const std::string& publicKeyPEM);
    };
}

#endif // CRYPTO_RSA_HPP
