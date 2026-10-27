/// @file ECDSA.hpp
/// @brief Elliptic-curve digital signatures (ECDSA over NIST P-256 with SHA-256).
///
/// ECDSA gives security comparable to RSA-3072 with much smaller keys and signatures,
/// and much faster key generation. It signs only; it cannot encrypt.
/// Keys use the same PEM formats as RSA.hpp ("BEGIN PUBLIC KEY" / unencrypted "BEGIN PRIVATE KEY").

#ifndef CRYPTO_ECDSA_HPP
#define CRYPTO_ECDSA_HPP

#include <vector>
#include <string>
#include <cstdint>

namespace Crypto
{
    /// A matching EC public/private key pair in PEM form.
    struct ECKeyPair
    {
        std::string publicKeyPEM;    ///< SubjectPublicKeyInfo ("BEGIN PUBLIC KEY"); safe to share.
        std::string privateKeyPEM;   ///< Unencrypted PKCS#8 ("BEGIN PRIVATE KEY"): protect it like a password.
    };

    /// ECDSA operations (all members are static).
    class ECDSA
    {
    public:
        /// Generates an EC key pair on NID_X9_62_prime256v1 (secp256r1 / NIST P-256).
        /// @return The key pair as PEM strings.
        /// @throws std::runtime_error if key generation fails.
        static ECKeyPair generateKeyPair();

        /// Signs data with ECDSA-SHA256.
        ///
        /// ECDSA signatures are randomised, so signing the same data twice gives different results.
        /// @param data          Data to sign (hashed internally; pass the whole message).
        /// @param privateKeyPEM Signer's P-256 private key.
        /// @return A DER-encoded signature (SEQUENCE of r and s), usually 70-72 bytes.
        /// @throws std::invalid_argument if the key is not an EC key.
        /// @throws std::runtime_error if the PEM cannot be parsed or signing fails.
        static std::vector<uint8_t> sign(const std::vector<uint8_t>& data,
            const std::string& privateKeyPEM);

        /// Verifies an ECDSA-SHA256 signature produced by sign().
        /// @param data         The data that was signed.
        /// @param signature    DER-encoded signature.
        /// @param publicKeyPEM Signer's public key.
        /// @return true only if valid; false for a wrong or malformed signature.
        /// @throws std::invalid_argument if the key is not an EC key.
        /// @throws std::runtime_error if the PEM cannot be parsed.
        static bool verify(const std::vector<uint8_t>& data,
            const std::vector<uint8_t>& signature,
            const std::string& publicKeyPEM);
    };
}

#endif // CRYPTO_ECDSA_HPP
