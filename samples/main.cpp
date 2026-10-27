// main.cpp : crypto_samples, the runbook's demonstration program.
//
// Walks through every feature of crypto_wrapper once, printing what it does, so it doubles
// as example code: each testXxx() function shows the typical call sequence for one class.
// Exits with 1 and an error message if any step fails. For exhaustive checks against
// published test vectors, see tests/crypto_tests.cpp.

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "crypto/Random.hpp"
#include "crypto/KDF.hpp"
#include "crypto/AES.hpp"
#include "crypto/RSA.hpp"
#include "crypto/ECDSA.hpp"
#include "crypto/SHA.hpp"
#include "crypto/HMAC.hpp"

// assert() disappears in Release builds (NDEBUG), so the samples use a check that always runs.
#define CHECK(cond) \
    do { if (!(cond)) throw std::runtime_error(std::string("Check failed: ") + #cond); } while (0)

void testRandomAndCleanse()
{
    std::cout << "[1] Testing CSPRNG & Secure Cleanse...\n";
    auto bytes = Crypto::Random::generateBytes(16);
    CHECK(bytes.size() == 16);

    std::cout << "    Generated 16 Random Bytes successfully.\n";
    Crypto::Random::secureCleanse(bytes.data(), bytes.size());
    for (uint8_t b : bytes)
    {
        CHECK(b == 0);
    }

    std::cout << "    [SUCCESS] Secure memory cleanse executed.\n\n";
}

void testPBKDF2()
{
    std::cout << "[2] Testing PBKDF2 Key Derivation...\n";
    std::string password = "UserSuperSecretPassword123!";
    auto salt = Crypto::Random::generateBytes(16);

    auto key = Crypto::KDF::pbkdf2(password, salt, 100000, 32);
    CHECK(key.size() == 32);
    CHECK(key == Crypto::KDF::pbkdf2(password, salt, 100000, 32));   // deterministic

    std::cout << "    Derived 256-bit key from password using 100,000 iterations.\n";
    Crypto::Random::secureCleanse(key.data(), key.size());
    std::cout << "    [SUCCESS] PBKDF2 completed.\n\n";
}

void testAES256CBC()
{
    std::cout << "[3] Testing AES-256-CBC...\n";
    std::string text = "Confidential Payload for AES-CBC";
    std::vector<uint8_t> plaintext(text.begin(), text.end());

    auto key = Crypto::Random::generateBytes(32);
    auto iv = Crypto::Random::generateBytes(16);

    auto cipher = Crypto::AES256::encryptCBC(plaintext, key, iv);
    auto decrypted = Crypto::AES256::decryptCBC(cipher, key, iv);

    CHECK(cipher != plaintext);
    CHECK(plaintext == decrypted);
    std::cout << "    [SUCCESS] AES-256-CBC matched.\n\n";
}

void testAES256GCM()
{
    std::cout << "[4] Testing AES-256-GCM (AEAD)...\n";
    std::string text = "Payload to protect with AES-GCM";
    std::vector<uint8_t> plaintext(text.begin(), text.end());

    auto key = Crypto::Random::generateBytes(32);
    auto iv = Crypto::Random::generateBytes(12);   // fresh IV for every message
    std::vector<uint8_t> aad = { 'h', 'e', 'a', 'd', 'e', 'r' };   // authenticated, not encrypted

    auto result = Crypto::AES256::encryptGCM(plaintext, key, iv, aad);
    auto decrypted = Crypto::AES256::decryptGCM(result.ciphertext, key, iv, result.tag, aad);
    CHECK(plaintext == decrypted);

    // Flip one ciphertext bit: decryption must refuse it.
    result.ciphertext[0] ^= 0x01;
    bool rejected = false;
    try
    {
        Crypto::AES256::decryptGCM(result.ciphertext, key, iv, result.tag, aad);
    }
    catch (const std::runtime_error&)
    {
        rejected = true;
    }

    CHECK(rejected);

    std::cout << "    [SUCCESS] AES-256-GCM encryption & tag verification passed (tampering rejected).\n\n";
}

// RSA: encrypt with the *public* key, decrypt with the *private* key;
// sign with the *private* key, verify with the *public* key.
void testRSA()
{
    std::cout << "[5] Testing RSA-2048 (Encryption & Digital Signatures)...\n";
    auto keyPair = Crypto::RSA::generateKeyPair(2048);

    std::string text = "Payload for RSA Operations";
    std::vector<uint8_t> data(text.begin(), text.end());

    // 1. Encryption
    auto encrypted = Crypto::RSA::encryptPublicKey(data, keyPair.publicKeyPEM);
    auto decrypted = Crypto::RSA::decryptPrivateKey(encrypted, keyPair.privateKeyPEM);
    CHECK(data == decrypted);

    // 2. Signature Verification
    auto signature = Crypto::RSA::sign(data, keyPair.privateKeyPEM);
    bool valid = Crypto::RSA::verify(data, signature, keyPair.publicKeyPEM);
    CHECK(valid);

    data[0] ^= 0x01;
    CHECK(!Crypto::RSA::verify(data, signature, keyPair.publicKeyPEM));

    std::cout << "    [SUCCESS] RSA-2048 Encryption & Digital Signature verified.\n\n";
}

void testECDSA()
{
    std::cout << "[6] Testing ECDSA (NIST P-256 Digital Signatures)...\n";
    auto keyPair = Crypto::ECDSA::generateKeyPair();

    std::string text = "Message to sign with ECDSA";
    std::vector<uint8_t> data(text.begin(), text.end());

    auto signature = Crypto::ECDSA::sign(data, keyPair.privateKeyPEM);
    bool valid = Crypto::ECDSA::verify(data, signature, keyPair.publicKeyPEM);
    CHECK(valid);

    data[0] ^= 0x01;
    CHECK(!Crypto::ECDSA::verify(data, signature, keyPair.publicKeyPEM));

    std::cout << "    [SUCCESS] ECDSA signature verified successfully.\n\n";
}

void testSHA256AndHMAC()
{
    std::cout << "[7] Testing SHA-256 & HMAC...\n";
    std::string text = "Authenticatable Data";
    std::vector<uint8_t> data(text.begin(), text.end());
    auto key = Crypto::Random::generateBytes(32);

    std::string hashHex = Crypto::SHA256::hashToHex(data);
    auto mac = Crypto::HMAC::calculateSHA256(data, key);

    CHECK(hashHex.size() == 64);
    CHECK(mac.size() == 32);
    CHECK(Crypto::HMAC::verifySHA256(data, key, mac));

    std::cout << "    SHA-256 Hex: " << hashHex << "\n";
    std::cout << "    [SUCCESS] SHA-256 and HMAC verified.\n\n";
}

int main()
{
    std::cout << "===================================================\n";
    std::cout << "  C++11 Complete Cryptography Suite Verification   \n";
    std::cout << "===================================================\n\n";

    try
    {
        testRandomAndCleanse();
        testPBKDF2();
        testAES256CBC();
        testAES256GCM();
        testRSA();
        testECDSA();
        testSHA256AndHMAC();

        std::cout << "ALL CRYPTOGRAPHIC TESTS COMPLETED SUCCESSFULLY!\n";
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[-] Critical Error: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
