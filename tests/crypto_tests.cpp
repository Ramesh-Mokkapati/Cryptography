// crypto_tests.cpp : known-answer tests (published vectors) and negative tests for crypto_wrapper.
//
// Three kinds of test:
//  - Known-answer tests compare output with vectors from the standards (FIPS, RFC, NIST),
//    which proves the right algorithm, mode and parameters are used, not just that
//    encrypt/decrypt are inverses of each other.
//  - Negative tests check that tampered data, wrong keys and bad input are rejected.
//  - Configuration proofs call OpenSSL directly to show the library uses PSS and OAEP-SHA256.
//
// The program prints PASS/FAIL per test and exits with 0 only if every check passed, so it
// can run under CTest, CI or the Visual Studio debugger without a test framework.
//
// To add a test: write a `void MyTest()` that uses CHECK(...), then add it to the table in main().

#include "crypto/AES.hpp"
#include "crypto/ECDSA.hpp"
#include "crypto/HMAC.hpp"
#include "crypto/KDF.hpp"
#include "crypto/RSA.hpp"
#include "crypto/Random.hpp"
#include "crypto/SHA.hpp"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <cstdio>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    typedef std::vector<uint8_t> Bytes;

    // Counters for the summary line, and the name of the running test for failure messages.
    int g_checks = 0;
    int g_failures = 0;
    const char* g_test = "";

    // Records a failure (with the line and expression) but keeps going, so one run reports
    // every broken check instead of stopping at the first. Unlike assert(), it also runs
    // in Release builds.
#define CHECK(cond)                                                                      \
    do {                                                                                     \
        ++g_checks;                                                                          \
        if (!(cond)) {                                                                       \
            ++g_failures;                                                                    \
            std::printf("  FAILED %s (line %d): %s\n", g_test, __LINE__, #cond);             \
        }                                                                                    \
    } while (0)

    // True only if fn() throws exactly an Ex (or a type derived from it). A different exception
    // type counts as failure, so tests also pin down *which* error the library reports.
    template <typename Ex, typename Fn>
    bool throws(Fn fn)
    {
        try
        {
            fn();
        }
        catch (const Ex&)
        {
            return true;
        }
        catch (...)
        {
            return false;
        }

        return false;
    }

    // Test-vector helpers: hex("0a0b") -> {0x0a, 0x0b}; toHex is the reverse;
    // str("abc") -> the bytes of the string (no terminator).
    Bytes hex(const std::string& h)
    {
        Bytes out;
        for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        {
            out.push_back(static_cast<uint8_t>(std::stoi(h.substr(i, 2), nullptr, 16)));
        }

        return out;
    }

    std::string toHex(const Bytes& b)
    {
        static const char digits[] = "0123456789abcdef";
        std::string s;
        for (uint8_t v : b)
        {
            s += digits[v >> 4];
            s += digits[v & 15];
        }

        return s;
    }

    Bytes str(const std::string& s)
    {
        return Bytes(s.begin(), s.end());
    }

    // ---------------------------------------------------------------------------------------
    // SHA-256: FIPS 180-2 / NIST examples

    void Sha256KnownAnswers()
    {
        CHECK(Crypto::SHA256::hashToHex(str("")) ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        CHECK(Crypto::SHA256::hashToHex(str("abc")) ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        CHECK(Crypto::SHA256::hashToHex(str("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) ==
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        CHECK(Crypto::SHA256::hash(str("abc")).size() == 32);
    }

    // ---------------------------------------------------------------------------------------
    // HMAC-SHA256: RFC 4231

    void HmacKnownAnswers()
    {
        // Test case 1
        CHECK(toHex(Crypto::HMAC::calculateSHA256(str("Hi There"), Bytes(20, 0x0b))) ==
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

        // Test case 2
        CHECK(toHex(Crypto::HMAC::calculateSHA256(str("what do ya want for nothing?"), str("Jefe"))) ==
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

        // Test case 6: key longer than the block size
        CHECK(toHex(Crypto::HMAC::calculateSHA256(str("Test Using Larger Than Block-Size Key - Hash Key First"),
            Bytes(131, 0xaa))) ==
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

        // Empty key and empty message
        CHECK(toHex(Crypto::HMAC::calculateSHA256(Bytes(), Bytes())) ==
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
    }

    void HmacVerify()
    {
        const Bytes key = Crypto::Random::generateBytes(32);
        const Bytes msg = str("message");
        Bytes mac = Crypto::HMAC::calculateSHA256(msg, key);
        CHECK(Crypto::HMAC::verifySHA256(msg, key, mac));
        mac[31] ^= 0x80;
        CHECK(!Crypto::HMAC::verifySHA256(msg, key, mac));
        CHECK(!Crypto::HMAC::verifySHA256(msg, key, Bytes(mac.begin(), mac.begin() + 16)));   // truncated
        CHECK(!Crypto::HMAC::verifySHA256(msg, key, Bytes()));
    }

    // ---------------------------------------------------------------------------------------
    // PBKDF2-HMAC-SHA256: RFC 7914 section 11 and the widely published "password"/"salt" vectors

    void Pbkdf2KnownAnswers()
    {
        CHECK(toHex(Crypto::KDF::pbkdf2("passwd", str("salt"), 1, 64)) ==
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
            "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783");

        CHECK(toHex(Crypto::KDF::pbkdf2("Password", str("NaCl"), 80000, 64)) ==
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
            "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d");

        CHECK(toHex(Crypto::KDF::pbkdf2("password", str("salt"), 1, 32)) ==
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");

        CHECK(toHex(Crypto::KDF::pbkdf2("password", str("salt"), 4096, 32)) ==
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
    }

    void Pbkdf2Validation()
    {
        CHECK(throws<std::invalid_argument>([] { Crypto::KDF::pbkdf2("pw", str("salt"), 0, 32); }));
        CHECK(throws<std::invalid_argument>([] { Crypto::KDF::pbkdf2("pw", str("salt"), 1000, 0); }));
        CHECK(Crypto::KDF::pbkdf2("pw", str("salt-a"), 1000, 32) != Crypto::KDF::pbkdf2("pw", str("salt-b"), 1000, 32));
    }

    // ---------------------------------------------------------------------------------------
    // AES-256-CBC: NIST SP 800-38A F.2.5

    void AesCbcKnownAnswer()
    {
        const Bytes key = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        const Bytes iv = hex("000102030405060708090a0b0c0d0e0f");
        const Bytes pt = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
        const std::string expected = "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
            "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b";

        const Bytes ct = Crypto::AES256::encryptCBC(pt, key, iv);

        // The library adds PKCS#7 padding, so a whole-block input gains one padding block.
        CHECK(ct.size() == pt.size() + 16);

        CHECK(toHex(Bytes(ct.begin(), ct.begin() + 64)) == expected);

        CHECK(Crypto::AES256::decryptCBC(ct, key, iv) == pt);
    }

    void AesCbcEdgeCases()
    {
        const Bytes key = Crypto::Random::generateBytes(32);
        const Bytes iv = Crypto::Random::generateBytes(16);

        for (std::size_t n : { 0u, 1u, 15u, 16u, 17u, 1000u })
        {
            const Bytes pt = Crypto::Random::generateBytes(n);
            const Bytes ct = Crypto::AES256::encryptCBC(pt, key, iv);

            CHECK(ct.size() == (n / 16 + 1) * 16);

            CHECK(Crypto::AES256::decryptCBC(ct, key, iv) == pt);
        }

        CHECK(throws<std::invalid_argument>([&] { Crypto::AES256::encryptCBC(str("x"), Bytes(16), iv); }));

        CHECK(throws<std::invalid_argument>([&] { Crypto::AES256::encryptCBC(str("x"), key, Bytes(12)); }));

        CHECK(throws<std::invalid_argument>([&] { Crypto::AES256::decryptCBC(Bytes(15), key, iv); }));

        CHECK(throws<std::invalid_argument>([&] { Crypto::AES256::decryptCBC(Bytes(), key, iv); }));

        // A wrong key either fails the padding check or yields different bytes (CBC is not
        // authenticated, so ~1/256 of wrong keys still produce valid-looking padding).
        const Bytes pt = str("attack at dawn");
        const Bytes ct = Crypto::AES256::encryptCBC(pt, key, iv);
        Bytes wrong = key;
        wrong[0] ^= 1;
        bool rejected = false;
        try
        {
            rejected = Crypto::AES256::decryptCBC(ct, wrong, iv) != pt;
        }
        catch (const std::runtime_error&)
        {
            rejected = true;
        }

        CHECK(rejected);
    }

    // ---------------------------------------------------------------------------------------
    // AES-256-GCM: test cases 13-16 of "The Galois/Counter Mode of Operation" (McGrew & Viega)

    void AesGcmKnownAnswers()
    {
        const Bytes zeroKey(32, 0), zeroIv(12, 0);

        // Test case 13: empty plaintext
        Crypto::GCMResult r = Crypto::AES256::encryptGCM(Bytes(), zeroKey, zeroIv);

        CHECK(r.ciphertext.empty());

        CHECK(toHex(r.tag) == "530f8afbc74536b9a963b4f1c4cb738b");

        CHECK(Crypto::AES256::decryptGCM(Bytes(), zeroKey, zeroIv, r.tag).empty());

        // Test case 14: one zero block
        r = Crypto::AES256::encryptGCM(Bytes(16, 0), zeroKey, zeroIv);

        CHECK(toHex(r.ciphertext) == "cea7403d4d606b6e074ec5d3baf39d18");

        CHECK(toHex(r.tag) == "d0d1c8a799996bf0265b98b5d48ab919");

        const Bytes key = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        const Bytes iv = hex("cafebabefacedbaddecaf888");
        const Bytes pt = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");

        // Test case 15: no AAD
        r = Crypto::AES256::encryptGCM(pt, key, iv);

        CHECK(toHex(r.ciphertext) == "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad");

        CHECK(toHex(r.tag) == "b094dac5d93471bdec1a502270e3cc6c");

        // Test case 16: AAD and a 60-byte plaintext
        const Bytes aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        const Bytes pt60(pt.begin(), pt.begin() + 60);

        r = Crypto::AES256::encryptGCM(pt60, key, iv, aad);

        CHECK(toHex(r.ciphertext) == "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662");

        CHECK(toHex(r.tag) == "76fc6ece0f4e1768cddf8853bb2d551b");

        CHECK(Crypto::AES256::decryptGCM(r.ciphertext, key, iv, r.tag, aad) == pt60);
    }

    void AesGcmTamperingRejected()
    {
        const Bytes key = Crypto::Random::generateBytes(32);
        const Bytes iv = Crypto::Random::generateBytes(12);
        const Bytes aad = str("header");
        const Bytes pt = str("Payload to protect with AES-GCM");
        const Crypto::GCMResult r = Crypto::AES256::encryptGCM(pt, key, iv, aad);

        CHECK(Crypto::AES256::decryptGCM(r.ciphertext, key, iv, r.tag, aad) == pt);

        Bytes ct = r.ciphertext;
        ct[5] ^= 0x01;

        CHECK(throws<std::runtime_error>([&] { Crypto::AES256::decryptGCM(ct, key, iv, r.tag, aad); }));

        Bytes tag = r.tag;
        tag[15] ^= 0x01;

        CHECK(throws<std::runtime_error>([&] { Crypto::AES256::decryptGCM(r.ciphertext, key, iv, tag, aad); }));

        CHECK(throws<std::runtime_error>([&] { Crypto::AES256::decryptGCM(r.ciphertext, key, iv, r.tag, str("Header")); }));

        CHECK(throws<std::runtime_error>([&] { Crypto::AES256::decryptGCM(r.ciphertext, key, iv, r.tag); }));   // AAD dropped

        Bytes wrongKey = key;
        wrongKey[0] ^= 1;

        CHECK(throws<std::runtime_error>([&] { Crypto::AES256::decryptGCM(r.ciphertext, wrongKey, iv, r.tag, aad); }));

        Bytes wrongIv = iv;
        wrongIv[11] ^= 1;

        CHECK(throws<std::runtime_error>([&] { Crypto::AES256::decryptGCM(r.ciphertext, key, wrongIv, r.tag, aad); }));

        CHECK(throws<std::invalid_argument>([&] { Crypto::AES256::encryptGCM(pt, key, Bytes(16)); }));

        CHECK(throws<std::invalid_argument>([&] { Crypto::AES256::decryptGCM(r.ciphertext, key, iv, Bytes(12), aad); }));
    }

    // ---------------------------------------------------------------------------------------
    // RSA

    // RSA key generation is slow, so the RSA tests share one key pair, created on first use.
    const Crypto::RSAKeyPair& RsaKeys()
    {
        static const Crypto::RSAKeyPair keys = Crypto::RSA::generateKeyPair(2048);
        return keys;
    }

    void RsaKeyFormat()
    {
        const auto& k = RsaKeys();

        CHECK(k.publicKeyPEM.find("-----BEGIN PUBLIC KEY-----") == 0);

        CHECK(k.privateKeyPEM.find("-----BEGIN PRIVATE KEY-----") == 0);   // PKCS#8, unencrypted

        CHECK(throws<std::invalid_argument>([] { Crypto::RSA::generateKeyPair(1024); }));
    }

    void RsaEncryption()
    {
        const auto& k = RsaKeys();
        const Bytes msg = str("Payload for RSA Operations");
        const Bytes c1 = Crypto::RSA::encryptPublicKey(msg, k.publicKeyPEM);
        const Bytes c2 = Crypto::RSA::encryptPublicKey(msg, k.publicKeyPEM);

        CHECK(c1.size() == 256);

        CHECK(c1 != c2);   // OAEP is randomised

        CHECK(Crypto::RSA::decryptPrivateKey(c1, k.privateKeyPEM) == msg);

        // OAEP-SHA256 capacity for a 2048-bit key is 256 - 2*32 - 2 = 190 bytes.
        CHECK(Crypto::RSA::decryptPrivateKey(Crypto::RSA::encryptPublicKey(Bytes(190, 7), k.publicKeyPEM), k.privateKeyPEM) == Bytes(190, 7));

        CHECK(throws<std::runtime_error>([&] { Crypto::RSA::encryptPublicKey(Bytes(191, 7), k.publicKeyPEM); }));

        Bytes bad = c1;
        bad[100] ^= 1;

        CHECK(throws<std::runtime_error>([&] { Crypto::RSA::decryptPrivateKey(bad, k.privateKeyPEM); }));

        CHECK(throws<std::runtime_error>([&] { Crypto::RSA::encryptPublicKey(msg, "not a key"); }));
    }

    // Decrypts with plain OpenSSL using OAEP and the given hash, to prove which hash the library used.
    bool OpenSslOaepDecrypts(const Bytes& ct, const std::string& privPem, const EVP_MD* md)
    {
        BIO* bio = BIO_new_mem_buf(privPem.data(), static_cast<int>(privPem.size()));
        EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
        bool ok = EVP_PKEY_decrypt_init(ctx) > 0 &&
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0 &&
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) > 0 &&
            EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) > 0;

        if (ok)
        {
            Bytes out(512);
            std::size_t len = out.size();
            ok = EVP_PKEY_decrypt(ctx, out.data(), &len, ct.data(), ct.size()) > 0;
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);
        ERR_clear_error();
        return ok;
    }

    void RsaUsesOaepSha256()
    {
        const auto& k = RsaKeys();
        const Bytes ct = Crypto::RSA::encryptPublicKey(str("secret"), k.publicKeyPEM);

        CHECK(OpenSslOaepDecrypts(ct, k.privateKeyPEM, EVP_sha256()));

        CHECK(!OpenSslOaepDecrypts(ct, k.privateKeyPEM, EVP_sha1()));   // not OpenSSL's SHA-1 default
    }

    // Verifies with plain OpenSSL using the given padding, to prove the library signs with PSS.
    bool OpenSslVerifies(const Bytes& data, const Bytes& sig, const std::string& pubPem, int padding)
    {
        BIO* bio = BIO_new_mem_buf(pubPem.data(), static_cast<int>(pubPem.size()));
        EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        EVP_MD_CTX* md = EVP_MD_CTX_new();
        EVP_PKEY_CTX* pctx = nullptr;

        bool ok = EVP_DigestVerifyInit(md, &pctx, EVP_sha256(), nullptr, key) > 0 &&
            EVP_PKEY_CTX_set_rsa_padding(pctx, padding) > 0 &&
            (padding != RSA_PKCS1_PSS_PADDING || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_AUTO) > 0) &&
            EVP_DigestVerifyUpdate(md, data.data(), data.size()) > 0 &&
            EVP_DigestVerifyFinal(md, sig.data(), sig.size()) == 1;

        EVP_MD_CTX_free(md);
        EVP_PKEY_free(key);
        ERR_clear_error();

        return ok;
    }

    void RsaSignatures()
    {
        const auto& k = RsaKeys();
        const Bytes data = str("Payload for RSA Operations");
        const Bytes s1 = Crypto::RSA::sign(data, k.privateKeyPEM);
        const Bytes s2 = Crypto::RSA::sign(data, k.privateKeyPEM);

        CHECK(s1.size() == 256);

        CHECK(s1 != s2);   // PSS is randomised; PKCS#1 v1.5 would give identical signatures

        CHECK(Crypto::RSA::verify(data, s1, k.publicKeyPEM));

        CHECK(Crypto::RSA::verify(data, s2, k.publicKeyPEM));

        CHECK(OpenSslVerifies(data, s1, k.publicKeyPEM, RSA_PKCS1_PSS_PADDING));

        CHECK(!OpenSslVerifies(data, s1, k.publicKeyPEM, RSA_PKCS1_PADDING));

        Bytes tampered = data;
        tampered.back() ^= 1;

        CHECK(!Crypto::RSA::verify(tampered, s1, k.publicKeyPEM));

        Bytes badSig = s1;
        badSig[10] ^= 1;

        CHECK(!Crypto::RSA::verify(data, badSig, k.publicKeyPEM));

        CHECK(!Crypto::RSA::verify(data, Bytes(), k.publicKeyPEM));

        CHECK(!Crypto::RSA::verify(data, Bytes(3, 1), k.publicKeyPEM));

        const Crypto::RSAKeyPair other = Crypto::RSA::generateKeyPair(2048);

        CHECK(!Crypto::RSA::verify(data, s1, other.publicKeyPEM));

        CHECK(ERR_peek_error() == 0);   // failed verifications leave no stale OpenSSL errors
    }

    // ---------------------------------------------------------------------------------------
    // ECDSA P-256

    void EcdsaSignatures()
    {
        const Crypto::ECKeyPair k = Crypto::ECDSA::generateKeyPair();

        CHECK(k.publicKeyPEM.find("-----BEGIN PUBLIC KEY-----") == 0);

        CHECK(k.privateKeyPEM.find("-----BEGIN PRIVATE KEY-----") == 0);

        const Bytes data = str("Message to sign with ECDSA");
        const Bytes sig = Crypto::ECDSA::sign(data, k.privateKeyPEM);

        CHECK(sig.size() >= 8 && sig.size() <= 72 && sig[0] == 0x30);   // DER SEQUENCE

        CHECK(Crypto::ECDSA::verify(data, sig, k.publicKeyPEM));

        Bytes tampered = data;
        tampered[0] ^= 1;

        CHECK(!Crypto::ECDSA::verify(tampered, sig, k.publicKeyPEM));

        Bytes badSig = sig;
        badSig[badSig.size() - 1] ^= 1;

        CHECK(!Crypto::ECDSA::verify(data, badSig, k.publicKeyPEM));

        CHECK(!Crypto::ECDSA::verify(data, Bytes(), k.publicKeyPEM));

        const Crypto::ECKeyPair other = Crypto::ECDSA::generateKeyPair();

        CHECK(!Crypto::ECDSA::verify(data, sig, other.publicKeyPEM));

        // Keys of the wrong type are refused rather than silently used.
        CHECK(throws<std::invalid_argument>([&] { Crypto::ECDSA::sign(data, RsaKeys().privateKeyPEM); }));

        CHECK(throws<std::invalid_argument>([&] { Crypto::RSA::sign(data, k.privateKeyPEM); }));

        CHECK(ERR_peek_error() == 0);
    }

    // ---------------------------------------------------------------------------------------
    // Random

    void RandomAndCleanse()
    {
        CHECK(Crypto::Random::generateBytes(0).empty());

        const Bytes a = Crypto::Random::generateBytes(32);
        const Bytes b = Crypto::Random::generateBytes(32);

        CHECK(a.size() == 32 && b.size() == 32);

        CHECK(a != b);

        CHECK(a != Bytes(32, 0));

        Bytes secret = str("top secret key material");
        Crypto::Random::secureCleanse(secret.data(), secret.size());

        CHECK(secret == Bytes(secret.size(), 0));

        Crypto::Random::secureCleanse(nullptr, 10);   // no-op, must not crash
    }

    // One entry in the test table: a display name and the function to run.
    struct Test
    {
        const char* name;
        std::function<void()> fn;
    };

} // namespace

int main()
{
    // Tests run in this order; each is independent, so the order only affects the output.
    const Test tests[] = {
        { "Sha256KnownAnswers", Sha256KnownAnswers },
        { "HmacKnownAnswers", HmacKnownAnswers },
        { "HmacVerify", HmacVerify },
        { "Pbkdf2KnownAnswers", Pbkdf2KnownAnswers },
        { "Pbkdf2Validation", Pbkdf2Validation },
        { "AesCbcKnownAnswer", AesCbcKnownAnswer },
        { "AesCbcEdgeCases", AesCbcEdgeCases },
        { "AesGcmKnownAnswers", AesGcmKnownAnswers },
        { "AesGcmTamperingRejected", AesGcmTamperingRejected },
        { "RsaKeyFormat", RsaKeyFormat },
        { "RsaEncryption", RsaEncryption },
        { "RsaUsesOaepSha256", RsaUsesOaepSha256 },
        { "RsaSignatures", RsaSignatures },
        { "EcdsaSignatures", EcdsaSignatures },
        { "RandomAndCleanse", RandomAndCleanse },
    };

    // Print the OpenSSL version actually loaded (useful when a DLL from elsewhere is picked up).
    std::printf("OpenSSL: %s\n\n", OpenSSL_version(OPENSSL_VERSION));
    for (const Test& t : tests)
    {
        g_test = t.name;
        const int before = g_failures;

        // An unexpected exception fails this test but does not stop the remaining ones.
        try
        {
            t.fn();
        }
        catch (const std::exception& ex)
        {
            ++g_failures;
            std::printf("  FAILED %s: unexpected exception: %s\n", t.name, ex.what());
        }

        std::printf("%s %s\n", g_failures == before ? "PASS" : "FAIL", t.name);
    }

    // Exit code 0 = all passed; CTest and CI treat anything else as a failure.
    std::printf("\n%d checks, %d failed\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
