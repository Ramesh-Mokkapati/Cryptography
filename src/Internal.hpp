// Internal.hpp
// Internal helpers shared by the library sources (not installed, not part of the public API).
//
// Conventions used throughout src/:
//  - Every OpenSSL object is held in one of the *Ptr types below, so it is freed on every
//    path, including when an exception is thrown halfway through a function.
//  - OpenSSL functions report failure through return codes and a per-thread error queue.
//    Failures are turned into exceptions with throwOpenSSL(), which also empties the queue.
//  - Where a failure is a normal answer (a signature that does not verify), the queue is
//    emptied with clearErrors() so stale errors don't confuse later, unrelated calls.

#ifndef CRYPTO_INTERNAL_HPP
#define CRYPTO_INTERNAL_HPP

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <climits>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>

namespace Crypto
{
    namespace detail
    {
        // RAII owners for OpenSSL objects, so every early return / throw frees them.
        // Each deleter calls the matching OpenSSL *_free function (all accept nullptr).
        struct CipherCtxDeleter { void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); } };
        struct MdCtxDeleter { void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); } };
        struct PkeyDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
        struct PkeyCtxDeleter { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
        struct BioDeleter { void operator()(BIO* p) const { BIO_free_all(p); } };

        typedef std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter> CipherCtxPtr;  // symmetric cipher state (AES)
        typedef std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>         MdCtxPtr;      // digest / digest-sign state
        typedef std::unique_ptr<EVP_PKEY, PkeyDeleter>            PkeyPtr;       // a public or private key
        typedef std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter>     PkeyCtxPtr;    // key operation (keygen, RSA encrypt)
        typedef std::unique_ptr<BIO, BioDeleter>                  BioPtr;        // OpenSSL in-memory I/O stream

        // Throws std::runtime_error with the message plus OpenSSL's most recent reason,
        // and clears the thread's OpenSSL error queue.
        // Example message: "Failed to parse Public Key PEM (error:1E08010C:DECODER routines::unsupported)".
        [[noreturn]] void throwOpenSSL(const std::string& what);

        // Clears the OpenSSL error queue (used where a failure is an expected answer, e.g. verify == false).
        void clearErrors();

        // OpenSSL takes int lengths; refuse sizes that would be truncated.
        // Returns size as int, or throws std::invalid_argument("<what>: input too large").
        int toInt(std::size_t size, const char* what);

        // PEM <-> EVP_PKEY
        // read*: parse a PEM string into a key object; throw std::runtime_error if it is not valid PEM.
        // write*: serialise a key; the private key is written as unencrypted PKCS#8.
        PkeyPtr readPublicKey(const std::string& pem);
        PkeyPtr readPrivateKey(const std::string& pem);
        std::string writePublicKey(EVP_PKEY* key);
        std::string writePrivateKey(EVP_PKEY* key);   // unencrypted PKCS#8

    } // namespace detail
} // namespace Crypto

#endif // CRYPTO_INTERNAL_HPP
