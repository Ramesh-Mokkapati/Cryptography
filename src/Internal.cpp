// Internal.cpp
// Error handling, size checks and PEM key conversion shared by the library sources.

#include "Internal.hpp"
#include "crypto/Random.hpp"

#include <openssl/pem.h>

namespace Crypto
{
    namespace detail
    {
        void throwOpenSSL(const std::string& what)
        {
            // Append the oldest queued OpenSSL error, which is normally the root cause;
            // later entries tend to be the same failure reported by outer layers.
            std::string message = what;
            const unsigned long code = ERR_get_error();
            if (code != 0)
            {
                char reason[256] = { 0 };
                ERR_error_string_n(code, reason, sizeof(reason));
                message += " (";
                message += reason;
                message += ")";
            }

            // Leave a clean queue for the next operation on this thread.
            ERR_clear_error();
            throw std::runtime_error(message);
        }

        void clearErrors()
        {
            ERR_clear_error();
        }

        int toInt(std::size_t size, const char* what)
        {
            // OpenSSL's older APIs take int lengths. Silently casting a >2 GB size_t would
            // truncate it and process only part of the data, so refuse it instead.
            if (size > static_cast<std::size_t>(INT_MAX))
            {
                throw std::invalid_argument(std::string(what) + ": input too large");
            }

            return static_cast<int>(size);
        }

        PkeyPtr readPublicKey(const std::string& pem)
        {
            // A read-only memory BIO lets OpenSSL's PEM parser read straight from the string.
            BioPtr bio(BIO_new_mem_buf(pem.data(), toInt(pem.size(), "Public key PEM")));
            if (!bio)
            {
                throwOpenSSL("Failed to allocate BIO");
            }

            // Accepts "BEGIN PUBLIC KEY" (SubjectPublicKeyInfo) for any key type; callers
            // check the type afterwards (requireRsa / requireEc).
            PkeyPtr key(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
            if (!key)
            {
                throwOpenSSL("Failed to parse Public Key PEM");
            }

            return key;
        }

        PkeyPtr readPrivateKey(const std::string& pem)
        {
            BioPtr bio(BIO_new_mem_buf(pem.data(), toInt(pem.size(), "Private key PEM")));
            if (!bio)
            {
                throwOpenSSL("Failed to allocate BIO");
            }

            // A null passphrase callback with a null user pointer would prompt on the console for
            // encrypted keys; pass an empty passphrase instead so encrypted keys fail cleanly.
            // Accepts PKCS#8 ("BEGIN PRIVATE KEY") and the traditional per-algorithm formats.
            PkeyPtr key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, const_cast<char*>("")));
            if (!key)
            {
                throwOpenSSL("Failed to parse Private Key PEM");
            }

            return key;
        }

        namespace
        {
            // Copies the contents of a memory BIO into a std::string.
            std::string bioToString(BIO* bio)
            {
                char* data = nullptr;
                const long len = BIO_get_mem_data(bio, &data);   // points into the BIO's buffer, not a copy
                if (len <= 0 || !data)
                {
                    throwOpenSSL("Failed to read PEM output");
                }

                return std::string(data, static_cast<std::size_t>(len));
            }
        } // namespace

        std::string writePublicKey(EVP_PKEY* key)
        {
            // A growable memory BIO collects the PEM text instead of writing a file.
            BioPtr bio(BIO_new(BIO_s_mem()));
            if (!bio || PEM_write_bio_PUBKEY(bio.get(), key) != 1)
            {
                throwOpenSSL("Failed to write Public Key PEM");
            }

            return bioToString(bio.get());
        }

        std::string writePrivateKey(EVP_PKEY* key)
        {
            // PKCS#8 is the algorithm-neutral format ("BEGIN PRIVATE KEY") that other tools
            // and languages read most easily. No cipher/passphrase: the PEM is unencrypted.
            BioPtr bio(BIO_new(BIO_s_mem()));
            if (!bio || PEM_write_bio_PKCS8PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1)
            {
                throwOpenSSL("Failed to write Private Key PEM");
            }

            std::string pem = bioToString(bio.get());

            // Wipe the copy of the private key left in the memory BIO before it is freed.
            char* data = nullptr;
            const long len = BIO_get_mem_data(bio.get(), &data);
            if (len > 0 && data)
            {
                Random::secureCleanse(data, static_cast<std::size_t>(len));
            }

            return pem;
        }

    } // namespace detail
} // namespace Crypto
