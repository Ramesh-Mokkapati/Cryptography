# CryptoWrapper – C++11 static cryptography library over OpenSSL

A small, exception-based C++11 API over OpenSSL 1.1.1 or 3.x, built from `cryptography_static_library_runbook.md`.

| Header | Class | What it does |
|---|---|---|
| `crypto/Random.hpp` | `Crypto::Random` | CSPRNG bytes (`RAND_bytes`), secure memory wipe (`OPENSSL_cleanse`) |
| `crypto/KDF.hpp` | `Crypto::KDF` | PBKDF2-HMAC-SHA256 (default 100,000 iterations, 32-byte key) |
| `crypto/AES.hpp` | `Crypto::AES256` | AES-256-CBC (PKCS#7) and AES-256-GCM (96-bit IV, 128-bit tag, optional AAD) |
| `crypto/RSA.hpp` | `Crypto::RSA` | RSA key generation (≥ 2048 bits), OAEP encryption, PSS signatures |
| `crypto/ECDSA.hpp` | `Crypto::ECDSA` | P-256 key generation, ECDSA-SHA256 signatures (DER) |
| `crypto/SHA.hpp` | `Crypto::SHA256` | SHA-256 digest and hex digest |
| `crypto/HMAC.hpp` | `Crypto::HMAC` | HMAC-SHA256, plus a constant-time `verifySHA256` |

Keys are exchanged as PEM strings: public keys as `BEGIN PUBLIC KEY` (SubjectPublicKeyInfo), private keys as unencrypted PKCS#8 `BEGIN PRIVATE KEY`.

```cpp
#include "crypto/AES.hpp"
#include "crypto/Random.hpp"

auto key = Crypto::Random::generateBytes(Crypto::AES256::KEY_SIZE);
auto iv  = Crypto::Random::generateBytes(Crypto::AES256::GCM_IV_SIZE);   // never reuse with this key
auto sealed = Crypto::AES256::encryptGCM(plaintext, key, iv, aad);
auto opened = Crypto::AES256::decryptGCM(sealed.ciphertext, key, iv, sealed.tag, aad);  // throws if tampered
```

## Differences from the runbook listings

The public API matches the runbook, except for one addition: `HMAC::verifySHA256`. The implementations were hardened:

- **RSA signatures really use PSS.** The runbook's code left OpenSSL's default, PKCS#1 v1.5. Signatures now use PSS with SHA-256, MGF1-SHA-256 and salt length = digest length.
- **RSA-OAEP uses SHA-256.** OpenSSL defaults to SHA-1 for both the OAEP hash and MGF1. The OAEP-SHA-256 limit is 190 bytes of plaintext for RSA-2048. Larger data should be encrypted with AES-GCM, and the AES key with RSA.
- **No leaks on error.** Every OpenSSL object is owned by RAII (`std::unique_ptr` with deleters), and every return code is checked, including `BIO_new`, `PEM_write_*` and `Digest*Update`. Exceptions carry OpenSSL's reason string.
- **Signature checks never throw for bad signatures.** `verify` returns `false` for a wrong or malformed signature, and leaves no stale OpenSSL error queue. It throws only for an unusable key, or one of the wrong type (e.g. an RSA key passed to ECDSA).
- **Failed decryptions are wiped.** When GCM authentication or CBC unpadding fails, the plaintext buffer is wiped before the exception, so unauthenticated data never leaves the function. The memory copy of a generated private key is wiped too.
- **Inputs are validated.**
  - RSA keys must be at least 2048 bits.
  - PBKDF2 needs at least 1 iteration and a non-empty key.
  - CBC ciphertext must be a whole number of 16-byte blocks.
  - Sizes above `INT_MAX` are refused rather than truncated.
- **C++11 linkage of the size constants.** `static constexpr` sizes have out-of-class definitions, so passing `AES256::KEY_SIZE` by reference links under C++11.
- **Checks that still run in Release.** The samples use a check that runs in every build type; the runbook's `assert` disappears in Release. `tests/crypto_tests.cpp` adds known-answer and negative tests.

### Usage notes

- **GCM IVs:** a GCM `(key, IV)` pair must never repeat. Use a fresh random 12-byte IV per message, and rotate the key long before 2³² messages.
- **CBC needs a MAC:** CBC is not authenticated. Prefer GCM; if you must use CBC, use encrypt-then-MAC with HMAC-SHA256 over IV + ciphertext, and check it with `verifySHA256` before decrypting.
- **PBKDF2 inputs:** use a random salt of at least 16 bytes per password, and store it alongside the derived hash.

## Build

### Visual Studio 2022 solution

Open **`Cryptography.sln`** in Visual Studio 2022 Community and build. It has three projects:

| Project | Type | Output (`bin\<Platform>\<Configuration>\`) |
|---|---|---|
| `crypto_wrapper` | Static library | `crypto_wrapper.lib` |
| `crypto_samples` | Console app (runbook demo) | `crypto_samples.exe` |
| `crypto_tests` | Console app (known-answer and negative tests) | `crypto_tests.exe` |

Configurations: Debug and Release, for x64 and x86. Set `crypto_samples` or `crypto_tests` as the startup project to run it.

**Where OpenSSL comes from.** The projects use OpenSSL from vcpkg, through the MSBuild integration set up in `vs\Directory.Build.props`:
- It uses `VCPKG_ROOT` if set, otherwise the vcpkg that ships with VS 2022. That copy needs the *vcpkg package manager* component in the Visual Studio Installer.
- The first build of each platform installs OpenSSL from `vcpkg.json` into `vcpkg_installed\`. This takes ~20 minutes the first time and is cached afterwards.
- The OpenSSL DLL is copied next to the exes.

**Language standard.** MSVC's oldest selectable standard is C++14, so the projects use `/std:c++14`. The code is C++11, and the CMake build compiles it with `-std=c++11`. Shared compiler settings (`/W4`, `/permissive-`, include paths, output folders) are in `vs\Common.props`.

Or from a command prompt:

```bash
"C:/Program Files/Microsoft Visual Studio/2022/Community/MSBuild/Current/Bin/MSBuild.exe" Cryptography.sln -m -p:Configuration=Release -p:Platform=x64
```

### Windows with CMake (Visual Studio 2022 + vcpkg)

OpenSSL comes from vcpkg in manifest mode: `vcpkg.json` is pinned to a registry baseline. In a *Developer PowerShell for VS 2022*, `VCPKG_ROOT` is already set:

```bash
cmake --preset windows-x64
```

```bash
cmake --build --preset windows-x64-release
```

```bash
ctest --preset windows-x64-release
```

The first configure builds OpenSSL, which takes a few minutes; it's cached afterwards.

Outputs in `build/windows-x64/Release/`:
- `crypto_wrapper.lib` (MSVC's name for the static library)
- `crypto_samples.exe` and `crypto_tests.exe`
- the OpenSSL DLLs vcpkg copies next to them

Use `windows-x86` for 32-bit.

### Linux / macOS (runbook §5)

```bash
sudo apt-get install -y libssl-dev cmake g++
```

```bash
mkdir -p build && cd build && cmake .. && make && ./crypto_samples
```

Or with the preset: `cmake --preset linux && cmake --build --preset linux && ctest --preset linux`. Output: `libcrypto_wrapper.a`.

### Using the library

```cmake
add_subdirectory(crypto_project)          # or: cmake --install, then point at lib/ + include/
target_link_libraries(my_app PRIVATE crypto_wrapper OpenSSL::Crypto)
```

It's a static library, so the application also links OpenSSL's libcrypto.

## Tests

`ctest` runs two programs:

- **`crypto_samples`:** the runbook's seven demos, plus tamper checks.
- **`crypto_tests`:** 15 test groups:
  - **Known answers:** SHA-256 (FIPS 180-2), HMAC-SHA256 (RFC 4231 cases 1, 2 and 6, plus empty key and message), PBKDF2-HMAC-SHA256 (RFC 7914 §11 and common vectors), AES-256-CBC (NIST SP 800-38A F.2.5) and AES-256-GCM (GCM specification test cases 13–16).
  - **Tampering:** modified GCM ciphertext, tag, AAD, key or IV, and altered or foreign RSA and ECDSA signatures, must all be rejected.
  - **Behaviour:** padding sizes, the RSA-OAEP plaintext limit, key formats, wrong key types, and a clean error queue after failed checks.
  - **Configuration proofs:** plain OpenSSL is used to show that signatures are PSS rather than PKCS#1 v1.5, and that encryption is OAEP-SHA-256 rather than SHA-1.

CI (`.github/workflows/build.yml`) builds and tests:
- on Ubuntu 24.04 (OpenSSL 3.0) with GCC and Clang
- on Windows x64 and x86 with MSVC and vcpkg's OpenSSL, through both CMake and `Cryptography.sln`

## Layout

```
Cryptography.sln  vs/  (crypto_wrapper, crypto_samples, crypto_tests .vcxproj + shared props)
CMakeLists.txt  CMakePresets.json  vcpkg.json
include/crypto/   AES  RSA  ECDSA  KDF  Random  HMAC  SHA (.hpp)
src/              matching .cpp files + Internal.hpp/.cpp (RAII, PEM, error helpers)
samples/main.cpp  runbook demo
tests/crypto_tests.cpp
```
