# kufuli

**kufuli** - Swahili for _lock_: cross-platform cryptographic signing, verification, and hashing for Scala 3 on JVM, Node.js, browsers and Native.

kufuli provides a unified API over platform-native crypto engines - JCA on JVM, Node.js `crypto` module, Web Crypto `SubtleCrypto` in browsers, OpenSSL on Linux, Security.framework on macOS, and BCrypt on Windows. All operations return typed errors via ZIO.

## Why kufuli?

Scala applications that target multiple platforms need cryptographic operations backed by each platform's native engine - not a pure-Scala reimplementation. Existing options serve subsets of this space well, but none cover all six deployment targets with a single API:

| Library | Platforms | Effect System | Native Crypto Engines |
| ------- | --------- | ------------- | --------------------- |
| [Bouncy Castle](https://www.bouncycastle.org/) | JVM | None (blocking) | No - pure Java implementation |
| [tsec](https://github.com/jmcardon/tsec) | JVM | Cats Effect | No - wraps JCA / Bouncy Castle |
| [bobcats](https://github.com/typelevel/bobcats) | JVM, JS, Native | Cats Effect | Partial - Node.js and WebCrypto; no Native crypto engines |
| **kufuli** | JVM, JS, Browser, Native | ZIO | Yes - all six platform engines |

kufuli delegates to the OS-provided cryptographic implementation on every target: JCA on JVM, Node.js `crypto` and Web Crypto `SubtleCrypto` on JS, OpenSSL EVP on Linux, Security.framework on macOS, and BCrypt on Windows. This means your application uses the same FIPS-validated (where applicable) crypto primitives as the host platform, with no additional native dependencies beyond what the OS already ships (except OpenSSL headers on Linux, which is generally the defacto).

## Installation

```scala
// JVM, Node.js (Scala.js), or Scala Native
libraryDependencies += "io.github.arashi01" %%% "kufuli-zio" % "<version>"

// Browser (Scala.js, Web Crypto) - use instead of kufuli-zio for browser targets
libraryDependencies += "io.github.arashi01" % "kufuli-zio-browser" % "<version>"
```

`kufuli-zio` is a cross-project published for JVM, Scala.js, and Scala Native. The `%%%` operator selects the correct platform artifact automatically. Browser applications use `kufuli-zio-browser` instead, which provides a Web Crypto `SubtleCrypto` backend.

For projects that only need the pure algorithm models, key types, and security primitives (no ZIO, no platform backends):

```scala
libraryDependencies += "io.github.arashi01" %%% "kufuli-core" % "<version>"
```

## Requirements

- **JVM**: JDK 21+ (JDK 17's SunEC provider incorrectly rejects valid ECDSA signatures where the nonce produces a point with x-coordinate >= curve order - [Wycheproof `ArithmeticError` vectors](https://github.com/C2SP/wycheproof), tcId 350/382/419)
- **Node.js**: 22.x+
- **Scala**: 3.8+
- **Scala Native (Linux)**: OpenSSL development headers (`libssl-dev` on Debian/Ubuntu, `openssl-devel` on Fedora/RHEL). macOS and Windows use built-in frameworks with no additional dependencies.

## Supported Algorithms

| Family | Algorithms | JWS Names |
| ------ | ---------- | --------- |
| HMAC | `HmacSha256`, `HmacSha384`, `HmacSha512` | HS256, HS384, HS512 |
| RSA PKCS#1 v1.5 | `RsaPkcs1Sha256`, `RsaPkcs1Sha384`, `RsaPkcs1Sha512` | RS256, RS384, RS512 |
| RSA-PSS | `RsaPssSha256`, `RsaPssSha384`, `RsaPssSha512` | PS256, PS384, PS512 |
| ECDSA | `EcdsaP256Sha256`, `EcdsaP384Sha384`, `EcdsaP521Sha512` | ES256, ES384, ES512 |
| EdDSA | `Ed25519`, `Ed448` | EdDSA |

Digest algorithms: `Sha1`, `Sha256`, `Sha384`, `Sha512`.

Resolve JWS "alg" header values at runtime via `SignAlgorithm.fromJwsName`:

```scala
SignAlgorithm.fromJwsName("ES256")                      // Right(EcdsaP256Sha256)
SignAlgorithm.fromJwsName("EdDSA", OkpCurve.Ed25519)    // Right(Ed25519)
SignAlgorithm.fromJwsName("EdDSA")                      // Left - requires curve
```

### Platform Algorithm Support

Not all algorithms are available on every platform. The table below shows which combinations are supported:

| Algorithm | JVM | Node.js | Browser | Native (Linux) | Native (macOS) | Native (Windows) |
| --------- | --- | ------- | ------- | -------------- | -------------- | ---------------- |
| HMAC-SHA* | Yes | Yes | Yes | Yes | Yes | Yes |
| RSA PKCS#1 | Yes | Yes | Yes | Yes | Yes | Yes |
| RSA-PSS | Yes | Yes | Yes | Yes | Yes | Yes |
| ECDSA P-256/384/521 | Yes | Yes | Yes | Yes | Yes | Yes |
| Ed25519 | Yes | Yes | Yes | Yes | No | No |
| Ed448 | Yes | Yes | No | Yes | No | No |

Attempting to use an unsupported algorithm returns `KufuliError.UnsupportedAlgorithm`.

## Usage

```scala
import kufuli.*
import kufuli.zio.*
import kufuli.zio.given
import zio.*

// Every operation returns typed errors - no exceptions
val signAndVerify: IO[KufuliError, Unit] =
  for
    // Key construction validates security invariants
    key      <- ZIO.fromEither(CryptoKey.symmetric(hmacKeyBytes))

    // Prepare once (expensive platform import), use many times (cheap)
    signer   <- key.prepareSigning(SignAlgorithm.HmacSha256)
    verifier <- key.prepareVerifying(SignAlgorithm.HmacSha256)

    // Sign returns typed Signature
    sig      <- signer.sign(data)

    // Verify accepts typed Signature
    _        <- verifier.verify(data, sig)
  yield ()

// Digest returns typed Digest
val hash: IO[KufuliError, Digest] =
  data.digest(DigestAlgorithm.Sha256)
```

Key construction returns `Either[KufuliError, CryptoKey]`, catching invalid key material as a typed value at the boundary. Key preparation is separated from signing/verification - prepare a key once (expensive platform import), then sign or verify many times (cheap).

### Signature Formats

`Signature` and `Digest` are zero-cost opaque types wrapping `Array[Byte]`. They prevent accidentally mixing signature bytes with digest bytes or arbitrary data at compile time.

For ECDSA, two wire formats exist. `Signature` provides format-aware constructors:

```scala
// From JWS R||S format (RFC 7515 ss3.4)
val sig = Signature.ecdsaConcat(rsBytes, EcCurve.P256)

// From DER format (X.509, OpenSSL, TLS)
val sig = Signature.ecdsaDer(derBytes, EcCurve.P256)

// Convert between formats
sig.toEcdsaDer                          // Signature -> Either[KufuliError, Array[Byte]]
sig.toEcdsaConcat(EcCurve.P256)         // Signature -> Either[KufuliError, Array[Byte]]

// For HMAC, RSA, EdDSA (no format ambiguity)
val sig = Signature.raw(signatureBytes)
```

`Digest` provides timing-safe comparison and hex display:

```scala
Digest.constantTimeEquals(computed, stored) // Boolean, constant-time
digest.toHex                                // "e3b0c44298fc1c14..."
```

### Key Construction

All constructors validate security invariants and return `Either[KufuliError, CryptoKey]`.

```scala
CryptoKey.symmetric(bytes)                          // HMAC
CryptoKey.rsaPublic(modulus, exponent)               // RSA (>= 2048 bits)
CryptoKey.rsaPrivate(modulus, exponent, d, p, q, dp, dq, qi)
CryptoKey.ecPublic(EcCurve.P256, x, y)              // ECDSA (point-on-curve validated)
CryptoKey.ecPrivate(EcCurve.P256, x, y, d)
CryptoKey.okpPublic(OkpCurve.Ed25519, x)             // EdDSA
CryptoKey.okpPrivate(OkpCurve.Ed25519, x, d)
```

All byte arrays are defensively cloned. RSA keys require >= 2048-bit modulus. EC keys are validated against the curve equation. OKP keys are validated for correct length.

### Key Introspection

`CryptoKey` exposes structural metadata without revealing key material:

```scala
key.keyType    // KeyType.Symmetric | Rsa | Ec | Okp
key.ecCurve    // Option[EcCurve] - Some for EC keys
key.okpCurve   // Option[OkpCurve] - Some for OKP keys
key.isPrivate  // true for symmetric, private RSA/EC/OKP keys
```

### Error Handling

All errors are values in the `KufuliError` ADT (extends `Throwable` with `NoStackTrace`):

| Variant | Meaning |
| ------- | ------- |
| `InvalidKey` | Key material fails validation (wrong size, not on curve, CRT mismatch) |
| `InvalidSignature` | Signature bytes are structurally invalid (wrong length, malformed DER, component out of range) |
| `SignatureMismatch` | Signature is well-formed but does not verify against the provided data and key |
| `UnsupportedAlgorithm` | Algorithm not available on this platform |
| `SignatureFailure` | Platform signing operation failed |
| `VerificationFailure` | Platform verification operation failed |
| `DigestFailure` | Platform digest operation failed |

### Platform Backends

Platform `given` instances are resolved automatically via `import kufuli.zio.given`. The correct backend is selected at compile time based on the target platform.

| Platform | Dependency | Crypto Engine |
| -------- | ---------- | ------------- |
| JVM | `kufuli-zio` | JCA (`java.security`, `javax.crypto`) |
| Node.js (Scala.js) | `kufuli-zio` | Node.js `crypto` module |
| Browser (Scala.js) | `kufuli-zio-browser` | Web Crypto `SubtleCrypto` |
| Native (Linux) | `kufuli-zio` | OpenSSL EVP |
| Native (macOS) | `kufuli-zio` | Security.framework + CommonCrypto |
| Native (Windows) | `kufuli-zio` | BCrypt |

### Security

- HMAC verification uses constant-time comparison on all platforms
- `prepareSigning` rejects public-only keys; `prepareVerifying` accepts both
- ECDSA signatures are pre-validated against the curve order before platform dispatch (CVE-2022-21449 mitigation)
- EdDSA signatures are length-checked before verification
- RSA keys require >= 2048-bit modulus; CRT invariant (n == p * q) is checked
- EC public keys are validated against the curve equation
- EC private key scalars are validated in [1, n-1]
- Key material byte arrays are cloned on construction to prevent external mutation
- Key equality uses constant-time comparison (`CryptoKey.contentEquals`)
- Strict DER parsing rejects non-canonical BER encodings
- Tested against [Wycheproof](https://github.com/C2SP/wycheproof) vectors (ECDSA, RSA PKCS#1, RSA-PSS, Ed25519)

## Modules

| Module | Platforms | Purpose |
| ------ | --------- | ------- |
| `kufuli-core` | JVM, JS, Native | Algorithm models, key types, security primitives |
| `kufuli-zio` | JVM, JS, Native | ZIO typeclasses and platform-specific crypto backends |
| `kufuli-zio-browser` | JS | Web Crypto backend |
| `kufuli-testkit` | JVM, JS, Native | RFC test vectors and abstract test suites |

## Licence

MIT
