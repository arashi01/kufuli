# kufuli

**kufuli** - Swahili for _lock_: cross-platform cryptographic signing, verification, and hashing for Scala 3 on JVM, Node.js, browsers and Native.

kufuli provides a unified API over platform-native crypto engines - JCA on JVM, Node.js `crypto` module, Web Crypto `SubtleCrypto` in browsers, OpenSSL on Linux, Security.framework on macOS, and BCrypt on Windows. All operations return typed errors via ZIO.

## Installation

```scala
// JVM or Node.js (Scala.js)
libraryDependencies += "io.github.arashi01" %%% "kufuli-zio" % "<version>"

// Browser (Scala.js, Web Crypto)
libraryDependencies += "io.github.arashi01" % "kufuli-zio-browser" % "<version>"
```

## Supported Algorithms

| Family | Algorithms | JWS Names |
| ------ | ---------- | --------- |
| HMAC | `HmacSha256`, `HmacSha384`, `HmacSha512` | HS256, HS384, HS512 |
| RSA PKCS#1 v1.5 | `RsaPkcs1Sha256`, `RsaPkcs1Sha384`, `RsaPkcs1Sha512` | RS256, RS384, RS512 |
| RSA-PSS | `RsaPssSha256`, `RsaPssSha384`, `RsaPssSha512` | PS256, PS384, PS512 |
| ECDSA | `EcdsaP256Sha256`, `EcdsaP384Sha384`, `EcdsaP521Sha512` | ES256, ES384, ES512 |
| EdDSA | `Ed25519`, `Ed448` | EdDSA |

Ed448 is not supported on the Web Crypto or Native backends. Ed25519 is not supported on the Web Crypto or Native (macOS/Windows) backends.

Digest algorithms: `Sha1`, `Sha256`, `Sha384`, `Sha512`.

## Usage

```scala
import kufuli.*
import kufuli.zio.*
import kufuli.zio.given
import zio.*

// Construct a key (validates at construction time)
val key: Either[KufuliError, CryptoKey] =
  CryptoKey.symmetric(hmacKeyBytes)

// Sign - returns typed Signature (not raw Array[Byte])
val sign: IO[KufuliError, Signature] =
  for
    prepared <- key.prepareSigning(SignAlgorithm.HmacSha256)
    sig      <- prepared.sign(data)
  yield sig

// Verify - accepts typed Signature
val verify: IO[KufuliError, Unit] =
  for
    prepared <- key.prepareVerifying(SignAlgorithm.HmacSha256)
    _        <- prepared.verify(data, Signature.raw(signatureBytes))
  yield ()

// Digest - returns typed Digest (not raw Array[Byte])
val hash: IO[KufuliError, Digest] =
  data.digest(DigestAlgorithm.Sha256)
```

Key preparation is separated from signing/verification. This lets you prepare a key once (expensive platform import) and sign or verify many times (cheap).

### Signature Types

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

`Digest` provides timing-safe comparison to prevent side-channel attacks:

```scala
Digest.constantTimeEquals(computed, stored) // Boolean, constant-time
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

### Error Handling

All errors are values in the `KufuliError` ADT (extends `Throwable` with `NoStackTrace`):

| Variant | Meaning |
| ------- | ------- |
| `InvalidKey` | Key material fails validation (wrong size, not on curve, CRT mismatch) |
| `InvalidSignature` | Signature is structurally invalid or verification failed |
| `UnsupportedAlgorithm` | Algorithm not available on this platform |
| `SignatureFailure` | Platform signing operation failed |
| `VerificationFailure` | Platform verification operation failed |
| `DigestFailure` | Platform digest operation failed |

### Platform Backends

Platform `given` instances are resolved automatically via `import kufuli.zio.given`. The correct backend is selected at compile time based on the target platform.

| Platform | Backend | Crypto Engine |
| -------- | ------- | ------------- |
| JVM | `kufuli-zio` | JCA (`java.security`, `javax.crypto`) |
| Node.js (Scala.js) | `kufuli-zio` | Node.js `crypto` module |
| Browser (Scala.js) | `kufuli-zio-browser` | Web Crypto `SubtleCrypto` |
| Native (Linux) | `kufuli-zio` | OpenSSL EVP |
| Native (macOS) | `kufuli-zio` | Security.framework + CommonCrypto |
| Native (Windows) | `kufuli-zio` | BCrypt |

### Security

- HMAC verification uses constant-time comparison on all platforms
- ECDSA signatures are pre-validated against the curve order before platform dispatch (CVE-2022-21449 mitigation)
- EdDSA signatures are length-checked before verification
- RSA keys require >= 2048-bit modulus; CRT invariant (n == p * q) is checked
- EC public keys are validated against the curve equation
- Key material byte arrays are cloned on construction to prevent external mutation
- Key equality uses constant-time comparison (`CryptoKey.contentEquals`)

## Modules

| Module | Platforms | Purpose |
| ------ | --------- | ------- |
| `kufuli-core` | JVM, JS, Native | Algorithm models, key types, security primitives |
| `kufuli-zio` | JVM, JS, Native | ZIO typeclasses and JVM/Node.js backends |
| `kufuli-zio-browser` | JS | Web Crypto backend |
| `kufuli-testkit` | JVM, JS, Native | RFC test vectors and abstract test suites |

## Licence

MIT
