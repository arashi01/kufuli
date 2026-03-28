# Contributing to kufuli

## Build Requirements

- JDK 21+
- sbt 1.12+
- Node.js 22+ (for Scala.js tests)
- OpenSSL development headers (required for Native on Linux)
- Playwright browsers
- Git (for external source checkout on first build)

## First Build

On a clean checkout, `sbt test` will automatically clone pinned external repositories to `.lib/`
via the `ExternalSources` mechanism (`project/ExternalSources.scala`). This requires network
access on the first build only. Subsequent builds reuse the cached checkouts.

```
sbt kufuli-jvm/test        # All JVM tests (core unit + integration)
sbt kufuli-js/test         # All JS tests (core unit + Node.js + browser via Playwright)
sbt kufuli-native/test     # All Native tests (core unit + platform integration)
```

These aggregate projects run tests for all modules on the target platform in a single command,
matching CI. `kufuli-js` aggregates both Node.js and browser (`kufuli-zio-browser`) tests.

## Project Structure

```
modules/
  core/              Pure types, algorithm models, security validation (no ZIO, no platform)
  zio/               ZIO typeclasses (shared) + platform backends (jvm/js/native)
  zio-browser/       Web Crypto SubtleCrypto backend (Scala.js, browser)
  tests/         Integration tests (shared + per-platform instantiation)
  testkit/           Abstract test suites, RFC vectors, shared test utilities
  js-shared/         Shared JS utilities (Node.js + browser)

project/
  ExternalSources.scala   Git checkout management for build-time dependencies
  WycheproofPlugin.scala  Embeds Wycheproof JSON as generated Scala source
```

## Test Structure

Tests are organised by purpose:

### Unit tests (`kufuli-core/test/`)

Pure tests with no platform backend or ZIO dependency. Two categories:

- **Internal logic:** `CryptoKeySpec`, `DigestSpec`, `SignatureSpec`, `EcdsaCodecSpec`,
  `SignAlgorithmSpec`, `ConstantTimeSpec` - regression and behaviour tests for our code.
- **Standards conformance (pure):** `EcParamsSpec` (FIPS 186-5 validation), `SecurityChecksSpec`
  (NIST SP 800-131A key sizes, RFC 7518 HMAC minimums) - verification that pure validation
  functions conform to standards.

### Integration tests (`kufuli-tests/shared/test/`)

Cross-platform tests that exercise the full stack through platform backends. Run on JVM, JS,
and Native.

- **RFC conformance:** `Rfc4231HmacSuite` (HMAC-SHA known-answer, RFC 4231 ss4),
  `Rfc8032Ed25519Suite` (Ed25519 known-answer, RFC 8032 ss7.1). These verify our implementation
  produces the exact output specified by the standard.
- **Adversarial (Wycheproof):** `WycheproofEcdsaSuite`, `WycheproofEcdsaP1363Suite`,
  `WycheproofEd25519Suite`, `WycheproofRsaSuite`, `WycheproofHmacSuite`. These test resistance
  to specific attack vectors (malformed signatures, edge-case keys, etc.).
- **Round-trip and rejection:** `CryptoTestSuite` (via `kufuli-testkit`) - sign-then-verify
  round-trips, tampered-message rejection, wrong-key rejection, algorithm mismatch rejection.

### Platform instantiation (`kufuli-tests/{jvm,js,native}/test/`)

Thin adapters that extend abstract test suites with the platform-specific ZIO runtime. These
files should contain only the `run` adapter and abstract method implementations - no test logic.

### Test requirements

- Every public API method must have at least one test.
- Every supported algorithm must have at least one RFC/NIST known-answer vector AND Wycheproof
  adversarial coverage where vectors exist.
- All applicable test vectors from referenced standards must be implemented. If a standard
  defines 5 test cases and 2 are inapplicable (e.g. key too short for our minimum), all 3
  applicable cases must be present, with the exclusions documented with the RFC reference.
- New test suites go in `shared/test/` (cross-platform) unless they test platform-specific
  behaviour that only exists on one platform.

## External Sources

Build-time dependencies (Wycheproof vectors, Argon2 C source) are managed by
`ExternalSources` in `project/ExternalSources.scala`. Repositories are pinned by exact commit
SHA for reproducible builds. The `.lib/` directory is gitignored.

To force a re-clone (e.g. after updating a SHA): `rm -rf .lib/<repo-name>`

## Code Style

Run `sbt format` before committing. The project compiles with `-Werror`, `-Yexplicit-nulls`, and all `-Wunused` flags. Test scope relaxes `-Werror` and `-Yexplicit-nulls`.
