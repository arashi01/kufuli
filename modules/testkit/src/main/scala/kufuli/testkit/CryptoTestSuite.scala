/*
 * Copyright (c) 2026 Ali Rashid.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package kufuli.testkit

import munit.FunSuite

import kufuli.CryptoKey
import kufuli.Digest
import kufuli.DigestAlgorithm
import kufuli.EcCurve
import kufuli.KufuliError
import kufuli.SignAlgorithm
import kufuli.Signature

/** Abstract test suite for verifying cryptographic backend implementations. Platform-specific test
  * modules extend this suite and implement the abstract methods using their effect runtime and
  * platform `given` instances.
  *
  * @see [[RfcVectors$ RfcVectors]] for the test vector data used by these tests
  */
abstract class CryptoTestSuite extends FunSuite:

  /** Sign data with the given key and algorithm. */
  def prepareAndSign(key: CryptoKey, algorithm: SignAlgorithm, data: Array[Byte]): Signature

  /** Verify a signature against data with the given key and algorithm. Throws on failure. */
  def prepareAndVerify(key: CryptoKey, algorithm: SignAlgorithm, data: Array[Byte], signature: Signature): Unit

  /** Compute a digest of the given data using the specified algorithm. */
  def computeDigest(data: Array[Byte], algorithm: DigestAlgorithm): Digest

  /** Attempt to prepare a key for signing, returning the error if it fails. */
  def prepareSigningError(key: CryptoKey, algorithm: SignAlgorithm): Option[KufuliError]

  // ---------------------------------------------------------------------------
  // HMAC tests
  // ---------------------------------------------------------------------------

  test("HMAC-SHA256 produces RFC 7515 A.1 expected signature"):
    val key = CryptoKey.symmetric(RfcVectors.hmacSha256Key).toOption.get
    val sig = prepareAndSign(key, SignAlgorithm.HmacSha256, RfcVectors.hmacSha256SigningInput)
    assertEquals(sig.bytes.toList, RfcVectors.hmacSha256ExpectedSignature.toList)

  test("HMAC-SHA256 signature verifies against RFC 7515 A.1 vector"):
    val key = CryptoKey.symmetric(RfcVectors.hmacSha256Key).toOption.get
    prepareAndVerify(
      key,
      SignAlgorithm.HmacSha256,
      RfcVectors.hmacSha256SigningInput,
      Signature.raw(RfcVectors.hmacSha256ExpectedSignature)
    )

  test("HMAC-SHA256 sign-verify round-trip"):
    val key = CryptoKey.symmetric(RfcVectors.hmacSha256Key).toOption.get
    val data = "test payload".getBytes("UTF-8")
    val sig = prepareAndSign(key, SignAlgorithm.HmacSha256, data)
    prepareAndVerify(key, SignAlgorithm.HmacSha256, data, sig)

  test("HMAC-SHA256 verification rejects wrong signature"):
    val key = CryptoKey.symmetric(RfcVectors.hmacSha256Key).toOption.get
    val data = "test payload".getBytes("UTF-8")
    val badSig = new Array[Byte](32)
    badSig(0) = 1
    intercept[Throwable]:
      prepareAndVerify(key, SignAlgorithm.HmacSha256, data, Signature.raw(badSig))

  test("HMAC-SHA384 sign-verify round-trip"):
    val keyBytes = new Array[Byte](48)
    keyBytes(0) = 42
    val key = CryptoKey.symmetric(keyBytes).toOption.get
    val data = "test payload".getBytes("UTF-8")
    val sig = prepareAndSign(key, SignAlgorithm.HmacSha384, data)
    assertEquals(sig.bytes.length, 48)
    prepareAndVerify(key, SignAlgorithm.HmacSha384, data, sig)

  test("HMAC-SHA512 sign-verify round-trip"):
    val keyBytes = new Array[Byte](64)
    keyBytes(0) = 42
    val key = CryptoKey.symmetric(keyBytes).toOption.get
    val data = "test payload".getBytes("UTF-8")
    val sig = prepareAndSign(key, SignAlgorithm.HmacSha512, data)
    assertEquals(sig.bytes.length, 64)
    prepareAndVerify(key, SignAlgorithm.HmacSha512, data, sig)

  // ---------------------------------------------------------------------------
  // ECDSA P-256 SHA-256 tests (RFC 7515 A.3)
  // ---------------------------------------------------------------------------

  test("ECDSA P-256 SHA-256 verification of RFC 7515 A.3 known answer"):
    val pubKey = CryptoKey.ecPublic(EcCurve.P256, RfcVectors.ecP256X, RfcVectors.ecP256Y).toOption.get
    val sig = Signature.ecdsaConcat(RfcVectors.ecdsaP256ExpectedSignature, EcCurve.P256).toOption.get
    prepareAndVerify(pubKey, SignAlgorithm.EcdsaP256Sha256, RfcVectors.ecdsaP256SigningInput, sig)

  test("ECDSA P-256 SHA-256 sign-verify round-trip"):
    val privKey = CryptoKey.ecPrivate(EcCurve.P256, RfcVectors.ecP256X, RfcVectors.ecP256Y, RfcVectors.ecP256D).toOption.get
    val pubKey = CryptoKey.ecPublic(EcCurve.P256, RfcVectors.ecP256X, RfcVectors.ecP256Y).toOption.get
    val data = "ECDSA round-trip test payload".getBytes("UTF-8")
    val sig = prepareAndSign(privKey, SignAlgorithm.EcdsaP256Sha256, data)
    assertEquals(sig.bytes.length, 64) // R||S = 32 + 32
    prepareAndVerify(pubKey, SignAlgorithm.EcdsaP256Sha256, data, sig)

  test("ECDSA P-256 SHA-256 verification rejects wrong signature"):
    val pubKey = CryptoKey.ecPublic(EcCurve.P256, RfcVectors.ecP256X, RfcVectors.ecP256Y).toOption.get
    val data = "ECDSA rejection test payload".getBytes("UTF-8")
    val badSig = new Array[Byte](64) // all zeros - trivially invalid
    badSig(0) = 1
    badSig(32) = 1
    intercept[Throwable]:
      prepareAndVerify(pubKey, SignAlgorithm.EcdsaP256Sha256, data, Signature.ecdsaConcat(badSig, EcCurve.P256).toOption.get)

  // ---------------------------------------------------------------------------
  // RSA PKCS#1 v1.5 SHA-256 tests (RFC 7515 A.2)
  // ---------------------------------------------------------------------------

  test("RSA PKCS#1 v1.5 SHA-256 verification of RFC 7515 A.2 known answer"):
    val pubKey = CryptoKey.rsaPublic(RfcVectors.rsaModulus, RfcVectors.rsaExponent).toOption.get
    prepareAndVerify(
      pubKey,
      SignAlgorithm.RsaPkcs1Sha256,
      RfcVectors.rsaSha256SigningInput,
      Signature.raw(RfcVectors.rsaSha256ExpectedSignature)
    )

  test("RSA PKCS#1 v1.5 SHA-256 produces RFC 7515 A.2 deterministic signature"):
    val privKey = CryptoKey
      .rsaPrivate(
        RfcVectors.rsaModulus,
        RfcVectors.rsaExponent,
        RfcVectors.rsaD,
        RfcVectors.rsaP,
        RfcVectors.rsaQ,
        RfcVectors.rsaDp,
        RfcVectors.rsaDq,
        RfcVectors.rsaQi
      )
      .toOption
      .get
    val sig = prepareAndSign(privKey, SignAlgorithm.RsaPkcs1Sha256, RfcVectors.rsaSha256SigningInput)
    assertEquals(sig.bytes.toList, RfcVectors.rsaSha256ExpectedSignature.toList)

  // ---------------------------------------------------------------------------
  // Key-algorithm mismatch tests
  // ---------------------------------------------------------------------------

  test("preparing symmetric key with RSA algorithm fails"):
    val key = CryptoKey.symmetric(new Array[Byte](32)).toOption.get
    val err = prepareSigningError(key, SignAlgorithm.RsaPkcs1Sha256)
    assert(err.isDefined, "Expected error for key-algorithm mismatch")

  // ---------------------------------------------------------------------------
  // Digest tests
  // ---------------------------------------------------------------------------

  test("SHA-1 digest of empty input matches NIST vector"):
    val digest = computeDigest(RfcVectors.emptyInput, DigestAlgorithm.Sha1)
    assertEquals(digest.bytes.toList, RfcVectors.sha1EmptyDigest.toList)

  test("SHA-256 digest of empty input matches NIST vector"):
    val digest = computeDigest(RfcVectors.emptyInput, DigestAlgorithm.Sha256)
    assertEquals(digest.bytes.toList, RfcVectors.sha256EmptyDigest.toList)

  test("SHA-384 digest of empty input matches NIST vector"):
    val digest = computeDigest(RfcVectors.emptyInput, DigestAlgorithm.Sha384)
    assertEquals(digest.bytes.toList, RfcVectors.sha384EmptyDigest.toList)

  test("SHA-512 digest of empty input matches NIST vector"):
    val digest = computeDigest(RfcVectors.emptyInput, DigestAlgorithm.Sha512)
    assertEquals(digest.bytes.toList, RfcVectors.sha512EmptyDigest.toList)

  test("SHA-256 digest output has correct length"):
    val digest = computeDigest("hello".getBytes("UTF-8"), DigestAlgorithm.Sha256)
    assertEquals(digest.length, 32)

  test("SHA-512 digest output has correct length"):
    val digest = computeDigest("hello".getBytes("UTF-8"), DigestAlgorithm.Sha512)
    assertEquals(digest.length, 64)

end CryptoTestSuite
