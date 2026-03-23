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
import kufuli.DigestAlgorithm
import kufuli.KufuliError
import kufuli.SignAlgorithm

/** Abstract test suite for verifying cryptographic backend implementations. Platform-specific test
  * modules extend this suite and implement the abstract methods using their effect runtime and
  * platform `given` instances.
  *
  * @see [[RfcVectors$ RfcVectors]] for the test vector data used by these tests
  */
abstract class CryptoTestSuite extends FunSuite:

  /** Sign data with the given key and algorithm. Implementations should prepare the key for signing
    * and then sign the data, returning the raw signature bytes.
    */
  def prepareAndSign(key: CryptoKey, algorithm: SignAlgorithm, data: Array[Byte]): Array[Byte]

  /** Verify a signature against data with the given key and algorithm. Implementations should
    * prepare the key for verifying and then verify, throwing on failure.
    */
  def prepareAndVerify(key: CryptoKey, algorithm: SignAlgorithm, data: Array[Byte], signature: Array[Byte]): Unit

  /** Compute a digest of the given data using the specified algorithm. */
  def computeDigest(data: Array[Byte], algorithm: DigestAlgorithm): Array[Byte]

  /** Attempt to prepare a key for signing, returning the error if it fails. */
  def prepareSigningError(key: CryptoKey, algorithm: SignAlgorithm): Option[KufuliError]

  // ---------------------------------------------------------------------------
  // HMAC tests
  // ---------------------------------------------------------------------------

  test("HMAC-SHA256 produces RFC 7515 A.1 expected signature"):
    val key = CryptoKey.symmetric(RfcVectors.hmacSha256Key).toOption.get
    val sig = prepareAndSign(key, SignAlgorithm.HmacSha256, RfcVectors.hmacSha256SigningInput)
    assertEquals(sig.toList, RfcVectors.hmacSha256ExpectedSignature.toList)

  test("HMAC-SHA256 signature verifies against RFC 7515 A.1 vector"):
    val key = CryptoKey.symmetric(RfcVectors.hmacSha256Key).toOption.get
    prepareAndVerify(key, SignAlgorithm.HmacSha256, RfcVectors.hmacSha256SigningInput, RfcVectors.hmacSha256ExpectedSignature)

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
      prepareAndVerify(key, SignAlgorithm.HmacSha256, data, badSig)

  test("HMAC-SHA384 sign-verify round-trip"):
    val keyBytes = new Array[Byte](48)
    keyBytes(0) = 42
    val key = CryptoKey.symmetric(keyBytes).toOption.get
    val data = "test payload".getBytes("UTF-8")
    val sig = prepareAndSign(key, SignAlgorithm.HmacSha384, data)
    assertEquals(sig.length, 48)
    prepareAndVerify(key, SignAlgorithm.HmacSha384, data, sig)

  test("HMAC-SHA512 sign-verify round-trip"):
    val keyBytes = new Array[Byte](64)
    keyBytes(0) = 42
    val key = CryptoKey.symmetric(keyBytes).toOption.get
    val data = "test payload".getBytes("UTF-8")
    val sig = prepareAndSign(key, SignAlgorithm.HmacSha512, data)
    assertEquals(sig.length, 64)
    prepareAndVerify(key, SignAlgorithm.HmacSha512, data, sig)

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

  test("SHA-256 digest of empty input matches NIST vector"):
    val digest = computeDigest(RfcVectors.emptyInput, DigestAlgorithm.Sha256)
    assertEquals(digest.toList, RfcVectors.sha256EmptyDigest.toList)

  test("SHA-384 digest of empty input matches NIST vector"):
    val digest = computeDigest(RfcVectors.emptyInput, DigestAlgorithm.Sha384)
    assertEquals(digest.toList, RfcVectors.sha384EmptyDigest.toList)

  test("SHA-512 digest of empty input matches NIST vector"):
    val digest = computeDigest(RfcVectors.emptyInput, DigestAlgorithm.Sha512)
    assertEquals(digest.toList, RfcVectors.sha512EmptyDigest.toList)

  test("SHA-256 digest output has correct length"):
    val digest = computeDigest("hello".getBytes("UTF-8"), DigestAlgorithm.Sha256)
    assertEquals(digest.length, 32)

  test("SHA-512 digest output has correct length"):
    val digest = computeDigest("hello".getBytes("UTF-8"), DigestAlgorithm.Sha512)
    assertEquals(digest.length, 64)

end CryptoTestSuite
