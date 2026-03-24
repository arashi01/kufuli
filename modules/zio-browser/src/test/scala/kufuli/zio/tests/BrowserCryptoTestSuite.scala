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
package kufuli.zio.tests

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

import zio.Runtime
import zio.Unsafe
import zio.ZIO

import kufuli.CryptoKey
import kufuli.DigestAlgorithm
import kufuli.KufuliError
import kufuli.SignAlgorithm
import kufuli.testkit.RfcVectors
import kufuli.zio.given

class BrowserCryptoTestSuite extends munit.FunSuite:

  private def run[A](zio: ZIO[Any, KufuliError, A]): Future[A] =
    Unsafe.unsafe { u ?=>
      Runtime.default.unsafe.runToFuture(zio)
    }

  // ---------------------------------------------------------------------------
  // HMAC tests
  // ---------------------------------------------------------------------------

  test("HMAC-SHA256 produces RFC 7515 A.1 expected signature"):
    val key = CryptoKey.symmetric(RfcVectors.hmacSha256Key).toOption.get
    run(key.prepareSigning(SignAlgorithm.HmacSha256).flatMap(_.sign(RfcVectors.hmacSha256SigningInput))).map { sig =>
      assertEquals(sig.toList, RfcVectors.hmacSha256ExpectedSignature.toList)
    }

  test("HMAC-SHA256 signature verifies against RFC 7515 A.1 vector"):
    val key = CryptoKey.symmetric(RfcVectors.hmacSha256Key).toOption.get
    run(
      key
        .prepareVerifying(SignAlgorithm.HmacSha256)
        .flatMap(_.verify(RfcVectors.hmacSha256SigningInput, RfcVectors.hmacSha256ExpectedSignature))
    )

  test("HMAC-SHA256 sign-verify round-trip"):
    val key = CryptoKey.symmetric(RfcVectors.hmacSha256Key).toOption.get
    val data = "test payload".getBytes("UTF-8")
    run:
      for
        signKey <- key.prepareSigning(SignAlgorithm.HmacSha256)
        sig <- signKey.sign(data)
        verifyKey <- key.prepareVerifying(SignAlgorithm.HmacSha256)
        _ <- verifyKey.verify(data, sig)
      yield ()

  test("HMAC-SHA256 verification rejects wrong signature"):
    val key = CryptoKey.symmetric(RfcVectors.hmacSha256Key).toOption.get
    val data = "test payload".getBytes("UTF-8")
    val badSig = new Array[Byte](32)
    badSig(0) = 1
    run(key.prepareVerifying(SignAlgorithm.HmacSha256).flatMap(_.verify(data, badSig))).failed
      .map(e => assert(e.getMessage.contains("mismatch") || e.getMessage.contains("verification")))

  test("HMAC-SHA384 sign-verify round-trip"):
    val keyBytes = new Array[Byte](48)
    keyBytes(0) = 42
    val key = CryptoKey.symmetric(keyBytes).toOption.get
    val data = "test payload".getBytes("UTF-8")
    run:
      for
        signKey <- key.prepareSigning(SignAlgorithm.HmacSha384)
        sig <- signKey.sign(data)
        _ = assertEquals(sig.length, 48)
        verifyKey <- key.prepareVerifying(SignAlgorithm.HmacSha384)
        _ <- verifyKey.verify(data, sig)
      yield ()

  test("HMAC-SHA512 sign-verify round-trip"):
    val keyBytes = new Array[Byte](64)
    keyBytes(0) = 42
    val key = CryptoKey.symmetric(keyBytes).toOption.get
    val data = "test payload".getBytes("UTF-8")
    run:
      for
        signKey <- key.prepareSigning(SignAlgorithm.HmacSha512)
        sig <- signKey.sign(data)
        _ = assertEquals(sig.length, 64)
        verifyKey <- key.prepareVerifying(SignAlgorithm.HmacSha512)
        _ <- verifyKey.verify(data, sig)
      yield ()

  // ---------------------------------------------------------------------------
  // Key-algorithm mismatch tests
  // ---------------------------------------------------------------------------

  test("preparing symmetric key with RSA algorithm fails"):
    val key = CryptoKey.symmetric(new Array[Byte](32)).toOption.get
    run(key.prepareSigning(SignAlgorithm.RsaPkcs1Sha256)).failed
      .map(_ => ())

  // ---------------------------------------------------------------------------
  // Digest tests
  // ---------------------------------------------------------------------------

  test("SHA-256 digest of empty input matches NIST vector"):
    run(RfcVectors.emptyInput.digest(DigestAlgorithm.Sha256)).map { digest =>
      assertEquals(digest.toList, RfcVectors.sha256EmptyDigest.toList)
    }

  test("SHA-384 digest of empty input matches NIST vector"):
    run(RfcVectors.emptyInput.digest(DigestAlgorithm.Sha384)).map { digest =>
      assertEquals(digest.toList, RfcVectors.sha384EmptyDigest.toList)
    }

  test("SHA-512 digest of empty input matches NIST vector"):
    run(RfcVectors.emptyInput.digest(DigestAlgorithm.Sha512)).map { digest =>
      assertEquals(digest.toList, RfcVectors.sha512EmptyDigest.toList)
    }

  test("SHA-256 digest output has correct length"):
    run("hello".getBytes("UTF-8").digest(DigestAlgorithm.Sha256)).map { digest =>
      assertEquals(digest.length, 32)
    }

  test("SHA-512 digest output has correct length"):
    run("hello".getBytes("UTF-8").digest(DigestAlgorithm.Sha512)).map { digest =>
      assertEquals(digest.length, 64)
    }

end BrowserCryptoTestSuite
