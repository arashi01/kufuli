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

import zio.Runtime
import zio.Unsafe
import zio.ZIO

import com.github.plokhotnyuk.jsoniter_scala.core.JsonValueCodec
import com.github.plokhotnyuk.jsoniter_scala.core.readFromStream
import com.github.plokhotnyuk.jsoniter_scala.macros.JsonCodecMaker
import munit.FunSuite

import kufuli.CryptoKey
import kufuli.KufuliError
import kufuli.SignAlgorithm
import kufuli.Signature
import kufuli.zio.given

/** Wycheproof RSA test vectors (google/wycheproof testvectors_v1).
  *
  * Tests RSA PKCS#1 v1.5 (RFC 8017 (November 2016)) and RSA-PSS (RFC 8017) signature verification
  * vectors.
  */
class WycheproofRsaSuite extends FunSuite:

  private def tryRun[A](zio: ZIO[Any, KufuliError, A]): Either[KufuliError, A] =
    Unsafe.unsafe { u ?=>
      Runtime.default.unsafe.run(zio.either).getOrThrowFiberFailure()
    }

  // -- JSON model for Wycheproof RSA vectors --

  private case class WycheproofSuite(
    numberOfTests: Int,
    testGroups: List[TestGroup]
  )

  private case class TestGroup(
    sha: String,
    publicKey: PublicKeyInfo,
    tests: List[TestVector]
  )

  private case class PublicKeyInfo(
    modulus: String,
    publicExponent: String
  )

  private case class TestVector(
    tcId: Int,
    comment: String,
    msg: String,
    sig: String,
    result: String
  )

  private given JsonValueCodec[WycheproofSuite] = JsonCodecMaker.make
  private given JsonValueCodec[TestGroup] = JsonCodecMaker.make
  private given JsonValueCodec[PublicKeyInfo] = JsonCodecMaker.make
  private given JsonValueCodec[TestVector] = JsonCodecMaker.make

  private def hexToBytes(hex: String): Array[Byte] =
    if hex.isEmpty then Array.empty[Byte]
    else
      val padded = if hex.length % 2 != 0 then "0" + hex else hex
      padded
        .grouped(2)
        .map(pair => ((Character.digit(pair.charAt(0), 16) << 4) + Character.digit(pair.charAt(1), 16)).toByte)
        .toArray

  // Strip leading zero byte from hex-decoded unsigned integers
  private def stripLeadingZero(bytes: Array[Byte]): Array[Byte] =
    bytes.dropWhile(_ == 0) match
      case a if a.isEmpty => Array(0.toByte)
      case a              => a

  private def loadAndTest(resourcePath: String, algorithm: SignAlgorithm): Unit =
    // scalafix:off DisableSyntax.null; Java interop: getResourceAsStream returns null on missing resource
    val stream = getClass.getResourceAsStream(resourcePath)
    assert(stream != null, s"Resource not found: $resourcePath")
    // scalafix:on
    val suite = readFromStream[WycheproofSuite](stream)
    stream.close()

    // scalafix:off DisableSyntax.var; test counter
    var passed = 0
    var failed = 0
    // scalafix:on

    suite.testGroups.foreach { group =>
      val modulus = stripLeadingZero(hexToBytes(group.publicKey.modulus))
      val exponent = stripLeadingZero(hexToBytes(group.publicKey.publicExponent))
      val keyResult = CryptoKey.rsaPublic(modulus, exponent)

      group.tests.foreach { tv =>
        val sigBytes = hexToBytes(tv.sig)
        val msg = hexToBytes(tv.msg)

        tv.result match
          case "valid" =>
            keyResult match
              case Right(pubKey) =>
                val verifyResult = tryRun(
                  pubKey.prepareVerifying(algorithm).flatMap(_.verify(msg, Signature.raw(sigBytes)))
                )
                if verifyResult.isRight then passed += 1
                else
                  failed += 1
                  fail(s"tcId=${tv.tcId}: valid vector failed verification: ${tv.comment}")
              case Left(_) =>
                failed += 1
                fail(s"tcId=${tv.tcId}: valid vector failed key construction")

          case "invalid" =>
            keyResult match
              case Left(_)       => passed += 1
              case Right(pubKey) =>
                val verifyResult = tryRun(
                  pubKey.prepareVerifying(algorithm).flatMap(_.verify(msg, Signature.raw(sigBytes)))
                )
                if verifyResult.isLeft then passed += 1
                else
                  failed += 1
                  fail(s"tcId=${tv.tcId}: invalid vector accepted: ${tv.comment}")

          case "acceptable" =>
            keyResult match
              case Right(pubKey) =>
                val _ = tryRun(
                  pubKey.prepareVerifying(algorithm).flatMap(_.verify(msg, Signature.raw(sigBytes)))
                ): Unit
              case _ => ()
            passed += 1

          case _ => ()
        end match
      }
    }

    assert(failed == 0, s"$failed Wycheproof vectors failed")
    assert(passed > 0, s"No vectors passed for $resourcePath")
  end loadAndTest

  test("Wycheproof RSA PKCS#1 v1.5 SHA-256 vectors"):
    loadAndTest("/wycheproof/rsa_signature_2048_sha256_test.json", SignAlgorithm.RsaPkcs1Sha256)

  test("Wycheproof RSA-PSS SHA-256 (salt=32) vectors"):
    loadAndTest("/wycheproof/rsa_pss_2048_sha256_mgf1_32_test.json", SignAlgorithm.RsaPssSha256)

  test("Wycheproof RSA-PSS SHA-384 (salt=48) vectors"):
    loadAndTest("/wycheproof/rsa_pss_2048_sha384_mgf1_48_test.json", SignAlgorithm.RsaPssSha384)

end WycheproofRsaSuite
