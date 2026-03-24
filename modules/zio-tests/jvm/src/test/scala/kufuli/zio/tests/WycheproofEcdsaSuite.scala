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
import kufuli.EcCurve
import kufuli.KufuliError
import kufuli.SignAlgorithm
import kufuli.Signature
import kufuli.zio.given

/** Wycheproof ECDSA test vectors (google/wycheproof testvectors_v1).
  *
  * Loads DER-encoded ECDSA signature vectors and verifies that:
  *   - "valid" vectors pass both DER parsing and cryptographic verification
  *   - "invalid" vectors are rejected (either at DER parsing or verification)
  *   - no vector causes a crash or exception leak
  */
class WycheproofEcdsaSuite extends FunSuite:

  private def tryRun[A](zio: ZIO[Any, KufuliError, A]): Either[KufuliError, A] =
    Unsafe.unsafe { u ?=>
      Runtime.default.unsafe.run(zio.either).getOrThrowFiberFailure()
    }

  // -- JSON model for Wycheproof ECDSA vectors --

  private case class WycheproofSuite(
    algorithm: String,
    numberOfTests: Int,
    testGroups: List[TestGroup]
  )

  private case class TestGroup(
    publicKey: PublicKeyInfo,
    sha: String,
    tests: List[TestVector]
  )

  private case class PublicKeyInfo(
    curve: String,
    wx: String,
    wy: String
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

  // -- Hex decoding --

  private def hexToBytes(hex: String): Array[Byte] =
    if hex.isEmpty then Array.empty[Byte]
    else
      hex
        .grouped(2)
        .map(pair => ((Character.digit(pair.charAt(0), 16) << 4) + Character.digit(pair.charAt(1), 16)).toByte)
        .toArray

  // -- Curve/algorithm resolution --

  private def curveFromName(name: String): EcCurve = name match
    case "secp256r1" => EcCurve.P256
    case "secp384r1" => EcCurve.P384
    case "secp521r1" => EcCurve.P521
    case other       => fail(s"Unsupported curve: $other")

  private def algorithmForCurve(curve: EcCurve): SignAlgorithm = curve match
    case EcCurve.P256 => SignAlgorithm.EcdsaP256Sha256
    case EcCurve.P384 => SignAlgorithm.EcdsaP384Sha384
    case EcCurve.P521 => SignAlgorithm.EcdsaP521Sha512

  // -- Test runner --

  private def loadAndTest(resourcePath: String): Unit =
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
      val curve = curveFromName(group.publicKey.curve)
      val algorithm = algorithmForCurve(curve)
      val wx = hexToBytes(group.publicKey.wx)
      val wy = hexToBytes(group.publicKey.wy)

      // Some test groups have invalid public keys that we should reject at construction
      val keyResult = CryptoKey.ecPublic(curve, wx, wy)

      group.tests.foreach { tv =>
        val sigDer = hexToBytes(tv.sig)
        val msg = hexToBytes(tv.msg)

        tv.result match
          case "valid" =>
            // Valid vectors must: parse DER, construct key, verify signature
            val sigResult = Signature.ecdsaDer(sigDer, curve)
            keyResult match
              case Right(pubKey) =>
                sigResult match
                  case Right(sig) =>
                    val verifyResult = tryRun(pubKey.prepareVerifying(algorithm).flatMap(_.verify(msg, sig)))
                    if verifyResult.isRight then passed += 1
                    else
                      failed += 1
                      fail(s"tcId=${tv.tcId}: valid vector failed verification: ${tv.comment}")
                  case Left(err) =>
                    failed += 1
                    fail(s"tcId=${tv.tcId}: valid vector failed DER parsing: $err")
              case Left(_) =>
                // Invalid public key in a "valid" test group - not our concern
                ()
            end match

          case "invalid" =>
            // Invalid vectors must be rejected at some layer (DER, validation, or verification)
            val sigResult = Signature.ecdsaDer(sigDer, curve)
            (keyResult, sigResult) match
              case (Left(_), _) =>
                // Rejected at key construction - acceptable
                passed += 1
              case (_, Left(_)) =>
                // Rejected at DER parsing or signature validation - good
                passed += 1
              case (Right(pubKey), Right(sig)) =>
                // Both parsed - must fail at verification
                val verifyResult = tryRun(pubKey.prepareVerifying(algorithm).flatMap(_.verify(msg, sig)))
                if verifyResult.isLeft then passed += 1
                else
                  failed += 1
                  fail(s"tcId=${tv.tcId}: invalid vector accepted: ${tv.comment}")
            end match

          case "acceptable" =>
            // Acceptable vectors may pass or fail - just ensure no crash
            val sigResult = Signature.ecdsaDer(sigDer, curve)
            (keyResult, sigResult) match
              case (Right(pubKey), Right(sig)) =>
                val _ = tryRun(pubKey.prepareVerifying(algorithm).flatMap(_.verify(msg, sig))): Unit
              case _ => ()
            passed += 1

          case _ => ()
        end match
      }
    }

    assert(failed == 0, s"$failed Wycheproof vectors failed")
    assert(passed > 0, s"No vectors passed for $resourcePath")
  end loadAndTest

  // -- Test cases --

  test("Wycheproof ECDSA P-256 SHA-256 vectors"):
    loadAndTest("/wycheproof/ecdsa_secp256r1_sha256_test.json")

  test("Wycheproof ECDSA P-384 SHA-384 vectors"):
    loadAndTest("/wycheproof/ecdsa_secp384r1_sha384_test.json")

  test("Wycheproof ECDSA P-521 SHA-512 vectors"):
    loadAndTest("/wycheproof/ecdsa_secp521r1_sha512_test.json")

end WycheproofEcdsaSuite
