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

/** Wycheproof ECDSA P1363 (R||S format) test vectors (google/wycheproof testvectors_v1).
  *
  * Tests the [[kufuli.Signature$.ecdsaConcat]] construction path directly, exercising R||S
  * validation without DER transcoding.
  */
class WycheproofEcdsaP1363Suite extends FunSuite:

  private def tryRun[A](zio: ZIO[Any, KufuliError, A]): Either[KufuliError, A] =
    Unsafe.unsafe { u ?=>
      Runtime.default.unsafe.run(zio.either).getOrThrowFiberFailure()
    }

  private case class WycheproofSuite(
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

  private def hexToBytes(hex: String): Array[Byte] =
    if hex.isEmpty then Array.empty[Byte]
    else
      val padded = if hex.length % 2 != 0 then "0" + hex else hex
      padded
        .grouped(2)
        .map(pair => ((Character.digit(pair.charAt(0), 16) << 4) + Character.digit(pair.charAt(1), 16)).toByte)
        .toArray

  private def curveFromName(name: String): EcCurve = name match
    case "secp256r1" => EcCurve.P256
    case "secp384r1" => EcCurve.P384
    case "secp521r1" => EcCurve.P521
    case other       => fail(s"Unsupported curve: $other")

  private def algorithmForCurve(curve: EcCurve): SignAlgorithm = curve match
    case EcCurve.P256 => SignAlgorithm.EcdsaP256Sha256
    case EcCurve.P384 => SignAlgorithm.EcdsaP384Sha384
    case EcCurve.P521 => SignAlgorithm.EcdsaP521Sha512

  test("Wycheproof ECDSA P-256 SHA-256 P1363 (R||S) vectors"):
    // scalafix:off DisableSyntax.null; Java interop: getResourceAsStream returns null on missing resource
    val stream = getClass.getResourceAsStream("/wycheproof/ecdsa_secp256r1_sha256_p1363_test.json")
    assert(stream != null, "Resource not found: /wycheproof/ecdsa_secp256r1_sha256_p1363_test.json")
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
      val keyResult = CryptoKey.ecPublic(curve, wx, wy)

      group.tests.foreach { tv =>
        val sigBytes = hexToBytes(tv.sig)
        val msg = hexToBytes(tv.msg)

        tv.result match
          case "valid" =>
            // P1363 signatures are already R||S - use ecdsaConcat
            val sigResult = Signature.ecdsaConcat(sigBytes, curve)
            keyResult match
              case Right(pubKey) =>
                sigResult match
                  case Right(sig) =>
                    val verifyResult = tryRun(pubKey.prepareVerifying(algorithm).flatMap(_.verify(msg, sig)))
                    if verifyResult.isRight then passed += 1
                    else
                      failed += 1
                      fail(s"tcId=${tv.tcId}: valid P1363 vector failed verification: ${tv.comment}")
                  case Left(err) =>
                    failed += 1
                    fail(s"tcId=${tv.tcId}: valid P1363 vector failed R||S validation: $err")
              case Left(_) => ()
            end match

          case "invalid" =>
            val sigResult = Signature.ecdsaConcat(sigBytes, curve)
            (keyResult, sigResult) match
              case (Left(_), _)                => passed += 1
              case (_, Left(_))                => passed += 1
              case (Right(pubKey), Right(sig)) =>
                val verifyResult = tryRun(pubKey.prepareVerifying(algorithm).flatMap(_.verify(msg, sig)))
                if verifyResult.isLeft then passed += 1
                else
                  failed += 1
                  fail(s"tcId=${tv.tcId}: invalid P1363 vector accepted: ${tv.comment}")

          case "acceptable" =>
            val sigResult = Signature.ecdsaConcat(sigBytes, curve)
            (keyResult, sigResult) match
              case (Right(pubKey), Right(sig)) =>
                val _ = tryRun(pubKey.prepareVerifying(algorithm).flatMap(_.verify(msg, sig))): Unit
              case _ => ()
            passed += 1

          case _ => ()
        end match
      }
    }

    assert(failed == 0, s"$failed Wycheproof P1363 vectors failed")
    assert(passed > 0, "No vectors passed for P1363")

end WycheproofEcdsaP1363Suite
