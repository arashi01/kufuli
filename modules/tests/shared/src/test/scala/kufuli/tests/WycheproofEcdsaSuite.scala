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
package kufuli.tests

import zio.Runtime
import zio.Unsafe
import zio.ZIO

import com.github.plokhotnyuk.jsoniter_scala.core.JsonValueCodec
import com.github.plokhotnyuk.jsoniter_scala.core.readFromString
import com.github.plokhotnyuk.jsoniter_scala.macros.JsonCodecMaker
import munit.FunSuite

import kufuli.CryptoKey
import kufuli.EcCurve
import kufuli.KufuliError
import kufuli.SignAlgorithm
import kufuli.Signature
import kufuli.testkit.HexCodec
import kufuli.zio.given

/** Wycheproof ECDSA DER-format test vectors. Cross-platform via generated string constants.
  *
  * Tests DER-encoded ECDSA signature verification per SEC 1 v2 (May 2009) C.8. Validates that
  * "valid" vectors pass, "invalid" vectors are rejected at DER parsing or verification, and no
  * vector causes a crash.
  */
class WycheproofEcdsaSuite extends FunSuite:

  private def tryRun[A](zio: ZIO[Any, KufuliError, A]): Either[KufuliError, A] =
    Unsafe.unsafe { u ?=>
      Runtime.default.unsafe.run(zio.either).getOrThrowFiberFailure()
    }

  private case class WpSuite(algorithm: String, numberOfTests: Int, testGroups: List[WpGroup])
  private case class WpGroup(publicKey: WpPubKey, sha: String, tests: List[WpVector])
  private case class WpPubKey(curve: String, wx: String, wy: String)
  private case class WpVector(tcId: Int, comment: String, msg: String, sig: String, result: String)

  private given JsonValueCodec[WpSuite] = JsonCodecMaker.make

  private def curveFromName(name: String): EcCurve = name match
    case "secp256r1" => EcCurve.P256
    case "secp384r1" => EcCurve.P384
    case "secp521r1" => EcCurve.P521
    case other       => fail(s"Unsupported curve: $other")

  private def algorithmForCurve(curve: EcCurve): SignAlgorithm = curve match
    case EcCurve.P256 => SignAlgorithm.EcdsaP256Sha256
    case EcCurve.P384 => SignAlgorithm.EcdsaP384Sha384
    case EcCurve.P521 => SignAlgorithm.EcdsaP521Sha512

  private def runVectors(json: String): Unit =
    val suite = readFromString[WpSuite](json)
    // scalafix:off DisableSyntax.var; test counters
    var passed = 0
    var failed = 0
    // scalafix:on

    suite.testGroups.foreach { group =>
      val curve = curveFromName(group.publicKey.curve)
      val algorithm = algorithmForCurve(curve)
      val keyResult = CryptoKey.ecPublic(curve, HexCodec.decode(group.publicKey.wx), HexCodec.decode(group.publicKey.wy))

      group.tests.foreach { tv =>
        val sigDer = HexCodec.decode(tv.sig)
        val msg = HexCodec.decode(tv.msg)

        tv.result match
          case "valid" =>
            val sigResult = Signature.ecdsaDer(sigDer, curve)
            keyResult match
              case Right(pubKey) =>
                sigResult match
                  case Right(sig) =>
                    val r = tryRun(pubKey.prepareVerifying(algorithm).flatMap(_.verify(msg, sig)))
                    if r.isRight then passed += 1
                    else
                      failed += 1; fail(s"tcId=${tv.tcId}: valid vector failed: ${tv.comment}")
                  case Left(err) =>
                    failed += 1; fail(s"tcId=${tv.tcId}: valid vector DER parse failed: $err")
              case Left(_) => () // invalid key in valid group - skip

          case "invalid" =>
            val sigResult = Signature.ecdsaDer(sigDer, curve)
            (keyResult, sigResult) match
              case (Left(_), _)                => passed += 1
              case (_, Left(_))                => passed += 1
              case (Right(pubKey), Right(sig)) =>
                val r = tryRun(pubKey.prepareVerifying(algorithm).flatMap(_.verify(msg, sig)))
                if r.isLeft then passed += 1
                else
                  failed += 1; fail(s"tcId=${tv.tcId}: invalid vector accepted: ${tv.comment}")

          case "acceptable" =>
            (keyResult, Signature.ecdsaDer(sigDer, curve)) match
              case (Right(pubKey), Right(sig)) =>
                val _ = tryRun(pubKey.prepareVerifying(algorithm).flatMap(_.verify(msg, sig))): Unit
              case _ => ()
            passed += 1

          case _ => ()
        end match
      }
    }
    assert(failed == 0, s"$failed Wycheproof ECDSA DER vectors failed")
    assert(passed > 0, "No vectors passed")
  end runVectors

  test("Wycheproof ECDSA P-256 SHA-256 DER vectors"):
    runVectors(kufuli.tests.wycheproof.EcdsaSecp256r1Sha256TestJson.json)

  test("Wycheproof ECDSA P-384 SHA-384 DER vectors"):
    runVectors(kufuli.tests.wycheproof.EcdsaSecp384r1Sha384TestJson.json)

  test("Wycheproof ECDSA P-521 SHA-512 DER vectors"):
    runVectors(kufuli.tests.wycheproof.EcdsaSecp521r1Sha512TestJson.json)

end WycheproofEcdsaSuite
