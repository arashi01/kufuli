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

import zio.ZIO

import com.github.plokhotnyuk.jsoniter_scala.core.JsonValueCodec
import com.github.plokhotnyuk.jsoniter_scala.core.readFromString
import com.github.plokhotnyuk.jsoniter_scala.macros.JsonCodecMaker

import kufuli.CryptoKey
import kufuli.EcCurve
import kufuli.SignAlgorithm
import kufuli.Signature
import kufuli.testkit.HexCodec
import kufuli.zio.given

/** Wycheproof ECDSA DER-format test vectors. Verifies DER-encoded ECDSA signatures per SEC 1 v2
  * (May 2009) C.8 across the full P-256/P-384/P-521 adversarial corpus.
  */
class WycheproofEcdsaSuite extends AsyncCryptoSuite:

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

  private def runVectors(json: String) =
    val suite = readFromString[WpSuite](json)

    val checks: List[ZIO[Any, Nothing, Option[String]]] =
      suite.testGroups.flatMap { group =>
        val curve = curveFromName(group.publicKey.curve)
        val algorithm = algorithmForCurve(curve)
        val keyResult = CryptoKey.ecPublic(curve, HexCodec.decode(group.publicKey.wx), HexCodec.decode(group.publicKey.wy))
        group.tests.map { tv =>
          checkVector(algorithm, curve, keyResult, tv, HexCodec.decode(tv.msg), HexCodec.decode(tv.sig))
        }
      }

    runIo(ZIO.foreach(checks)(identity)).map { results =>
      val failures = results.flatten
      assert(failures.isEmpty, s"${failures.size} Wycheproof ECDSA DER vectors failed:\n${failures.mkString("\n")}")
      assert(results.nonEmpty, "No vectors processed")
    }
  end runVectors

  private def checkVector(
    algorithm: SignAlgorithm,
    curve: EcCurve,
    keyResult: Either[kufuli.KufuliError, CryptoKey],
    tv: WpVector,
    msg: Array[Byte],
    sigDer: Array[Byte]
  ): ZIO[Any, Nothing, Option[String]] =
    tv.result match
      case "valid" =>
        (keyResult, Signature.ecdsaDer(sigDer, curve)) match
          case (Right(pubKey), Right(sig)) =>
            pubKey
              .prepareVerifying(algorithm)
              .flatMap(_.verify(msg, sig))
              .as(Option.empty[String])
              .catchAll(e => ZIO.succeed(Some(s"tcId=${tv.tcId}: valid vector failed: ${tv.comment} (${e.getMessage})")))
          case (Left(err), _)    => ZIO.succeed(Some(s"tcId=${tv.tcId}: valid vector key construction failed: ${err.getMessage}"))
          case (_, Left(derErr)) => ZIO.succeed(Some(s"tcId=${tv.tcId}: valid vector DER parse failed: ${derErr.getMessage}"))

      case "invalid" =>
        (keyResult, Signature.ecdsaDer(sigDer, curve)) match
          case (Left(_), _)                => ZIO.succeed(None)
          case (_, Left(_))                => ZIO.succeed(None)
          case (Right(pubKey), Right(sig)) =>
            pubKey
              .prepareVerifying(algorithm)
              .flatMap(_.verify(msg, sig))
              .as(Some(s"tcId=${tv.tcId}: invalid vector accepted: ${tv.comment}"))
              .catchAll(_ => ZIO.succeed(None))

      case "acceptable" =>
        (keyResult, Signature.ecdsaDer(sigDer, curve)) match
          case (Right(pubKey), Right(sig)) =>
            pubKey
              .prepareVerifying(algorithm)
              .flatMap(_.verify(msg, sig))
              .as(Option.empty[String])
              .catchAll(_ => ZIO.succeed(None))
          case _ => ZIO.succeed(None)

      case _ => ZIO.succeed(None)
    end match
  end checkVector

  test("Wycheproof ECDSA P-256 SHA-256 DER vectors"):
    runVectors(kufuli.tests.wycheproof.EcdsaSecp256r1Sha256TestJson.json)

  test("Wycheproof ECDSA P-384 SHA-384 DER vectors"):
    runVectors(kufuli.tests.wycheproof.EcdsaSecp384r1Sha384TestJson.json)

  test("Wycheproof ECDSA P-521 SHA-512 DER vectors"):
    runVectors(kufuli.tests.wycheproof.EcdsaSecp521r1Sha512TestJson.json)

end WycheproofEcdsaSuite
