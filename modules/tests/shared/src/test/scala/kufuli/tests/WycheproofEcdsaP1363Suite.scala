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

/** Wycheproof ECDSA P1363 (R||S) format test vectors. Exercises [[kufuli.Signature$.ecdsaConcat]]
  * R||S validation per NIST FIPS 186-5 (February 2023) without the DER transcoding path.
  */
class WycheproofEcdsaP1363Suite extends AsyncCryptoSuite:

  private case class WpSuite(numberOfTests: Int, testGroups: List[WpGroup])
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
      assert(failures.isEmpty, s"${failures.size} Wycheproof P1363 vectors failed:\n${failures.mkString("\n")}")
      assert(results.nonEmpty, "No vectors processed")
    }
  end runVectors

  private def checkVector(
    algorithm: SignAlgorithm,
    curve: EcCurve,
    keyResult: Either[kufuli.KufuliError, CryptoKey],
    tv: WpVector,
    msg: Array[Byte],
    sigBytes: Array[Byte]
  ): ZIO[Any, Nothing, Option[String]] =
    tv.result match
      case "valid" =>
        (keyResult, Signature.ecdsaConcat(sigBytes, curve)) match
          case (Right(pubKey), Right(sig)) =>
            pubKey
              .prepareVerifying(algorithm)
              .flatMap(_.verify(msg, sig))
              .as(Option.empty[String])
              .catchAll(e => ZIO.succeed(Some(s"tcId=${tv.tcId}: valid P1363 vector failed: ${tv.comment} (${e.getMessage})")))
          case (Left(err), _) =>
            ZIO.succeed(Some(s"tcId=${tv.tcId}: valid P1363 vector key construction failed: ${err.getMessage}"))
          case (_, Left(rsErr)) =>
            ZIO.succeed(Some(s"tcId=${tv.tcId}: valid P1363 R||S validation failed: ${rsErr.getMessage}"))

      case "invalid" =>
        (keyResult, Signature.ecdsaConcat(sigBytes, curve)) match
          case (Left(_), _)                => ZIO.succeed(None)
          case (_, Left(_))                => ZIO.succeed(None)
          case (Right(pubKey), Right(sig)) =>
            pubKey
              .prepareVerifying(algorithm)
              .flatMap(_.verify(msg, sig))
              .as(Some(s"tcId=${tv.tcId}: invalid P1363 vector accepted: ${tv.comment}"))
              .catchAll(_ => ZIO.succeed(None))

      case "acceptable" =>
        (keyResult, Signature.ecdsaConcat(sigBytes, curve)) match
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

  test("Wycheproof ECDSA P-256 SHA-256 P1363 vectors"):
    runVectors(kufuli.tests.wycheproof.EcdsaSecp256r1Sha256P1363TestJson.json)

  test("Wycheproof ECDSA P-384 SHA-384 P1363 vectors"):
    runVectors(kufuli.tests.wycheproof.EcdsaSecp384r1Sha384P1363TestJson.json)

  test("Wycheproof ECDSA P-521 SHA-512 P1363 vectors"):
    runVectors(kufuli.tests.wycheproof.EcdsaSecp521r1Sha512P1363TestJson.json)

end WycheproofEcdsaP1363Suite
