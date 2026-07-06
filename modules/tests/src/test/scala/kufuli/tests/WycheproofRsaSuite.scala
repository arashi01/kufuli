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
import kufuli.SignAlgorithm
import kufuli.Signature
import kufuli.testkit.HexCodec
import kufuli.zio.given

/** Wycheproof RSA PKCS#1 v1.5 and RSA-PSS test vectors per RFC 8017 (November 2016). */
class WycheproofRsaSuite extends AsyncCryptoSuite:

  private case class WpSuite(numberOfTests: Int, testGroups: List[WpGroup])
  private case class WpGroup(sha: String, publicKey: WpPubKey, tests: List[WpVector])
  private case class WpPubKey(modulus: String, publicExponent: String)
  private case class WpVector(tcId: Int, comment: String, msg: String, sig: String, result: String)

  private given JsonValueCodec[WpSuite] = JsonCodecMaker.make

  private def runVectors(json: String, algorithm: SignAlgorithm) =
    val suite = readFromString[WpSuite](json)

    val checks: List[ZIO[Any, Nothing, Option[String]]] =
      suite.testGroups.flatMap { group =>
        val modulus = HexCodec.stripLeadingZero(HexCodec.decode(group.publicKey.modulus))
        val exponent = HexCodec.stripLeadingZero(HexCodec.decode(group.publicKey.publicExponent))
        val keyResult = CryptoKey.rsaPublic(modulus, exponent)
        group.tests.map { tv =>
          val sigBytes = HexCodec.decode(tv.sig)
          val msg = HexCodec.decode(tv.msg)
          checkVector(algorithm, keyResult, tv, msg, sigBytes)
        }
      }

    runIo(ZIO.foreach(checks)(identity)).map { results =>
      val failures = results.flatten
      assert(failures.isEmpty, s"${failures.size} Wycheproof RSA vectors failed:\n${failures.mkString("\n")}")
      assert(results.nonEmpty, "No vectors processed")
    }
  end runVectors

  private def checkVector(
    algorithm: SignAlgorithm,
    keyResult: Either[kufuli.KufuliError, CryptoKey],
    tv: WpVector,
    msg: Array[Byte],
    sigBytes: Array[Byte]
  ): ZIO[Any, Nothing, Option[String]] =
    tv.result match
      case "valid" =>
        keyResult match
          case Right(pubKey) =>
            pubKey
              .prepareVerifying(algorithm)
              .flatMap(_.verify(msg, Signature.raw(sigBytes)))
              .as(Option.empty[String])
              .catchAll(e => ZIO.succeed(Some(s"tcId=${tv.tcId}: valid vector failed: ${tv.comment} (${e.getMessage})")))
          case Left(err) =>
            ZIO.succeed(Some(s"tcId=${tv.tcId}: valid vector key construction failed: ${err.getMessage}"))

      case "invalid" =>
        keyResult match
          case Left(_)       => ZIO.succeed(None)
          case Right(pubKey) =>
            pubKey
              .prepareVerifying(algorithm)
              .flatMap(_.verify(msg, Signature.raw(sigBytes)))
              .as(Some(s"tcId=${tv.tcId}: invalid vector accepted: ${tv.comment}"))
              .catchAll(_ => ZIO.succeed(None))

      case "acceptable" =>
        keyResult match
          case Right(pubKey) =>
            pubKey
              .prepareVerifying(algorithm)
              .flatMap(_.verify(msg, Signature.raw(sigBytes)))
              .as(Option.empty[String])
              .catchAll(_ => ZIO.succeed(None))
          case Left(_) => ZIO.succeed(None)

      case _ => ZIO.succeed(None)
    end match
  end checkVector

  test("Wycheproof RSA PKCS#1 v1.5 SHA-256 vectors"):
    runVectors(kufuli.tests.wycheproof.RsaSignature2048Sha256TestJson.json, SignAlgorithm.RsaPkcs1Sha256)

  test("Wycheproof RSA PKCS#1 v1.5 SHA-384 vectors"):
    runVectors(kufuli.tests.wycheproof.RsaSignature2048Sha384TestJson.json, SignAlgorithm.RsaPkcs1Sha384)

  test("Wycheproof RSA PKCS#1 v1.5 SHA-512 vectors"):
    runVectors(kufuli.tests.wycheproof.RsaSignature2048Sha512TestJson.json, SignAlgorithm.RsaPkcs1Sha512)

  test("Wycheproof RSA-PSS SHA-256 (salt=32) vectors"):
    runVectors(kufuli.tests.wycheproof.RsaPss2048Sha256Mgf132TestJson.json, SignAlgorithm.RsaPssSha256)

  test("Wycheproof RSA-PSS SHA-384 (salt=48) vectors"):
    runVectors(kufuli.tests.wycheproof.RsaPss2048Sha384Mgf148TestJson.json, SignAlgorithm.RsaPssSha384)

  test("Wycheproof RSA-PSS SHA-512 (salt=64) vectors"):
    runVectors(kufuli.tests.wycheproof.RsaPss4096Sha512Mgf164TestJson.json, SignAlgorithm.RsaPssSha512)

end WycheproofRsaSuite
