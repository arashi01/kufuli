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
import kufuli.OkpCurve
import kufuli.SignAlgorithm
import kufuli.Signature
import kufuli.testkit.HexCodec
import kufuli.zio.given

/** Wycheproof Ed25519 test vectors per RFC 8032 (January 2017). Skipped on platforms whose Native
  * crypto backend does not expose EdDSA (Security.framework on macOS, BCrypt on Windows).
  */
class WycheproofEd25519Suite extends AsyncCryptoSuite:

  private case class WpSuite(numberOfTests: Int, testGroups: List[WpGroup])
  private case class WpGroup(publicKey: WpPubKey, tests: List[WpVector])
  private case class WpPubKey(pk: String)
  private case class WpVector(tcId: Int, comment: String, msg: String, sig: String, result: String)

  private given JsonValueCodec[WpSuite] = JsonCodecMaker.make

  test("Wycheproof Ed25519 vectors"):
    assume(PlatformAlgorithms.supports(SignAlgorithm.Ed25519), "Ed25519 not supported on this platform")

    val suite = readFromString[WpSuite](kufuli.tests.wycheproof.Ed25519TestJson.json)

    val checks: List[ZIO[Any, Nothing, Option[String]]] =
      suite.testGroups.flatMap { group =>
        val keyResult = CryptoKey.okpPublic(OkpCurve.Ed25519, HexCodec.decode(group.publicKey.pk))
        group.tests.map { tv =>
          checkVector(keyResult, tv, HexCodec.decode(tv.msg), HexCodec.decode(tv.sig))
        }
      }

    runIo(ZIO.foreach(checks)(identity)).map { results =>
      val failures = results.flatten
      assert(failures.isEmpty, s"${failures.size} Wycheproof Ed25519 vectors failed:\n${failures.mkString("\n")}")
      assert(results.nonEmpty, "No vectors processed")
    }

  private def checkVector(
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
              .prepareVerifying(SignAlgorithm.Ed25519)
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
              .prepareVerifying(SignAlgorithm.Ed25519)
              .flatMap(_.verify(msg, Signature.raw(sigBytes)))
              .as(Some(s"tcId=${tv.tcId}: invalid vector accepted: ${tv.comment}"))
              .catchAll(_ => ZIO.succeed(None))

      case "acceptable" =>
        keyResult match
          case Right(pubKey) =>
            pubKey
              .prepareVerifying(SignAlgorithm.Ed25519)
              .flatMap(_.verify(msg, Signature.raw(sigBytes)))
              .as(Option.empty[String])
              .catchAll(_ => ZIO.succeed(None))
          case _ => ZIO.succeed(None)

      case _ => ZIO.succeed(None)
    end match
  end checkVector

end WycheproofEd25519Suite
