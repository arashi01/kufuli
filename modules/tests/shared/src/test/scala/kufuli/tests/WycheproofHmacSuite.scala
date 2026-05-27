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
import kufuli.testkit.HexCodec
import kufuli.zio.given

/** Wycheproof HMAC-SHA test vectors per RFC 2104 (February 1997). Sign each vector and compare the
  * resulting tag to the expected output; vectors marked invalid must yield a different tag.
  */
class WycheproofHmacSuite extends AsyncCryptoSuite:

  private case class WpSuite(numberOfTests: Int, testGroups: List[WpGroup])
  private case class WpGroup(keySize: Int, tagSize: Int, tests: List[WpVector])
  private case class WpVector(tcId: Int, comment: String, key: String, msg: String, tag: String, result: String)

  private given JsonValueCodec[WpSuite] = JsonCodecMaker.make

  private def runVectors(json: String, algorithm: SignAlgorithm, expectedTagBytes: Int) =
    val suite = readFromString[WpSuite](json)

    val checks: List[ZIO[Any, Nothing, Option[String]]] =
      suite.testGroups.filter(_.tagSize == expectedTagBytes * 8).flatMap { group =>
        group.tests.flatMap { tv =>
          val keyBytes = HexCodec.decode(tv.key)
          // RFC 7518 (May 2015) ss3.2: HMAC key must be at least hash output length
          if keyBytes.length < expectedTagBytes then None
          else
            Some(
              CryptoKey.symmetric(keyBytes) match
                case Right(key) =>
                  val msg = HexCodec.decode(tv.msg)
                  val expectedTag = HexCodec.decode(tv.tag)
                  key
                    .prepareSigning(algorithm)
                    .flatMap(_.sign(msg))
                    .map { sig =>
                      val matches = sig.bytes.toSeq == expectedTag.toSeq
                      tv.result match
                        case "valid"   => if matches then None else Some(s"tcId=${tv.tcId}: HMAC output mismatch")
                        case "invalid" => if !matches then None else Some(s"tcId=${tv.tcId}: invalid tag matched computed HMAC")
                        case _         => None
                    }
                    .catchAll(_ => ZIO.succeed(if tv.result == "invalid" then None else Some(s"tcId=${tv.tcId}: sign failed")))
                case Left(_) => ZIO.succeed(None)
            )
          end if
        }
      }

    runIo(ZIO.foreach(checks)(identity)).map { results =>
      val failures = results.flatten
      assert(failures.isEmpty, s"${failures.size} Wycheproof HMAC vectors failed:\n${failures.mkString("\n")}")
      assert(results.nonEmpty, "No vectors processed")
    }
  end runVectors

  test("Wycheproof HMAC-SHA-256 vectors"):
    runVectors(kufuli.tests.wycheproof.HmacSha256TestJson.json, SignAlgorithm.HmacSha256, 32)

  test("Wycheproof HMAC-SHA-384 vectors"):
    runVectors(kufuli.tests.wycheproof.HmacSha384TestJson.json, SignAlgorithm.HmacSha384, 48)

  test("Wycheproof HMAC-SHA-512 vectors"):
    runVectors(kufuli.tests.wycheproof.HmacSha512TestJson.json, SignAlgorithm.HmacSha512, 64)

end WycheproofHmacSuite
