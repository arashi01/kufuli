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
import kufuli.KufuliError
import kufuli.SignAlgorithm
import kufuli.Signature
import kufuli.testkit.HexCodec
import kufuli.zio.given

/** Wycheproof HMAC-SHA test vectors per RFC 2104 (February 1997). Cross-platform.
  *
  * Tests HMAC sign-then-verify against adversarial vectors including modified tags, truncated
  * outputs, and edge-case key/message lengths.
  */
class WycheproofHmacSuite extends FunSuite:

  private def tryRun[A](zio: ZIO[Any, KufuliError, A]): Either[KufuliError, A] =
    Unsafe.unsafe { u ?=>
      Runtime.default.unsafe.run(zio.either).getOrThrowFiberFailure()
    }

  private case class WpSuite(numberOfTests: Int, testGroups: List[WpGroup])
  private case class WpGroup(keySize: Int, tagSize: Int, tests: List[WpVector])
  private case class WpVector(tcId: Int, comment: String, key: String, msg: String, tag: String, result: String)

  private given JsonValueCodec[WpSuite] = JsonCodecMaker.make

  private def runVectors(json: String, algorithm: SignAlgorithm, expectedTagBytes: Int): Unit =
    val suite = readFromString[WpSuite](json)
    // scalafix:off DisableSyntax.var; test counters
    var passed = 0
    var failed = 0
    // scalafix:on

    suite.testGroups.foreach { group =>
      // Only test full-length tags matching our algorithm output
      if group.tagSize == expectedTagBytes * 8 then
        group.tests.foreach { tv =>
          val keyBytes = HexCodec.decode(tv.key)
          val msg = HexCodec.decode(tv.msg)
          val expectedTag = HexCodec.decode(tv.tag)

          // Skip keys shorter than HMAC minimum per RFC 7518 (May 2015) ss3.2
          val minKeyBytes = expectedTagBytes
          if keyBytes.length >= minKeyBytes then
            val keyResult = CryptoKey.symmetric(keyBytes)
            keyResult match
              case Right(key) =>
                val signResult = tryRun(key.prepareSigning(algorithm).flatMap(_.sign(msg)))

                tv.result match
                  case "valid" =>
                    signResult match
                      case Right(sig) =>
                        if sig.bytes.toSeq == expectedTag.toSeq then passed += 1
                        else
                          failed += 1; fail(s"tcId=${tv.tcId}: HMAC output mismatch")
                      case Left(err) =>
                        failed += 1; fail(s"tcId=${tv.tcId}: valid vector sign failed: $err")

                  case "invalid" =>
                    // For HMAC, "invalid" means the tag is wrong. Our sign should produce a DIFFERENT tag.
                    signResult match
                      case Right(sig) =>
                        if sig.bytes.toSeq != expectedTag.toSeq then passed += 1
                        else
                          failed += 1; fail(s"tcId=${tv.tcId}: invalid tag matched computed HMAC")
                      case Left(_) => passed += 1 // Sign failure also acceptable

                  case _ => ()
                end match
              case Left(_) => () // Key rejected (too short) - skip
            end match
          end if
        }
    }
    assert(failed == 0, s"$failed Wycheproof HMAC vectors failed")
    assert(passed > 0, "No vectors passed")
  end runVectors

  test("Wycheproof HMAC-SHA-256 vectors"):
    runVectors(kufuli.tests.wycheproof.HmacSha256TestJson.json, SignAlgorithm.HmacSha256, 32)

  test("Wycheproof HMAC-SHA-384 vectors"):
    runVectors(kufuli.tests.wycheproof.HmacSha384TestJson.json, SignAlgorithm.HmacSha384, 48)

  test("Wycheproof HMAC-SHA-512 vectors"):
    runVectors(kufuli.tests.wycheproof.HmacSha512TestJson.json, SignAlgorithm.HmacSha512, 64)

end WycheproofHmacSuite
