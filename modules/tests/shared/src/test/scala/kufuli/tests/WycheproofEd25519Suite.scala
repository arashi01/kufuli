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
import kufuli.OkpCurve
import kufuli.SignAlgorithm
import kufuli.Signature
import kufuli.testkit.HexCodec
import kufuli.zio.given

/** Wycheproof Ed25519 test vectors per RFC 8032 (January 2017). Cross-platform. */
class WycheproofEd25519Suite extends FunSuite:

  private def tryRun[A](zio: ZIO[Any, KufuliError, A]): Either[KufuliError, A] =
    Unsafe.unsafe { u ?=>
      Runtime.default.unsafe.run(zio.either).getOrThrowFiberFailure()
    }

  private case class WpSuite(numberOfTests: Int, testGroups: List[WpGroup])
  private case class WpGroup(publicKey: WpPubKey, tests: List[WpVector])
  private case class WpPubKey(pk: String)
  private case class WpVector(tcId: Int, comment: String, msg: String, sig: String, result: String)

  private given JsonValueCodec[WpSuite] = JsonCodecMaker.make

  test("Wycheproof Ed25519 vectors"):
    val suite = readFromString[WpSuite](kufuli.tests.wycheproof.Ed25519TestJson.json)
    // scalafix:off DisableSyntax.var; test counters
    var passed = 0
    var failed = 0
    // scalafix:on

    suite.testGroups.foreach { group =>
      val keyResult = CryptoKey.okpPublic(OkpCurve.Ed25519, HexCodec.decode(group.publicKey.pk))

      group.tests.foreach { tv =>
        val sigBytes = HexCodec.decode(tv.sig)
        val msg = HexCodec.decode(tv.msg)

        tv.result match
          case "valid" =>
            keyResult match
              case Right(pubKey) =>
                val r = tryRun(pubKey.prepareVerifying(SignAlgorithm.Ed25519).flatMap(_.verify(msg, Signature.raw(sigBytes))))
                if r.isRight then passed += 1
                else
                  failed += 1; fail(s"tcId=${tv.tcId}: valid vector failed: ${tv.comment}")
              case Left(err) =>
                failed += 1; fail(s"tcId=${tv.tcId}: valid vector key construction failed: $err")

          case "invalid" =>
            keyResult match
              case Left(_)       => passed += 1
              case Right(pubKey) =>
                val r = tryRun(pubKey.prepareVerifying(SignAlgorithm.Ed25519).flatMap(_.verify(msg, Signature.raw(sigBytes))))
                if r.isLeft then passed += 1
                else
                  failed += 1; fail(s"tcId=${tv.tcId}: invalid vector accepted: ${tv.comment}")

          case "acceptable" =>
            keyResult match
              case Right(pubKey) =>
                val _ = tryRun(pubKey.prepareVerifying(SignAlgorithm.Ed25519).flatMap(_.verify(msg, Signature.raw(sigBytes)))): Unit
              case _ => ()
            passed += 1

          case _ => ()
        end match
      }
    }
    assert(failed == 0, s"$failed Wycheproof Ed25519 vectors failed")
    assert(passed > 0, "No vectors passed")

end WycheproofEd25519Suite
