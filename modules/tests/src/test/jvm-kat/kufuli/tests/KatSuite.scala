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

import boilerplate.Slice
import boilerplate.effect.*

import kufuli.*
import kufuli.password.*
import kufuli.tests.support.*

// Argon2id is the one family whose provider is backend-specific and not yet common across the real
// backends (BouncyCastle on JVM; the Native libargon2 provider is pending), so its exact vector and
// the PHC login flow are exercised here on the JVM only. Every other real-backend behaviour moved to
// the cross-backend suites (RealVectorSuite, RealBackendSuite), which run on JVM and Native alike.
class KatSuite extends munit.CatsEffectSuite:

  private def hex(b: Array[Byte]): String = b.map(x => f"$x%02x").mkString

  test("Argon2id via BouncyCastle == OpenSSL 3.5 reference (pass=password, salt=16x02, m=512, t=3, p=1)") {
    val a = summon[Argon2]
    val params = Argon2Params.of(512, 3, 1).toOption.get
    for
      out <- a.hash(Slice.of("password".getBytes), Slice.of(Array.fill(16)(0x02.toByte)), params).absolve
      _ <- check(hex(out) == "cc9ddc55720b3a3446d2641d4c4e40418be3e2f401943b12f1ed3f243ed52170", "argon2id vector")
    yield ()
  }

  test("password: Argon2id login flow (PHC parse, verify, policy rehash)") {
    for
      stored <- "correct horse".hash(Argon2Params.interactive).absolve
      parsed = PasswordHash.of(stored.value)
      _ <- check(parsed.isRight, "PHC parses")
      good <- "correct horse".verify(parsed.toOption.get, Argon2Params.interactive).absolve
      _ <- check(good match
                   case PasswordCheck.Verified(None) => true;
                   case _                            => false
                 ,
                 "correct password, no rehash"
           )
      bad <- "wrong".verify(parsed.toOption.get, Argon2Params.interactive).absolve
      _ <- check(bad == PasswordCheck.Rejected, "wrong password rejected")
      rehash <- "correct horse".verify(parsed.toOption.get, Argon2Params.default).absolve
      _ <- check(rehash match
                   case PasswordCheck.Verified(Some(_)) => true;
                   case _                               => false
                 ,
                 "stronger policy -> rehash"
           )
    yield ()
  }
end KatSuite
