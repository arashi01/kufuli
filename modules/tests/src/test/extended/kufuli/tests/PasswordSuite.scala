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

import cats.effect.IO

import kufuli.Supports
import kufuli.password.*
import kufuli.tests.support.check
import kufuli.tests.support.expectRight

object passwordFlows:
  def loginFlow(using Supports[Argon2id]): IO[Unit] =
    val pw = "correct horse battery staple"
    for
      hash <- expectRight("hash")(pw.hash(Argon2Params.interactive))
      storedColumn = hash.value // -> database
      parsed <- IO.fromEither(PasswordHash.of(storedColumn))
      outcome <- expectRight("verify")(pw.verify(against = parsed, policy = Argon2Params.default))
      _ <- outcome match
             case PasswordCheck.Rejected         => IO.raiseError(new AssertionError("login rejected"))
             case PasswordCheck.Verified(rehash) =>
               rehash.fold(IO.unit)(p => expectRight("rehash")(pw.hash(p)).void)
      _ <- check(PasswordHash.of("not-a-phc-string").isLeft, "malformed stored hash surfaces at parse")
    yield ()
  end loginFlow

  def valueChecks(): Unit =
    assert(PasswordHash.of("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA").isRight, "PHC parse")
    assert(PasswordHash.of("plainly-not-a-hash").isLeft, "corrupt column fails at parse, not verify")
    assert(Argon2Params.of(memoryKib = 4, iterations = 1, parallelism = 1).isLeft, "m >= 8p enforced")
    assert(Argon2Params.of(memoryKib = 65536, iterations = 3, parallelism = 4).isRight, "valid params")
end passwordFlows

class PasswordSuite extends munit.CatsEffectSuite:
  test("login: hash -> store -> parse -> verify with policy rehash")(passwordFlows.loginFlow)
  test("password value layer: PHC parse and parameter validation")(IO(passwordFlows.valueChecks()))
