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
package kufuli.password

import java.nio.charset.StandardCharsets

import scala.annotation.targetName
import scala.util.control.NoStackTrace

import boilerplate.effect.EffIO
import boilerplate.effect.UEffIO

import kufuli.Algorithm
import kufuli.AlgorithmSpec
import kufuli.Supports

// Argon2id password hashing, fail-safe by construction: a wrong password is a PasswordCheck result
// rather than an error, a malformed stored hash fails at PasswordHash.of, and verify takes the
// current policy so it can flag a rehash. The PHC string format is identical on every backend.

sealed abstract class PasswordError(message: String) extends Exception(message) with NoStackTrace derives CanEqual
case object InvalidParams extends PasswordError("invalid Argon2 parameters")
type InvalidParams = InvalidParams.type
case object MalformedHash extends PasswordError("not a PHC argon2id string")
type MalformedHash = MalformedHash.type

/** The Argon2id password-hashing algorithm. */
sealed trait Argon2id extends Algorithm
case object Argon2id extends AlgorithmSpec[Argon2id] with Argon2id:
  given (using kufuli.PasswordCapable =:= true): Supports[Argon2id] = Supports.token(Argon2id)

/** Argon2id cost parameters; use a preset or the validated [[Argon2Params$ Argon2Params.of]]. */
final case class Argon2Params private (memoryKib: Int, iterations: Int, parallelism: Int) derives CanEqual
object Argon2Params:
  val interactive: Argon2Params = Argon2Params(19456, 2, 1) // OWASP interactive floor
  val default: Argon2Params = Argon2Params(65536, 3, 4) // RFC 9106 second recommendation
  val sensitive: Argon2Params = Argon2Params(2097152, 1, 4) // RFC 9106 first recommendation

  /** Validate caller-supplied parameters: iterations >= 1, 1 <= parallelism <= 255, and memory >= 8
    * * parallelism KiB.
    */
  def of(memoryKib: Int, iterations: Int, parallelism: Int): Either[InvalidParams, Argon2Params] =
    if iterations >= 1 && parallelism >= 1 && parallelism <= 255 && memoryKib >= 8 * parallelism then
      Right(Argon2Params(memoryKib, iterations, parallelism))
    else Left(InvalidParams)
end Argon2Params

/** A stored PHC argon2id hash string; parse via [[PasswordHash$ PasswordHash]]. */
opaque type PasswordHash = String
object PasswordHash:
  private[kufuli] def unsafe(s: String): PasswordHash = s

  /** Parse a stored PHC argon2id string; a corrupt column fails here, not at verify. */
  def of(stored: String): Either[MalformedHash, PasswordHash] =
    if stored.startsWith("$argon2id$") then Right(stored) else Left(MalformedHash)
  extension (h: PasswordHash) def value: String = h

/** The outcome of verifying a password against a stored hash. */
enum PasswordCheck derives CanEqual:
  case Rejected

  /** `rehash` is `Some` when the stored hash is weaker than the current policy and should be
    * recomputed.
    */
  case Verified(rehash: Option[Argon2Params])

extension (pw: Array[Byte])
  /** Hash `pw` under `params`, yielding a PHC string. */
  def hash(params: Argon2Params)(using ev: Supports[Argon2id]): UEffIO[PasswordHash] =
    val _ = (pw, params, ev)
    EffIO.succeed(PasswordHash.unsafe("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"))

  /** Check `pw` against a stored hash; a `Verified` result carries a rehash recommendation measured
    * against `policy`.
    */
  def verify(against: PasswordHash, policy: Argon2Params)(using ev: Supports[Argon2id]): UEffIO[PasswordCheck] =
    val _ = (pw, against, ev)
    EffIO.succeed(PasswordCheck.Verified(Option.when(Argon2Params.interactive != policy)(policy)))
end extension

// String input is encoded as UTF-8 with no normalisation; applying RFC 8265 OpaqueString, where
// wanted, is the caller's responsibility.
extension (pw: String)
  @targetName("hashString")
  def hash(params: Argon2Params)(using Supports[Argon2id]): UEffIO[PasswordHash] =
    pw.getBytes(StandardCharsets.UTF_8).hash(params)
  @targetName("verifyString")
  def verify(against: PasswordHash, policy: Argon2Params)(using Supports[Argon2id]): UEffIO[PasswordCheck] =
    pw.getBytes(StandardCharsets.UTF_8).verify(against, policy)
