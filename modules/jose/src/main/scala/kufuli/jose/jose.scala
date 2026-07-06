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
package kufuli.jose

import scala.annotation.targetName
import scala.concurrent.duration.DurationInt
import scala.concurrent.duration.FiniteDuration
import scala.util.control.NoStackTrace

import boilerplate.effect.EffIO
import boilerplate.effect.UEffIO

import kufuli.*

// Verification is safe by construction: the audience and the algorithm allowlist are required
// arguments, and `alg: none` is unrepresentable. Times are epoch seconds (java.time is not on the
// cross-platform floor).

sealed abstract class JoseError(message: String) extends Exception(message) with NoStackTrace derives CanEqual

/** A JWS `alg` (RFC 7518). Each value fixes the signing and verifying key types through its
  * `Signing` and `Verifying` members, so a key of the wrong algorithm is a type error.
  */
sealed trait JWSAlg derives CanEqual:
  type Signing
  type Verifying
case object HS256 extends JWSAlg:
  type Signing = SecretKey[HmacSha256]; type Verifying = SecretKey[HmacSha256]
case object HS384 extends JWSAlg:
  type Signing = SecretKey[HmacSha384]; type Verifying = SecretKey[HmacSha384]
case object HS512 extends JWSAlg:
  type Signing = SecretKey[HmacSha512]; type Verifying = SecretKey[HmacSha512]
case object RS256 extends JWSAlg:
  type Signing = PrivateKey[Rsa]; type Verifying = PublicKey[Rsa] // PKCS#1 v1.5
case object PS256 extends JWSAlg:
  type Signing = PrivateKey[Rsa]; type Verifying = PublicKey[Rsa] // PSS
case object ES256 extends JWSAlg:
  type Signing = PrivateKey[P256]; type Verifying = PublicKey[P256]
case object ES384 extends JWSAlg:
  type Signing = PrivateKey[P384]; type Verifying = PublicKey[P384]
case object ES512 extends JWSAlg:
  type Signing = PrivateKey[P521]; type Verifying = PublicKey[P521]
case object EdDSA extends JWSAlg:
  type Signing = PrivateKey[Ed25519]; type Verifying = PublicKey[Ed25519]

/** A JSON value carried in a JWT's custom claims. */
enum JoseValue derives CanEqual:
  case Str(value: String)
  case Num(value: Double)
  case Bool(value: Boolean)
  case Arr(values: List[JoseValue])
  case Obj(fields: Map[String, JoseValue])
  case Null

/** A compact-serialised JWT; sign and verify via [[JWT$ JWT]]. */
opaque type JWT = String
object JWT:
  final case class Claims(
    subject: Option[String] = None,
    issuer: Option[String] = None,
    audiences: Set[String] = Set.empty, // RFC 7519 `aud` is string OR array; emitted as string when 1
    expiresIn: Option[FiniteDuration] = None, // stamped against the clock at sign time
    custom: Map[String, JoseValue] = Map.empty
  )

  /** Audience and algorithms are the two checks whose omission is an exploit: constructor-required. */
  final case class Policy(
    audience: String,
    algorithms: Set[JWSAlg],
    issuer: Option[String] = None,
    clockSkew: FiniteDuration = 0.seconds
  ):
    require(algorithms.nonEmpty, "the algorithm allowlist cannot be empty")
  object Policy:
    /** Deliberate, named opt-out for audience-free internal tokens. */
    final case class Unaudienced(algorithms: Set[JWSAlg], issuer: Option[String] = None, clockSkew: FiniteDuration = 0.seconds):
      require(algorithms.nonEmpty, "the algorithm allowlist cannot be empty")
    def unaudienced(algorithms: Set[JWSAlg]): Unaudienced = Unaudienced(algorithms)
    @targetName("unaudiencedIssuer")
    def unaudienced(algorithms: Set[JWSAlg], issuer: Option[String]): Unaudienced = Unaudienced(algorithms, issuer)

  final case class Verified(
    subject: Option[String],
    issuer: Option[String],
    audiences: Set[String], // the policy's audience is REQUIRED to be a member (or Unaudienced was chosen)
    expiresAt: Option[Long], // epoch seconds
    issuedAt: Option[Long],
    claims: Map[String, JoseValue]
  )

  enum Rejected(message: String) extends JoseError(message):
    case Malformed extends Rejected("not a JWS compact serialization")
    case BadSignature extends Rejected("signature verification failed")
    case Expired extends Rejected("token expired")
    case NotYetValid extends Rejected("token not yet valid (nbf)")
    case IssuerMismatch extends Rejected("issuer mismatch")
    case AudienceMismatch extends Rejected("audience mismatch")
    case UntrustedAlgorithm extends Rejected("algorithm not in the allowlist")
    case UnknownKey extends Rejected("no key for kid")

  /** Sign with the dependent key type: the alg singleton fixes what `key` may be. */
  def sign(claims: Claims, alg: JWSAlg)(key: alg.Signing): UEffIO[JWT] =
    val _ = (claims, alg, key)
    EffIO.succeed("eyJ.design.stub")
  def verify(token: String, keys: JWKS, policy: Policy): EffIO[Rejected, Verified] =
    val _ = (token, keys)
    EffIO.succeed(Verified(Some("sub"), policy.issuer, Set(policy.audience), None, None, Map.empty))
  @targetName("verifyUnaudienced")
  def verify(token: String, keys: JWKS, policy: Policy.Unaudienced): EffIO[Rejected, Verified] =
    val _ = (token, keys)
    EffIO.succeed(Verified(Some("sub"), policy.issuer, Set.empty, None, None, Map.empty))

  /** Single-key verification for the fixed-key deployment (no JWKS indirection). */
  def verify(token: String, alg: JWSAlg, key: alg.Verifying, policy: Policy): EffIO[Rejected, Verified] =
    val _ = (token, alg, key)
    EffIO.succeed(Verified(Some("sub"), policy.issuer, Set(policy.audience), None, None, Map.empty))

  extension (jwt: JWT) def compact: String = jwt
end JWT

final case class JWK(kid: Option[String], key: ImportedPublicKey)
object JWK:
  def parse(json: String): Either[Malformed, JWK] =
    if json.startsWith("{") then Right(JWK(Some("k1"), ImportedPublicKey.Ed(PublicKey.unsafe(IArray.empty)))) else Left(Malformed)
final case class JWKS(keys: List[JWK]):
  def find(kid: String): Option[JWK] = keys.find(_.kid.contains(kid))
object JWKS:
  def parse(json: String): Either[Malformed, JWKS] =
    if json.startsWith("{") then Right(JWKS(Nil)) else Left(Malformed)

/** RFC 7638 JWK thumbprint. Any digest is admissible (not only a signature hash), because the
  * related `x5t` header is SHA-1 by definition.
  */
extension [A](pub: PublicKey[A])
  def thumbprint(): UEffIO[Digest] = pub.thumbprint(Sha256)
  @targetName("thumbprintWith") def thumbprint(alg: DigestSpec[?]): UEffIO[Digest] =
    val _ = pub
    EffIO.succeed(Digest.unsafe(IArray.fill(alg.length)(0.toByte)))

/** COSE_Key import (RFC 9052): WebAuthn credential public keys arrive as COSE, not JWK. Parsing
  * yields the same key GADT as SPKI and JWK; the WebAuthn ceremony is the caller's concern.
  */
object COSEKey:
  def parse(cbor: Array[Byte]): Either[InvalidKey, ImportedPublicKey] =
    if cbor.nonEmpty then Right(ImportedPublicKey.Ed(PublicKey.unsafe(IArray.empty)))
    else Left(InvalidKey.Malformed)

/** A compact-serialised JWE; seal and open via [[JWE$ JWE]]. */
opaque type JWE = String
object JWE:
  enum Alg derives CanEqual:
    case EcdhEs, EcdhEsA128Kw, EcdhEsA256Kw, RsaOaep256, Dir
  enum Enc derives CanEqual:
    case A128CbcHs256, A256CbcHs512, A128Gcm, A256Gcm
  enum Rejected(message: String) extends JoseError(message):
    case Malformed extends Rejected("not a JWE compact serialization")
    case DecryptionFailed extends Rejected("content decryption failed")
    case UntrustedAlgorithm extends Rejected("alg/enc not in the allowlist")
  def seal[C <: EcCurve](pt: Array[Byte], recipient: PublicKey[C], alg: Alg, enc: Enc): UEffIO[JWE] =
    val _ = (pt, recipient, alg, enc)
    EffIO.succeed("eyJ.design.jwe")
  @targetName("sealRsa")
  def seal(pt: Array[Byte], recipient: PublicKey[Rsa], enc: Enc): UEffIO[JWE] =
    val _ = (pt, recipient, enc)
    EffIO.succeed("eyJ.design.jwe")
  def open[C <: EcCurve](jwe: String, key: PrivateKey[C], allowed: Set[Enc]): EffIO[Rejected, Array[Byte]] =
    val _ = (jwe, key, allowed)
    EffIO.succeed(Array.emptyByteArray)
  extension (jwe: JWE) def compact: String = jwe
end JWE
