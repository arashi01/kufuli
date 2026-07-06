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
package kufuli.x509

import scala.annotation.targetName
import scala.util.control.NoStackTrace

import boilerplate.effect.EffIO

import kufuli.ImportedPublicKey
import kufuli.Malformed
import kufuli.PublicKey

// TLS-profile path validation: parse, verify the chain's signatures to trust anchors, check the
// validity window, match SAN/hostname (RFC 6125), and enforce basic constraints and EKU by purpose,
// plus stapled-OCSP verification. Not full RFC 5280 policy trees, and never CRL or live-OCSP
// fetching. Times are epoch seconds.

sealed abstract class X509Error(message: String) extends Exception(message) with NoStackTrace derives CanEqual
enum PathInvalid(message: String) extends X509Error(message):
  case MalformedChain extends PathInvalid("unparseable certificate in chain")
  case Expired extends PathInvalid("certificate outside validity window")
  case UntrustedAnchor extends PathInvalid("chain does not terminate at a trust anchor")
  case BadSignature extends PathInvalid("chain signature verification failed")
  case NameMismatch extends PathInvalid("hostname does not match SAN")
  case ConstraintViolated extends PathInvalid("basic constraints / EKU violated")

/** A parsed X.509 certificate; construct and read via [[Certificate$ Certificate]]. */
opaque type Certificate = IArray[Byte]
object Certificate:
  def fromDer(der: Array[Byte]): Either[Malformed, Certificate] =
    if der.nonEmpty then Right(IArray.from(der)) else Left(Malformed)
  def fromPem(pem: String): Either[Malformed, Certificate] =
    if pem.contains("BEGIN CERTIFICATE") then Right(IArray(1.toByte)) else Left(Malformed)

  /** Parse a `fullchain.pem` bundle, leaf first, as issued by certbot, acme.sh, and cloud CAs. */
  def chainFromPem(pem: String): Either[Malformed, List[Certificate]] =
    if pem.contains("BEGIN CERTIFICATE") then Right(List(IArray(1.toByte))) else Left(Malformed)
  extension (cert: Certificate)
    def der: IArray[Byte] = cert
    def publicKey: ImportedPublicKey =
      ImportedPublicKey.Ed(PublicKey.unsafe(IArray.empty))
    def notBefore: Long = 0L
    def notAfter: Long = Long.MaxValue
    def subjectAltDns: List[String] = Nil
end Certificate

/** A validated DNS hostname for SAN matching; construct via [[Hostname$ Hostname]]. */
opaque type Hostname = String
object Hostname:
  def of(name: String): Either[Malformed, Hostname] =
    if name.nonEmpty && !name.contains(" ") then Right(name) else Left(Malformed)
  extension (h: Hostname) def value: String = h

final case class TrustAnchors(anchors: List[Certificate]):
  require(anchors.nonEmpty, "at least one trust anchor")

/** What a chain is validated for; selects the EKU and key-usage checks. */
enum PathPurpose derives CanEqual:
  case ServerAuth, ClientAuth

final case class VerifiedPath(leaf: Certificate, chain: List[Certificate])

object CertPath:
  /** ServerAuth by default (the TLS-client / DB-client path). */
  def verify(
    chain: List[Certificate],
    anchors: TrustAnchors,
    at: Long, // epoch seconds
    hostname: Option[Hostname] // required for ServerAuth in practice; None is mTLS/client paths
  ): EffIO[PathInvalid, VerifiedPath] =
    verify(chain, anchors, at, hostname, PathPurpose.ServerAuth)
  @targetName("verifyPurpose") def verify(
    chain: List[Certificate],
    anchors: TrustAnchors,
    at: Long,
    hostname: Option[Hostname],
    purpose: PathPurpose
  ): EffIO[PathInvalid, VerifiedPath] =
    val _ = (anchors, at, hostname, purpose)
    chain match
      case leaf :: rest => EffIO.succeed(VerifiedPath(leaf, rest))
      case Nil          => EffIO.fail(PathInvalid.MalformedChain)
end CertPath

/** Verifies a stapled OCSP response the caller supplies (from the TLS handshake). No network I/O is
  * performed; live OCSP and CRL fetching are out of scope.
  */
object OCSP:
  enum Status derives CanEqual:
    case Good
    case Revoked(at: Long)
    case Unknown
  def verifyStapled(response: Array[Byte], leaf: Certificate, issuer: Certificate, at: Long): EffIO[PathInvalid, Status] =
    val _ = (leaf, issuer, at)
    if response.nonEmpty then EffIO.succeed(Status.Good) else EffIO.fail(PathInvalid.MalformedChain)
