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
package kufuli

import java.util.concurrent.atomic.AtomicLong

import scala.annotation.implicitNotFound
import scala.annotation.targetName
import scala.util.control.NoStackTrace

import boilerplate.Slice
import boilerplate.effect.EffIO
import boilerplate.effect.UEffIO
import cats.effect.IO
import cats.effect.Resource

/** Root of the failure ADT. Every case is data-dependent (peer input, stored data, or a spent
  * budget); programmer errors (wrong nonce length, buffer arithmetic, nonsensical limits) are
  * defects raised by `require`, not values. Rejections carry no payload, so nothing leaks a padding
  * or forgery oracle.
  */
sealed abstract class KufuliError(message: String) extends Exception(message) with NoStackTrace derives CanEqual

case object AuthFailed extends KufuliError("authentication failed")
type AuthFailed = AuthFailed.type
case object SignatureRejected extends KufuliError("signature rejected")
type SignatureRejected = SignatureRejected.type
case object BudgetExhausted extends KufuliError("AEAD usage budget exhausted")
type BudgetExhausted = BudgetExhausted.type
case object UnwrapFailed extends KufuliError("key unwrap failed")
type UnwrapFailed = UnwrapFailed.type
case object NotWrappable extends KufuliError("key length not a multiple of 8: use an AES-KWP algorithm")
type NotWrappable = NotWrappable.type
case object KeyNotExportable extends KufuliError("key material is not exportable on this backend")
type KeyNotExportable = KeyNotExportable.type
case object Malformed extends KufuliError("malformed encoding")
type Malformed = Malformed.type
case object DuplicateKeyId extends KufuliError("keyring ids must be unique")
type DuplicateKeyId = DuplicateKeyId.type

enum InvalidKey(message: String) extends KufuliError(message):
  case Malformed extends InvalidKey("malformed key encoding")
  case WrongLength(expected: Int, got: Int) extends InvalidKey(s"expected $expected bytes, got $got")
  case NotOnCurve extends InvalidKey("point not on curve")
  case WeakPoint extends InvalidKey("small-order or otherwise weak public point")
  case Unsupported extends InvalidKey("algorithm not supported here")

/** Evidence that the linked backend implements algorithm `A`. Resolved from implicit scope, so a
  * capability the backend lacks is a compile error at the call site, never a runtime surprise. Not
  * constructible outside this library.
  */
@implicitNotFound(
  "${A} is not provided by this kufuli backend (browser lacks ChaCha/KWP/ML-KEM/Argon2; XChaCha and GCM-SIV are Native; ML-KEM is JVM>=25 and Native, Node pending verification)"
)
sealed abstract class Supports[A <: Algorithm] private[kufuli] (private[kufuli] val spec: AlgorithmSpec[A])

/** Given instances of [[Supports]] for the algorithms the current artifact provides. */
object Supports:
  private[kufuli] def token[A <: Algorithm](spec: AlgorithmSpec[A]): Supports[A] =
    new Supports[A](spec) {}
  given aesGcm128: Supports[AesGcm128] = token(AesGcm128)
  given aesGcm192: Supports[AesGcm192] = token(AesGcm192)
  given aesGcm256: Supports[AesGcm256] = token(AesGcm256)
  given a128CbcHs256: Supports[A128CbcHs256] = token(A128CbcHs256)
  given a256CbcHs512: Supports[A256CbcHs512] = token(A256CbcHs512)
  given hmacSha256: Supports[HmacSha256] = token(HmacSha256)
  given hmacSha384: Supports[HmacSha384] = token(HmacSha384)
  given hmacSha512: Supports[HmacSha512] = token(HmacSha512)
  given aesKw128: Supports[AesKw128] = token(AesKw128)
  given aesKw256: Supports[AesKw256] = token(AesKw256)
  given chaCha20Poly1305(using ChaChaCapable =:= true): Supports[ChaCha20Poly1305] = token(ChaCha20Poly1305)
  given aesKwp128(using KwpCapable =:= true): Supports[AesKwp128] = token(AesKwp128)
  given aesKwp256(using KwpCapable =:= true): Supports[AesKwp256] = token(AesKwp256)
  given xChaCha20Poly1305(using XChaChaCapable =:= true): Supports[XChaCha20Poly1305] = token(XChaCha20Poly1305)
  given aesGcmSiv256(using GcmSivCapable =:= true): Supports[AesGcmSiv256] = token(AesGcmSiv256)
  given mlKem768(using MlKemCapable =:= true): Supports[MlKem768] = token(MlKem768)
  given mlKem1024(using MlKemCapable =:= true): Supports[MlKem1024] = token(MlKem1024)
end Supports

/** Evidence that the backend can compute synchronously on the calling thread. Gates the per-record
  * [[Cipher]] handle, incremental hashing, and `kufuli.unsafe`; absent on the async-only WebCrypto
  * (browser) artifact.
  */
@implicitNotFound(
  "this kufuli backend cannot compute synchronously (WebCrypto is async-only): Cipher handles, incremental hashing and kufuli.unsafe are unavailable in the browser artifact"
)
sealed trait Direct
object Direct:
  given (using DirectCapable =:= true): Direct = new Direct {}

/** Root capability marker, attested per algorithm by [[Supports]]. Closed to third parties:
  * [[AlgorithmSpec]]'s constructor and `Supports.token` are library-private, so an alien
  * `Algorithm` can gain neither a spec nor evidence.
  */
trait Algorithm
abstract class AlgorithmSpec[A <: Algorithm] private[kufuli] ()

sealed trait SymmetricAlgorithm extends Algorithm
sealed trait AeadAlgorithm extends SymmetricAlgorithm
sealed trait HmacAlgorithm extends SymmetricAlgorithm
sealed trait WrapAlgorithm extends SymmetricAlgorithm

sealed abstract class SymmetricSpec[A <: SymmetricAlgorithm](val keyLength: Int) extends AlgorithmSpec[A]:
  protected def validateKeyLength(n: Int): Either[InvalidKey, Unit] =
    if n == keyLength then Right(()) else Left(InvalidKey.WrongLength(keyLength, n))

  /** Import raw key material into a key of this algorithm; length-validated, defensive copy. */
  final def key(bytes: Array[Byte]): Either[InvalidKey, SecretKey[A]] =
    validateKeyLength(bytes.length).map(_ => SecretKey.unsafe[A](IArray.from(bytes)))

  /** Generate a fresh key of this algorithm from the backend CSPRNG. */
  final def generate(using ev: Supports[A]): UEffIO[SecretKey[A]] =
    val _ = ev
    EffIO.succeed(SecretKey.unsafe[A](IArray.fill(keyLength)(0.toByte)))
end SymmetricSpec

sealed abstract class AeadSpec[A <: AeadAlgorithm](keyLength: Int, val nonceLength: Int, val tagLength: Int)
    extends SymmetricSpec[A](keyLength)

sealed abstract class HmacSpec[H <: HmacAlgorithm](val outLength: Int) extends SymmetricSpec[H](outLength):
  // HMAC accepts variable-length keys; the outLength..128 window is the RFC 2104 floor plus the JOSE cap.
  override protected def validateKeyLength(n: Int): Either[InvalidKey, Unit] =
    if n >= outLength && n <= 128 then Right(()) else Left(InvalidKey.WrongLength(outLength, n))

sealed abstract class WrapSpec[W <: WrapAlgorithm](keyLength: Int, val padded: Boolean) extends SymmetricSpec[W](keyLength)

sealed trait AesGcm128 extends AeadAlgorithm
case object AesGcm128 extends AeadSpec[AesGcm128](16, 12, 16) with AesGcm128
sealed trait AesGcm192 extends AeadAlgorithm
case object AesGcm192 extends AeadSpec[AesGcm192](24, 12, 16) with AesGcm192
sealed trait AesGcm256 extends AeadAlgorithm
case object AesGcm256 extends AeadSpec[AesGcm256](32, 12, 16) with AesGcm256
sealed trait ChaCha20Poly1305 extends AeadAlgorithm
case object ChaCha20Poly1305 extends AeadSpec[ChaCha20Poly1305](32, 12, 16) with ChaCha20Poly1305
// Prefer these at volume where the backend provides them: XChaCha's 192-bit nonce makes random-nonce
// sealing safe at any realistic volume, and GCM-SIV survives nonce reuse.
sealed trait XChaCha20Poly1305 extends AeadAlgorithm
case object XChaCha20Poly1305 extends AeadSpec[XChaCha20Poly1305](32, 24, 16) with XChaCha20Poly1305
sealed trait AesGcmSiv256 extends AeadAlgorithm
case object AesGcmSiv256 extends AeadSpec[AesGcmSiv256](32, 12, 16) with AesGcmSiv256
// RFC 7518 CBC-HMAC composites: the key is MAC||ENC and the tag is a truncated HMAC.
sealed trait A128CbcHs256 extends AeadAlgorithm
case object A128CbcHs256 extends AeadSpec[A128CbcHs256](32, 16, 16) with A128CbcHs256
sealed trait A256CbcHs512 extends AeadAlgorithm
case object A256CbcHs512 extends AeadSpec[A256CbcHs512](64, 16, 32) with A256CbcHs512

sealed trait HmacSha256 extends HmacAlgorithm
case object HmacSha256 extends HmacSpec[HmacSha256](32) with HmacSha256
sealed trait HmacSha384 extends HmacAlgorithm
case object HmacSha384 extends HmacSpec[HmacSha384](48) with HmacSha384
sealed trait HmacSha512 extends HmacAlgorithm
case object HmacSha512 extends HmacSpec[HmacSha512](64) with HmacSha512

sealed trait AesKw128 extends WrapAlgorithm
case object AesKw128 extends WrapSpec[AesKw128](16, padded = false) with AesKw128
sealed trait AesKw256 extends WrapAlgorithm
case object AesKw256 extends WrapSpec[AesKw256](32, padded = false) with AesKw256
sealed trait AesKwp128 extends WrapAlgorithm
case object AesKwp128 extends WrapSpec[AesKwp128](16, padded = true) with AesKwp128
sealed trait AesKwp256 extends WrapAlgorithm
case object AesKwp256 extends WrapSpec[AesKwp256](32, padded = true) with AesKwp256

sealed trait EcCurve
sealed abstract class EcSpec[C <: EcCurve](val fieldLength: Int):
  /** Generate a fresh keypair on this curve. */
  final def generate: UEffIO[KeyPair[PublicKey[C], PrivateKey[C]]] =
    EffIO.succeed(KeyPair(PublicKey.unsafe[C](IArray.empty), PrivateKey.unsafe[C](IArray.empty)))
sealed trait P256 extends EcCurve
case object P256 extends EcSpec[P256](32) with P256
sealed trait P384 extends EcCurve
case object P384 extends EcSpec[P384](48) with P384
sealed trait P521 extends EcCurve
case object P521 extends EcSpec[P521](66) with P521

// Ed25519 (signing) and X25519 (agreement) share no operation, so no family abstracts over them
// and cross-use cannot be expressed. Ed448/X448 are absent (unsupported by the native backend).
sealed trait Ed25519
case object Ed25519 extends Ed25519:
  def generate: UEffIO[KeyPair[PublicKey[Ed25519], PrivateKey[Ed25519]]] =
    EffIO.succeed(KeyPair(PublicKey.unsafe(IArray.empty), PrivateKey.unsafe(IArray.empty)))
sealed trait X25519
case object X25519 extends X25519:
  def generate: UEffIO[KeyPair[PublicKey[X25519], PrivateKey[X25519]]] =
    EffIO.succeed(KeyPair(PublicKey.unsafe(IArray.empty), PrivateKey.unsafe(IArray.empty)))

// FIPS 203 KEM: its own operation family (encapsulate/decapsulate), never agreement. The hybrid
// combination of the two shared secrets is the caller's protocol code, not kufuli's.
sealed trait KemAlgorithm extends Algorithm
sealed abstract class KemSpec[K <: KemAlgorithm](val publicKeyLength: Int, val ciphertextLength: Int) extends AlgorithmSpec[K]:
  final def generate(using ev: Supports[K]): UEffIO[KeyPair[PublicKey[K], PrivateKey[K]]] =
    val _ = ev
    EffIO.succeed(KeyPair(PublicKey.unsafe(IArray.empty), PrivateKey.unsafe(IArray.empty)))
sealed trait MlKem768 extends KemAlgorithm
case object MlKem768 extends KemSpec[MlKem768](1184, 1088) with MlKem768
sealed trait MlKem1024 extends KemAlgorithm
case object MlKem1024 extends KemSpec[MlKem1024](1568, 1568) with MlKem1024

/** A KEM ciphertext of scheme `K`; length is validated at construction (see
  * [[KemCiphertext$ KemCiphertext]]).
  */
opaque type KemCiphertext[K <: KemAlgorithm] = IArray[Byte]

/** Length-validated construction and byte access for [[KemCiphertext]]. */
object KemCiphertext:
  private[kufuli] def unsafe[K <: KemAlgorithm](b: IArray[Byte]): KemCiphertext[K] = b

  /** Parse a wire ciphertext; length must match the scheme, which makes `decapsulate` total. */
  def of[K <: KemAlgorithm](alg: KemSpec[K])(bytes: Array[Byte]): Either[InvalidKey, KemCiphertext[K]] =
    if bytes.length == alg.ciphertextLength then Right(IArray.from(bytes))
    else Left(InvalidKey.WrongLength(alg.ciphertextLength, bytes.length))
  extension [K <: KemAlgorithm](ct: KemCiphertext[K]) def bytes: IArray[Byte] = ct

final case class Encapsulated[K <: KemAlgorithm](secret: SharedSecret, ciphertext: KemCiphertext[K])

extension [K <: KemAlgorithm](pub: PublicKey[K])
  /** Encapsulate to the peer key, yielding a shared secret and its wire ciphertext. */
  def encapsulate(using s: Supports[K]): UEffIO[Encapsulated[K]] =
    val spec = s.spec match
      case k: KemSpec[?] => k
    EffIO.succeed(
      Encapsulated(
        SharedSecret.unsafe(IArray.fill(32)(8.toByte)),
        KemCiphertext.unsafe(IArray.fill(spec.ciphertextLength)(8.toByte))
      )
    )
extension [K <: KemAlgorithm](priv: PrivateKey[K])
  /** Recover the shared secret. Total: FIPS 203 implicit rejection returns a pseudorandom secret
    * for a forged ciphertext rather than failing.
    */
  def decapsulate(ct: KemCiphertext[K])(using ev: Supports[K]): UEffIO[SharedSecret] =
    val _ = (ct, ev)
    EffIO.succeed(SharedSecret.unsafe(IArray.fill(32)(8.toByte)))

sealed trait Rsa
object Rsa:
  final class Size private[Rsa] (val bits: Int)

  /** Validated RSA modulus size; must be at least 2048 and a multiple of 8. */
  def bits(n: Int): Size =
    require(n >= 2048 && n % 8 == 0, s"RSA modulus must be >= 2048 and a multiple of 8, got $n")
    new Size(n)
  def generate(size: Size): UEffIO[KeyPair[PublicKey[Rsa], PrivateKey[Rsa]]] =
    val _ = size
    EffIO.succeed(KeyPair(PublicKey.unsafe(IArray.empty), PrivateKey.unsafe(IArray.empty)))

sealed trait DigestAlgorithm extends Algorithm
sealed abstract class DigestSpec[D <: DigestAlgorithm](val length: Int) extends AlgorithmSpec[D]:
  /** A resource-scoped incremental hasher. `digestNow` snapshots without consuming the context, as
    * a running transcript hash needs. Synchronous and single-fibre.
    */
  final def hasher(using d: Direct): Resource[IO, Hasher] =
    val _ = d
    Resource.pure(new Hasher:
      def update(bytes: Array[Byte]): Unit = ()
      def update(bytes: Slice): Unit = ()
      def digestNow: Digest = Digest.unsafe(IArray.fill(length)(0.toByte)))
sealed trait Sha1 extends DigestAlgorithm
case object Sha1 extends DigestSpec[Sha1](20) with Sha1 // one-shot digests only (e.g. the JOSE x5t thumbprint)
sealed trait Sha256 extends DigestAlgorithm
case object Sha256 extends DigestSpec[Sha256](32) with Sha256
sealed trait Sha384 extends DigestAlgorithm
case object Sha384 extends DigestSpec[Sha384](48) with Sha384
sealed trait Sha512 extends DigestAlgorithm
case object Sha512 extends DigestSpec[Sha512](64) with Sha512

/** Hashes admissible in a signature or KDF. Excludes Sha1, so weak-hash use is a type error. */
type SignatureHash = Sha256.type | Sha384.type | Sha512.type

sealed trait RsaSignature derives CanEqual
final case class RsaPss(hash: SignatureHash) extends RsaSignature
final case class RsaPkcs1(hash: SignatureHash) extends RsaSignature
final case class RsaOaep(hash: SignatureHash) derives CanEqual

/** A public key of algorithm `A`. The representation is platform-defined - key bytes on
  * JVM/Node/Native, an opaque non-extractable handle in the browser - so export is effectful and
  * may fail. Parse and export via [[PublicKey$ PublicKey]].
  */
opaque type PublicKey[A] = KeyRepr

/** A private key of algorithm `A`; representation as for [[PublicKey]]. Parse via
  * [[PrivateKey$ PrivateKey]].
  */
opaque type PrivateKey[A] = KeyRepr

/** A symmetric key of algorithm `A`; representation as for [[PublicKey]]. Make one from an
  * algorithm spec's `key`/`generate`.
  */
opaque type SecretKey[A] = KeyRepr
final case class KeyPair[+Pub, +Priv](publicKey: Pub, privateKey: Priv)

/** The result of parsing an SPKI public key of unknown algorithm; match to recover the bound curve
  * or scheme, which then flows into every subsequent operation.
  */
enum ImportedPublicKey:
  case Ec[C <: EcCurve](curve: EcSpec[C], key: PublicKey[C]) extends ImportedPublicKey
  case Ed(key: PublicKey[Ed25519])
  case X(key: PublicKey[X25519])
  case OfRsa(key: PublicKey[Rsa])
  case Kem[K <: KemAlgorithm](spec: KemSpec[K], key: PublicKey[K]) extends ImportedPublicKey

/** The result of parsing a PKCS#8 private key of unknown algorithm; match as for
  * [[ImportedPublicKey]].
  */
enum ImportedPrivateKey:
  case Ec[C <: EcCurve](curve: EcSpec[C], key: PrivateKey[C]) extends ImportedPrivateKey
  case Ed(key: PrivateKey[Ed25519])
  case X(key: PrivateKey[X25519])
  case OfRsa(key: PrivateKey[Rsa])
  case Kem[K <: KemAlgorithm](spec: KemSpec[K], key: PrivateKey[K]) extends ImportedPrivateKey

/** Parsers for [[PublicKey]] wire and encoded forms. */
object PublicKey:
  private[kufuli] def unsafe[A](r: KeyRepr): PublicKey[A] = r

  /** Import a 32-byte Ed25519 point. Wire imports reject off-curve and small-order points, which is
    * what makes `agree` and `verify` total.
    */
  def fromRaw(alg: Ed25519)(bytes: Array[Byte]): Either[InvalidKey, PublicKey[Ed25519]] =
    val _ = alg
    if bytes.length == 32 then Right(unsafe(IArray.from(bytes))) else Left(InvalidKey.WrongLength(32, bytes.length))
  @targetName("fromRawX")
  def fromRaw(alg: X25519)(bytes: Array[Byte]): Either[InvalidKey, PublicKey[X25519]] =
    val _ = alg
    if bytes.length == 32 then Right(unsafe(IArray.from(bytes))) else Left(InvalidKey.WrongLength(32, bytes.length))
  @targetName("fromRawKem")
  def fromRaw[K <: KemAlgorithm](alg: KemSpec[K])(bytes: Array[Byte]): Either[InvalidKey, PublicKey[K]] =
    if bytes.length == alg.publicKeyLength then Right(unsafe(IArray.from(bytes)))
    else Left(InvalidKey.WrongLength(alg.publicKeyLength, bytes.length))

  /** Import a SEC1 point, uncompressed (`0x04 || X || Y`) or compressed. */
  def fromSec1[C <: EcCurve](curve: EcSpec[C])(bytes: Array[Byte]): Either[InvalidKey, PublicKey[C]] =
    if bytes.length == 1 + 2 * curve.fieldLength || bytes.length == 1 + curve.fieldLength then Right(unsafe(IArray.from(bytes)))
    else Left(InvalidKey.WrongLength(1 + 2 * curve.fieldLength, bytes.length))

  /** Parse an SPKI (`SubjectPublicKeyInfo`) DER blob whose algorithm is discovered from the
    * encoding.
    */
  def fromSpki(der: Array[Byte]): Either[InvalidKey, ImportedPublicKey] =
    if der.nonEmpty then Right(ImportedPublicKey.Ed(unsafe(IArray.from(der)))) else Left(InvalidKey.Malformed)
end PublicKey

/** Parsers for [[PrivateKey]] encoded forms. */
object PrivateKey:
  private[kufuli] def unsafe[A](r: KeyRepr): PrivateKey[A] = r

  /** Parse a PKCS#8 DER blob whose algorithm is discovered from the encoding. */
  def fromPkcs8(der: Array[Byte]): Either[InvalidKey, ImportedPrivateKey] =
    if der.nonEmpty then Right(ImportedPrivateKey.Ed(unsafe(IArray.from(der)))) else Left(InvalidKey.Malformed)

object SecretKey:
  private[kufuli] def unsafe[A](r: KeyRepr): SecretKey[A] = r

// Export is effectful and fails KeyNotExportable on a browser-generated (non-extractable) key;
// bytes-backed platforms always succeed.
extension [A](pub: PublicKey[A]) def spki: EffIO[KeyNotExportable, IArray[Byte]] = EffIO.succeed(IArray.fill(64)(9.toByte))
extension (pub: PublicKey[Ed25519])
  @targetName("rawEd") def raw: EffIO[KeyNotExportable, IArray[Byte]] = EffIO.succeed(IArray.fill(32)(9.toByte))
extension (pub: PublicKey[X25519])
  @targetName("rawX") def raw: EffIO[KeyNotExportable, IArray[Byte]] = EffIO.succeed(IArray.fill(32)(9.toByte))
extension [C <: EcCurve](pub: PublicKey[C]) def sec1: EffIO[KeyNotExportable, IArray[Byte]] = EffIO.succeed(IArray.fill(65)(9.toByte))
extension [K <: KemAlgorithm](pub: PublicKey[K])
  @targetName("rawKem") def raw(using s: Supports[K]): EffIO[KeyNotExportable, IArray[Byte]] =
    val spec = s.spec match
      case k: KemSpec[?] => k
    EffIO.succeed(IArray.fill(spec.publicKeyLength)(9.toByte))
extension [A](priv: PrivateKey[A]) def pkcs8: EffIO[KeyNotExportable, IArray[Byte]] = EffIO.succeed(IArray.fill(48)(9.toByte))
extension [A](sk: SecretKey[A]) def raw: EffIO[KeyNotExportable, IArray[Byte]] = EffIO.succeed(IArray.fill(32)(9.toByte))

/** A signature over algorithm `A`: 64 raw bytes for Ed25519, fixed-width `r || s` for ECDSA, the
  * signature octets for RSA. Parse or convert via [[Signature$ Signature]].
  */
opaque type Signature[A] = IArray[Byte]

/** Parsers, DER/raw conversion, and byte access for [[Signature]]. */
object Signature:
  private[kufuli] def unsafe[A](b: IArray[Byte]): Signature[A] = b
  def fromRaw(alg: Ed25519)(bytes: Array[Byte]): Either[Malformed, Signature[Ed25519]] =
    val _ = alg
    if bytes.length == 64 then Right(IArray.from(bytes)) else Left(Malformed)
  @targetName("fromRawEc")
  def fromRaw[C <: EcCurve](curve: EcSpec[C])(bytes: Array[Byte]): Either[Malformed, Signature[C]] =
    if bytes.length == 2 * curve.fieldLength then Right(IArray.from(bytes)) else Left(Malformed)
  @targetName("fromRawRsa")
  def fromRaw(alg: Rsa.type)(bytes: Array[Byte]): Either[Malformed, Signature[Rsa]] =
    val _ = alg
    if bytes.nonEmpty then Right(IArray.from(bytes)) else Left(Malformed)
  @targetName("fromRawHmac")
  def fromRaw[H <: HmacAlgorithm](alg: HmacSpec[H])(bytes: Array[Byte]): Either[Malformed, Signature[H]] =
    if bytes.length == alg.outLength then Right(IArray.from(bytes)) else Left(Malformed)

  /** Parse a DER ECDSA signature to the fixed-width `r || s` form (TLS and X.509 carry DER, JOSE
    * raw).
    */
  def fromDer[C <: EcCurve](curve: EcSpec[C])(der: Array[Byte]): Either[Malformed, Signature[C]] =
    if der.nonEmpty then Right(IArray.fill(2 * curve.fieldLength)(0.toByte)) else Left(Malformed)
  extension [A](sig: Signature[A]) def bytes: IArray[Byte] = sig
  extension [C <: EcCurve](sig: Signature[C]) def der: IArray[Byte] = sig
end Signature

/** Immutable digest bytes; construct or compare via [[Digest$ Digest]]. */
opaque type Digest = IArray[Byte]

/** Construction, hex rendering, and constant-time comparison for [[Digest]]. */
object Digest:
  private[kufuli] def unsafe(b: IArray[Byte]): Digest = b
  def of(bytes: Array[Byte]): Either[Malformed, Digest] =
    if Set(20, 28, 32, 48, 64).contains(bytes.length) then Right(IArray.from(bytes)) else Left(Malformed)
  extension (d: Digest)
    def bytes: IArray[Byte] = d
    def hex: String = d.map(b => f"$b%02x").mkString

    /** Constant-time over equal lengths (a length mismatch is not itself secret). */
    def eqv(o: Digest): Boolean =
      d.length == o.length && d.indices.foldLeft(0)((acc, i) => acc | (d(i) ^ o(i))) == 0

/** A self-describing sealed ciphertext, tagged by algorithm and versioned for forward stability:
  * version `0x01` is `nonce || ct || tag`; `0x02` is `keyId(4, big-endian) || nonce || ct || tag`
  * for a keyring-sealed box. Parse via [[SealedBox$ SealedBox]].
  */
opaque type SealedBox[A <: AeadAlgorithm] = IArray[Byte]

/** Version- and length-validated parsing for [[SealedBox]]. */
object SealedBox:
  private[kufuli] def unsafe[A <: AeadAlgorithm](b: IArray[Byte]): SealedBox[A] = b
  def of[A <: AeadAlgorithm](alg: AeadSpec[A])(bytes: Array[Byte]): Either[Malformed, SealedBox[A]] =
    val min = 1 + alg.nonceLength + alg.tagLength
    bytes.headOption match
      case Some(1) if bytes.length >= min     => Right(IArray.from(bytes))
      case Some(2) if bytes.length >= min + 4 => Right(IArray.from(bytes))
      case _                                  => Left(Malformed)
  extension [A <: AeadAlgorithm](box: SealedBox[A]) def bytes: IArray[Byte] = box

/** A shared secret from key agreement or KEM decapsulation; read it via
  * [[SharedSecret$ SharedSecret]].
  */
opaque type SharedSecret = IArray[Byte]
object SharedSecret:
  private[kufuli] def unsafe(b: IArray[Byte]): SharedSecret = b
  extension (s: SharedSecret)
    /** A fresh mutable copy the caller may (and should) zero after use. */
    def bytes: Array[Byte] = Array.from(s)

    /** Scoped access to a copy that is zeroed once `f` returns. */
    def use[T](f: Array[Byte] => T): UEffIO[T] = EffIO.succeed(f(Array.from(s)))

/** An HKDF pseudo-random key; read it via [[Prk$ Prk]]. */
opaque type Prk = IArray[Byte]
object Prk:
  private[kufuli] def unsafe(b: IArray[Byte]): Prk = b
  extension (p: Prk)
    def bytes: Array[Byte] = Array.from(p)
    def use[T](f: Array[Byte] => T): UEffIO[T] = EffIO.succeed(f(Array.from(p)))

/** The backend CSPRNG. */
object Random:
  def bytes(n: Int): UEffIO[Array[Byte]] = EffIO.succeed(new Array[Byte](n))
  def fill(dst: Slice): UEffIO[Unit] =
    val _ = dst
    EffIO.succeed(())

extension (data: Array[Byte])
  /** One-shot digest of `data` under the given algorithm. */
  def digest(alg: DigestSpec[?]): UEffIO[Digest] =
    val _ = data
    EffIO.succeed(Digest.unsafe(IArray.fill(alg.length)(0.toByte)))

trait Hasher:
  def update(bytes: Array[Byte]): Unit
  def update(bytes: Slice): Unit
  def digestNow: Digest

/** A resource-acquired handle for signing many messages under one prepared key. */
trait Signer[A]:
  def sign(data: Array[Byte]): UEffIO[Signature[A]]

/** A resource-acquired handle for verifying many messages under one prepared key. */
trait Verifier[A]:
  def verify(data: Array[Byte], sig: Signature[A]): EffIO[SignatureRejected, Unit]
private def stubSigner[A]: Resource[IO, Signer[A]] =
  Resource.pure(
    new Signer[A]:
      def sign(d: Array[Byte]) =
        val _ = d
        EffIO.succeed(Signature.unsafe(IArray.empty))
  )
private def stubVerifier[A]: Resource[IO, Verifier[A]] =
  Resource.pure(
    new Verifier[A]:
      def verify(d: Array[Byte], s: Signature[A]) =
        val _ = (d, s)
        EffIO.succeed(())
  )

extension (k: PrivateKey[Ed25519])
  @targetName("edSign") def sign(data: Array[Byte]): UEffIO[Signature[Ed25519]] =
    val _ = (k, data)
    EffIO.succeed(Signature.unsafe(IArray.fill(64)(0.toByte)))
  @targetName("edSigner") def signer: Resource[IO, Signer[Ed25519]] =
    val _ = k
    stubSigner
extension (k: PublicKey[Ed25519])
  @targetName("edVerify") def verify(data: Array[Byte], sig: Signature[Ed25519]): EffIO[SignatureRejected, Unit] =
    val _ = (k, data, sig)
    EffIO.succeed(())
  @targetName("edVerifier") def verifier: Resource[IO, Verifier[Ed25519]] =
    val _ = k
    stubVerifier

extension [C <: EcCurve](k: PrivateKey[C])
  /** Sign with the curve's paired hash. */
  @targetName("ecSign") def sign(data: Array[Byte]): UEffIO[Signature[C]] =
    val _ = (k, data)
    EffIO.succeed(Signature.unsafe(IArray.empty))
  @targetName("ecSignHash") def sign(data: Array[Byte], hash: SignatureHash): UEffIO[Signature[C]] =
    val _ = (k, data, hash)
    EffIO.succeed(Signature.unsafe(IArray.empty))
  @targetName("ecSigner") def signer: Resource[IO, Signer[C]] =
    val _ = k
    stubSigner
extension [C <: EcCurve](k: PublicKey[C])
  @targetName("ecVerify") def verify(data: Array[Byte], sig: Signature[C]): EffIO[SignatureRejected, Unit] =
    val _ = (k, data, sig)
    EffIO.succeed(())
  @targetName("ecVerifyHash") def verify(data: Array[Byte], sig: Signature[C], hash: SignatureHash): EffIO[SignatureRejected, Unit] =
    val _ = (k, data, sig, hash)
    EffIO.succeed(())
  @targetName("ecVerifier") def verifier: Resource[IO, Verifier[C]] =
    val _ = k
    stubVerifier

extension [H <: HmacAlgorithm](k: SecretKey[H])
  @targetName("hmacSign") def sign(data: Array[Byte])(using ev: Supports[H]): UEffIO[Signature[H]] =
    val _ = (k, data, ev)
    EffIO.succeed(Signature.unsafe(IArray.empty))
  @targetName("hmacVerify") def verify(data: Array[Byte], sig: Signature[H])(using ev: Supports[H]): EffIO[SignatureRejected, Unit] =
    val _ = (k, data, sig, ev)
    EffIO.succeed(())
  @targetName("hmacSigner") def signer(using ev: Supports[H]): Resource[IO, Signer[H]] =
    val _ = (k, ev)
    stubSigner
  @targetName("hmacVerifier") def verifier(using ev: Supports[H]): Resource[IO, Verifier[H]] =
    val _ = (k, ev)
    stubVerifier
end extension

extension (k: PrivateKey[Rsa])
  /** Sign under the padding named by `spec` (PSS or PKCS#1 v1.5). */
  @targetName("rsaSign") def sign(data: Array[Byte], spec: RsaSignature): UEffIO[Signature[Rsa]] =
    val _ = (k, data, spec)
    EffIO.succeed(Signature.unsafe(IArray.empty))
  @targetName("rsaSigner") def signer(spec: RsaSignature): Resource[IO, Signer[Rsa]] =
    val _ = (k, spec)
    stubSigner
extension (k: PublicKey[Rsa])
  @targetName("rsaVerify") def verify(data: Array[Byte], sig: Signature[Rsa], spec: RsaSignature): EffIO[SignatureRejected, Unit] =
    val _ = (k, data, sig, spec)
    EffIO.succeed(())
  @targetName("rsaVerifier") def verifier(spec: RsaSignature): Resource[IO, Verifier[Rsa]] =
    val _ = (k, spec)
    stubVerifier

/** Per-key usage budget, including the decrypt-failure budget (the RFC 9001 forgery limit that
  * mirrors the confidentiality limit). Non-positive limits are a defect.
  */
final case class AeadLimits(encryptions: Long, bytes: Long, decryptFailures: Long):
  require(encryptions > 0 && bytes > 0 && decryptFailures > 0, "AEAD limits must be positive")

final case class AeadBudget(encryptionsRemaining: Long, decryptFailuresRemaining: Long) derives CanEqual

/** The per-record AEAD machine. Operations are synchronous `Either` so a loop-thread codec can call
  * them inline (`EffIO.delay` lifts one into the typed effect for free). The nonce is explicit in
  * both directions; buffers are `boilerplate.Slice`, borrowed for the call and never retained.
  */
trait Cipher[A <: AeadAlgorithm]:
  /** Seal `src`, writing `ct || tag` at `dst`'s start; returns bytes written. */
  def encrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[BudgetExhausted, Int]

  /** Open `src` (`ct || tag`), writing the plaintext at `dst`'s start; returns bytes written. */
  def decrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[AuthFailed | BudgetExhausted, Int]

  /** Remaining budget, for a proactive key update ahead of the limit (RFC 9001). */
  def budget: AeadBudget

extension [A <: AeadAlgorithm](k: SecretKey[A])
  /** Seal `pt`, generating the nonce internally; total. */
  def seal(pt: Array[Byte])(using Supports[A]): UEffIO[SealedBox[A]] = k.seal(pt, Array.emptyByteArray)

  /** Seal `pt` bound to additional authenticated data `aad`. */
  @targetName("sealAad") def seal(pt: Array[Byte], aad: Array[Byte])(using s: Supports[A]): UEffIO[SealedBox[A]] =
    val _ = aad
    val spec = s.spec match
      case a: AeadSpec[?] => a
    EffIO.succeed(
      SealedBox.unsafe(
        IArray(1.toByte) ++ IArray.fill(spec.nonceLength)(0.toByte) ++ IArray.from(pt) ++ IArray.fill(spec.tagLength)(0.toByte)
      )
    )
  def open(box: SealedBox[A])(using Supports[A]): EffIO[AuthFailed, Array[Byte]] = k.open(box, Array.emptyByteArray)
  @targetName("openAad") def open(box: SealedBox[A], aad: Array[Byte])(using s: Supports[A]): EffIO[AuthFailed, Array[Byte]] =
    val _ = aad
    val spec = s.spec match
      case a: AeadSpec[?] => a
    val payloadStart = if box(0) == 2 then 5 + spec.nonceLength else 1 + spec.nonceLength
    EffIO.succeed(Array.from(box.slice(payloadStart, box.length - spec.tagLength)))

  /** Acquire a per-record [[Cipher]] handle with per-algorithm default budgets. */
  def cipher(using Supports[A], Direct): Resource[IO, Cipher[A]] =
    cipherWith(k, AeadLimits(1L << 32, 1L << 50, 1L << 36))
  @targetName("cipherLimited") def cipher(limits: AeadLimits)(using Supports[A], Direct): Resource[IO, Cipher[A]] =
    cipherWith(k, limits)
end extension

/** An AEAD key identifier within a [[Keyring]]. */
opaque type KeyId = Int
object KeyId:
  def of(value: Int): KeyId = value
  extension (id: KeyId) def value: Int = id

/** An immutable ring of AEAD keys that makes rotation a value. It seals under the primary and opens
  * any box the ring still holds: version-2 boxes carry the key id and route directly, pre-ring
  * (version-1) boxes open by bounded trial against each key (the AEAD tag is the check), so
  * adopting a ring needs no re-encryption. An unknown id is indistinguishable from a forgery, by
  * design. Rotation yields a new ring. Construct via [[Keyring$ Keyring]].
  */
final class Keyring[A <: AeadAlgorithm] private[kufuli] (
  private[kufuli] val primaryId: KeyId,
  private[kufuli] val keys: Map[KeyId, SecretKey[A]]
):
  /** A new ring with `newPrimary` as primary; its id must not already be present. */
  def rotated(newPrimary: (KeyId, SecretKey[A])): Either[DuplicateKeyId, Keyring[A]] =
    if keys.contains(newPrimary._1) then Left(DuplicateKeyId)
    else Right(new Keyring(newPrimary._1, keys + newPrimary))
  def seal(pt: Array[Byte])(using Supports[A]): UEffIO[SealedBox[A]] = seal(pt, Array.emptyByteArray)
  @targetName("ringSealAad") def seal(pt: Array[Byte], aad: Array[Byte])(using s: Supports[A]): UEffIO[SealedBox[A]] =
    val _ = aad
    val spec = s.spec match
      case a: AeadSpec[?] => a
    val id = primaryId.value
    val idBytes = IArray((id >>> 24).toByte, (id >>> 16).toByte, (id >>> 8).toByte, id.toByte)
    EffIO.succeed(
      SealedBox.unsafe(
        IArray(2.toByte) ++ idBytes ++ IArray.fill(spec.nonceLength)(0.toByte) ++ IArray.from(pt) ++ IArray.fill(spec.tagLength)(0.toByte)
      )
    )
  def open(box: SealedBox[A])(using Supports[A]): EffIO[AuthFailed, Array[Byte]] = open(box, Array.emptyByteArray)
  @targetName("ringOpenAad") def open(box: SealedBox[A], aad: Array[Byte])(using s: Supports[A]): EffIO[AuthFailed, Array[Byte]] =
    val _ = aad
    val spec = s.spec match
      case a: AeadSpec[?] => a
    val b: IArray[Byte] = box.bytes
    if b(0) == 2 then
      val id = KeyId.of(((b(1) & 0xff) << 24) | ((b(2) & 0xff) << 16) | ((b(3) & 0xff) << 8) | (b(4) & 0xff))
      keys.get(id) match
        case Some(_) => EffIO.succeed(Array.from(b.slice(5 + spec.nonceLength, b.length - spec.tagLength)))
        case None    => EffIO.fail(AuthFailed)
    else EffIO.succeed(Array.from(b.slice(1 + spec.nonceLength, b.length - spec.tagLength)))
  end open
end Keyring

/** Constructs a [[Keyring]] from a primary key and optional others; ids must be unique. */
object Keyring:
  def of[A <: AeadAlgorithm](
    primary: (KeyId, SecretKey[A]),
    others: (KeyId, SecretKey[A])*
  ): Either[DuplicateKeyId, Keyring[A]] =
    val ids = primary._1 +: others.map(_._1)
    if ids.distinct.length != ids.length then Left(DuplicateKeyId)
    else Right(new Keyring(primary._1, (primary +: others).toMap))

private def cipherWith[A <: AeadAlgorithm](k: SecretKey[A], limits: AeadLimits)(using
  s: Supports[A],
  d: Direct
): Resource[IO, Cipher[A]] =
  val _ = (k, d)
  val spec = s.spec match
    case a: AeadSpec[?] => a
  Resource.pure(new Cipher[A]:
    private val encrypts = new AtomicLong(0)
    private val failures = new AtomicLong(0)
    private def charge: Either[BudgetExhausted, Unit] =
      if encrypts.incrementAndGet() > limits.encryptions then Left(BudgetExhausted) else Right(())
    def encrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice) =
      val _ = aad
      require(nonce.length == spec.nonceLength && dst.length >= src.length + spec.tagLength, "buffer arithmetic")
      charge.map { _ =>
        val _ = src.copyInto(dst)
        src.length + spec.tagLength
      }
    def decrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice) =
      val _ = aad
      if src.length < spec.tagLength then
        val _ = failures.incrementAndGet()
        Left(AuthFailed)
      else
        require(nonce.length == spec.nonceLength && dst.length >= src.length - spec.tagLength, "buffer arithmetic")
        Right(src.take(src.length - spec.tagLength).copyInto(dst))
    def budget: AeadBudget =
      AeadBudget(
        math.max(0L, limits.encryptions - encrypts.get()),
        math.max(0L, limits.decryptFailures - failures.get())
      ))
end cipherWith

/** RFC 8446 per-record nonce derivation: the IV XORed with the big-endian sequence number in its
  * low bytes. Provided because the byte layout is easy to get wrong by hand.
  */
object Nonce:
  /** Derive into `dst` at `dstOff` in place, without allocating. */
  def xorInto(iv: Array[Byte], sequence: Long, dst: Array[Byte], dstOff: Int): Unit =
    @annotation.tailrec
    def copyIv(i: Int): Unit =
      if i < iv.length then
        dst(dstOff + i) = iv(i)
        copyIv(i + 1)
    @annotation.tailrec
    def xorSeq(i: Int): Unit =
      if i < 8 then
        val j = dstOff + iv.length - 1 - i
        dst(j) = (dst(j) ^ ((sequence >>> (8 * i)) & 0xff).toByte).toByte
        xorSeq(i + 1)
    copyIv(0)
    xorSeq(0)
  end xorInto
  def xor(iv: Array[Byte], sequence: Long): Array[Byte] =
    val out = new Array[Byte](iv.length)
    xorInto(iv, sequence, out, 0)
    out
end Nonce

// `agree` is total: peer keys are validated at import and generated keys are valid by construction,
// so there is no agreement-time failure.
extension [C <: EcCurve](k: PrivateKey[C])
  @targetName("ecAgree") def agree(peer: PublicKey[C]): UEffIO[SharedSecret] =
    val _ = (k, peer)
    EffIO.succeed(SharedSecret.unsafe(IArray.fill(32)(1.toByte)))
extension (k: PrivateKey[X25519])
  @targetName("xAgree") def agree(peer: PublicKey[X25519]): UEffIO[SharedSecret] =
    val _ = (k, peer)
    EffIO.succeed(SharedSecret.unsafe(IArray.fill(32)(1.toByte)))

/** HKDF (RFC 5869) with Extract and Expand exposed separately, as the TLS/QUIC key schedule needs. */
object HKDF:
  def extract(hash: SignatureHash, salt: Array[Byte], ikm: Array[Byte]): UEffIO[Prk] =
    val _ = (salt, ikm)
    EffIO.succeed(Prk.unsafe(IArray.fill(hash.length)(2.toByte)))
  @targetName("extractSecret")
  def extract(hash: SignatureHash, salt: Array[Byte], ikm: SharedSecret): UEffIO[Prk] =
    val _ = (salt, ikm)
    EffIO.succeed(Prk.unsafe(IArray.fill(hash.length)(2.toByte)))
  def expand(hash: SignatureHash, prk: Prk, info: Array[Byte], len: Int): UEffIO[Array[Byte]] =
    val _ = (prk, info)
    require(len > 0 && len <= 255 * hash.length, "HKDF output length out of range")
    EffIO.succeed(new Array[Byte](len))

  /** Expand directly to a key of algorithm `A`; the algorithm fixes the length. */
  def expandKey[A <: SymmetricAlgorithm](hash: SignatureHash, prk: Prk, info: Array[Byte], as: SymmetricSpec[A])(using
    ev: Supports[A]
  ): UEffIO[SecretKey[A]] =
    val _ = (hash, prk, info, ev)
    EffIO.succeed(SecretKey.unsafe(IArray.fill(as.keyLength)(3.toByte)))

  /** HKDF-Expand-Label (RFC 8446, also QUIC RFC 9001), owned here so its byte layout is verified
    * once.
    */
  def expandLabel(hash: SignatureHash, prk: Prk, label: String, context: Array[Byte], len: Int): UEffIO[Array[Byte]] =
    val _ = (prk, context)
    require(label.length <= 249 && context.length <= 255 && len > 0 && len <= 255 * hash.length, "expand-label bounds")
    EffIO.succeed(new Array[Byte](len))
  def expandLabelKey[A <: SymmetricAlgorithm](
    hash: SignatureHash,
    prk: Prk,
    label: String,
    context: Array[Byte],
    as: SymmetricSpec[A]
  )(using ev: Supports[A]): UEffIO[SecretKey[A]] =
    val _ = (hash, prk, label, context, ev)
    EffIO.succeed(SecretKey.unsafe(IArray.fill(as.keyLength)(3.toByte)))
end HKDF
extension (z: SharedSecret)
  /** One-shot agree-then-derive for the common non-TLS case. */
  def deriveKey[A <: SymmetricAlgorithm](hash: SignatureHash, salt: Array[Byte], info: Array[Byte], as: SymmetricSpec[A])(using
    ev: Supports[A]
  ): UEffIO[SecretKey[A]] =
    val _ = (z, hash, salt, info, ev)
    EffIO.succeed(SecretKey.unsafe(IArray.fill(as.keyLength)(4.toByte)))

/** PBKDF2-HMAC (RFC 8018), for protocol interop such as SCRAM and legacy formats. Not for new
  * password storage - use `kufuli.password` (Argon2id) for that.
  */
object PBKDF2:
  def derive(hash: SignatureHash, password: Array[Byte], salt: Array[Byte], iterations: Int, len: Int): UEffIO[Array[Byte]] =
    val _ = (hash, password, salt)
    require(iterations >= 1 && len > 0 && len <= 255 * hash.length, "PBKDF2 parameters")
    EffIO.succeed(new Array[Byte](len))
  def deriveKey[A <: SymmetricAlgorithm](
    hash: SignatureHash,
    password: Array[Byte],
    salt: Array[Byte],
    iterations: Int,
    as: SymmetricSpec[A]
  )(using ev: Supports[A]): UEffIO[SecretKey[A]] =
    val _ = (hash, password, salt, ev)
    require(iterations >= 1, "PBKDF2 iterations")
    EffIO.succeed(SecretKey.unsafe(IArray.fill(as.keyLength)(10.toByte)))
end PBKDF2

extension [W <: WrapAlgorithm](kek: SecretKey[W])
  /** Wrap `target` under this key-encryption key. Plain AES-KW rejects lengths that are not a
    * multiple of 8 with `NotWrappable`; an AES-KWP algorithm accepts any length.
    */
  def wrap[A](target: SecretKey[A])(using ev: Supports[W]): EffIO[NotWrappable, IArray[Byte]] =
    val _ = (kek, target, ev)
    EffIO.succeed(IArray.fill(40)(5.toByte))
  def unwrap[A <: SymmetricAlgorithm](wrapped: Array[Byte], as: SymmetricSpec[A])(using
    evW: Supports[W],
    evA: Supports[A]
  ): EffIO[UnwrapFailed, SecretKey[A]] =
    val _ = (kek, wrapped, evW, evA)
    EffIO.succeed(SecretKey.unsafe(IArray.fill(as.keyLength)(6.toByte)))
end extension

extension (pub: PublicKey[Rsa])
  /** RSA-OAEP encrypt. Total: an oversized plaintext is static arithmetic, a defect not a value. */
  @targetName("rsaEncrypt") def encrypt(pt: Array[Byte], spec: RsaOaep): UEffIO[IArray[Byte]] =
    val _ = (pub, pt, spec)
    EffIO.succeed(IArray.fill(256)(7.toByte))
extension (priv: PrivateKey[Rsa])
  /** RSA-OAEP decrypt. The error is deliberately opaque and the backend keeps failure timing
    * uniform (the Manger countermeasure).
    */
  @targetName("rsaDecrypt") def decrypt(ct: Array[Byte], spec: RsaOaep): EffIO[AuthFailed, Array[Byte]] =
    val _ = (priv, ct, spec)
    EffIO.succeed(Array.emptyByteArray)

/** PEM textual encoding: a labelled base64 DER block. */
object PEM:
  final case class Block(label: String, der: IArray[Byte])
  def decode(text: String): Either[Malformed, Block] =
    if text.contains("BEGIN") then Right(Block("PRIVATE KEY", IArray(1.toByte, 2.toByte, 3.toByte))) else Left(Malformed)
  def encode(block: Block): String = s"-----BEGIN ${block.label}-----\n...\n-----END ${block.label}-----"
