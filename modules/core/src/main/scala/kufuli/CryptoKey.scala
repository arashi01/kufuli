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

/** Cryptographic key ADT. Cases are `private[kufuli]` to enforce construction via smart
  * constructors that validate security invariants. External consumers interact with `CryptoKey` as
  * an opaque handle - construction via companion smart constructors, equality via
  * [[CryptoKey$.contentEquals]].
  *
  * All byte arrays are defensively cloned on construction to prevent external mutation of key
  * material. `CanEqual` is intentionally omitted: the `==` operator would use reference equality
  * for array fields, producing silently wrong results. Under strict equality this is a compile
  * error, forcing use of [[CryptoKey$.contentEquals]] for value-based comparison.
  *
  * '''Sensitive memory threat model:''' Key material is held in JVM-managed `Array[Byte]` (on JVM)
  * or GC-managed memory (on JS/Native). It is NOT zeroed after use and may persist in memory until
  * garbage-collected. On Native, zone-allocated copies used for C FFI calls are freed when the
  * `Zone` exits, but are also not explicitly zeroed. This is a known limitation: JVM and JS
  * runtimes do not provide reliable memory zeroing guarantees. Applications handling key material
  * with stricter requirements should manage key lifecycle at a higher layer.
  */
enum CryptoKey:
  private[kufuli] case Symmetric(bytes: Array[Byte])
  private[kufuli] case RsaPublic(modulus: Array[Byte], exponent: Array[Byte])
  private[kufuli] case RsaPrivate(
    modulus: Array[Byte],
    exponent: Array[Byte],
    d: Array[Byte],
    p: Array[Byte],
    q: Array[Byte],
    dp: Array[Byte],
    dq: Array[Byte],
    qi: Array[Byte]
  )
  private[kufuli] case EcPublic(curve: EcCurve, x: Array[Byte], y: Array[Byte])
  private[kufuli] case EcPrivate(curve: EcCurve, x: Array[Byte], y: Array[Byte], d: Array[Byte])
  private[kufuli] case OkpPublic(curve: OkpCurve, x: Array[Byte])
  private[kufuli] case OkpPrivate(curve: OkpCurve, x: Array[Byte], d: Array[Byte])
end CryptoKey

/** Smart constructors for [[CryptoKey]], providing Phase 1 security validation. */
object CryptoKey:

  def symmetric(bytes: Array[Byte]): Either[KufuliError, CryptoKey] =
    Either.cond(
      bytes.length > 0,
      Symmetric(bytes.clone()),
      KufuliError.InvalidKey("Symmetric key must not be empty")
    )

  def rsaPublic(modulus: Array[Byte], exponent: Array[Byte]): Either[KufuliError, CryptoKey] =
    SecurityChecks.validateRsaKeySize(modulus).map(_ => RsaPublic(modulus.clone(), exponent.clone()))

  def rsaPrivate(
    modulus: Array[Byte],
    exponent: Array[Byte],
    d: Array[Byte],
    p: Array[Byte],
    q: Array[Byte],
    dp: Array[Byte],
    dq: Array[Byte],
    qi: Array[Byte]
  ): Either[KufuliError, CryptoKey] =
    for
      _ <- SecurityChecks.validateRsaKeySize(modulus)
      _ <- SecurityChecks.validateRsaCrt(modulus, p, q)
    yield RsaPrivate(modulus.clone(), exponent.clone(), d.clone(), p.clone(), q.clone(), dp.clone(), dq.clone(), qi.clone())

  def ecPublic(curve: EcCurve, x: Array[Byte], y: Array[Byte]): Either[KufuliError, CryptoKey] =
    SecurityChecks.validatePointOnCurve(curve, x, y).map { _ =>
      val len = curve.componentLength
      EcPublic(curve, padToLength(x, len), padToLength(y, len))
    }

  def ecPrivate(curve: EcCurve, x: Array[Byte], y: Array[Byte], d: Array[Byte]): Either[KufuliError, CryptoKey] =
    for
      _ <- SecurityChecks.validatePointOnCurve(curve, x, y)
      _ <- SecurityChecks.validateEcPrivateScalar(curve, d)
    yield
      val len = curve.componentLength
      EcPrivate(curve, padToLength(x, len), padToLength(y, len), padToLength(d, len))

  def okpPublic(curve: OkpCurve, x: Array[Byte]): Either[KufuliError, CryptoKey] =
    SecurityChecks.validateOkpKeyLength(curve, x).map(_ => OkpPublic(curve, x.clone()))

  def okpPrivate(curve: OkpCurve, x: Array[Byte], d: Array[Byte]): Either[KufuliError, CryptoKey] =
    for
      _ <- SecurityChecks.validateOkpKeyLength(curve, x)
      _ <- SecurityChecks.validateOkpPrivateKeyLength(curve, d)
    yield OkpPrivate(curve, x.clone(), d.clone())

  extension (key: CryptoKey)

    /** Structural classification of this key. */
    def keyType: KeyType = key match
      case _: Symmetric                 => KeyType.Symmetric
      case _: RsaPublic | _: RsaPrivate => KeyType.Rsa
      case _: EcPublic | _: EcPrivate   => KeyType.Ec
      case _: OkpPublic | _: OkpPrivate => KeyType.Okp

    /** The associated EC curve, if this is an EC key. */
    def ecCurve: Option[EcCurve] = key match
      case k: EcPublic  => Some(k.curve)
      case k: EcPrivate => Some(k.curve)
      case _            => None

    /** The associated OKP curve, if this is an OKP key. */
    def okpCurve: Option[OkpCurve] = key match
      case k: OkpPublic  => Some(k.curve)
      case k: OkpPrivate => Some(k.curve)
      case _             => None

    /** Whether this key contains private material. Returns `true` for symmetric, RSA private, EC
      * private, and OKP private keys.
      */
    def isPrivate: Boolean = key match
      case _: Symmetric | _: RsaPrivate | _: EcPrivate | _: OkpPrivate => true
      case _                                                           => false
  end extension

  /** Value-based equality for two crypto keys. All byte array fields are compared using
    * constant-time comparison to prevent timing side-channel leakage of key material.
    */
  def contentEquals(a: CryptoKey, b: CryptoKey): Boolean =
    (a, b) match
      case (Symmetric(ab), Symmetric(bb))         => ConstantTime.equals(ab, bb)
      case (RsaPublic(am, ae), RsaPublic(bm, be)) =>
        ConstantTime.equals(am, bm) & ConstantTime.equals(ae, be)
      case (RsaPrivate(am, ae, ad, ap, aq, adp, adq, aqi), RsaPrivate(bm, be, bd, bp, bq, bdp, bdq, bqi)) =>
        ConstantTime.equals(am, bm) & ConstantTime.equals(ae, be) & ConstantTime.equals(ad, bd) &
          ConstantTime.equals(ap, bp) & ConstantTime.equals(aq, bq) & ConstantTime.equals(adp, bdp) &
          ConstantTime.equals(adq, bdq) & ConstantTime.equals(aqi, bqi)
      case (EcPublic(ac, ax, ay), EcPublic(bc, bx, by)) =>
        (ac == bc) & ConstantTime.equals(ax, bx) & ConstantTime.equals(ay, by)
      case (EcPrivate(ac, ax, ay, ad), EcPrivate(bc, bx, by, bd)) =>
        (ac == bc) & ConstantTime.equals(ax, bx) & ConstantTime.equals(ay, by) & ConstantTime.equals(ad, bd)
      case (OkpPublic(ac, ax), OkpPublic(bc, bx))           => (ac == bc) & ConstantTime.equals(ax, bx)
      case (OkpPrivate(ac, ax, ad), OkpPrivate(bc, bx, bd)) => (ac == bc) & ConstantTime.equals(ax, bx) & ConstantTime.equals(ad, bd)
      case _                                                => false

  /** Normalises a big-endian unsigned integer byte array to exactly `len` bytes: strips leading
    * zeros then left-pads with zeros. This ensures EC coordinate and scalar arrays are stored at
    * the canonical length for their curve, which is required for correct DER encoding of
    * uncompressed EC points (04 || x || y) per SEC 1 v2 (May 2009) ss2.3.3.
    */
  private def padToLength(bytes: Array[Byte], len: Int): Array[Byte] =
    val stripped = bytes.dropWhile(_ == 0)
    if stripped.length == len then stripped.clone()
    else if stripped.length < len then
      val out = new Array[Byte](len)
      System.arraycopy(stripped, 0, out, len - stripped.length, stripped.length)
      out
    else throw AssertionError(s"EC component $len bytes expected after validation, got ${stripped.length}") // scalafix:ok
end CryptoKey
