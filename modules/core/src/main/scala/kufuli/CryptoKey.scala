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

import java.util.Arrays

/** Cryptographic key ADT. Cases are `private[kufuli]` to enforce construction via smart
  * constructors that validate security invariants. External consumers interact with `CryptoKey` as
  * an opaque handle — construction via companion smart constructors, equality via
  * [[CryptoKey$.contentEquals]].
  *
  * All byte arrays are defensively cloned on construction to prevent external mutation of key
  * material. `CanEqual` is intentionally omitted: the `==` operator would use reference equality
  * for array fields, producing silently wrong results. Under strict equality this is a compile
  * error, forcing use of [[CryptoKey$.contentEquals]] for value-based comparison.
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
    SecurityChecks.validatePointOnCurve(curve, x, y).map(_ => EcPublic(curve, x.clone(), y.clone()))

  def ecPrivate(curve: EcCurve, x: Array[Byte], y: Array[Byte], d: Array[Byte]): Either[KufuliError, CryptoKey] =
    SecurityChecks.validatePointOnCurve(curve, x, y).map(_ => EcPrivate(curve, x.clone(), y.clone(), d.clone()))

  def okpPublic(curve: OkpCurve, x: Array[Byte]): Either[KufuliError, CryptoKey] =
    SecurityChecks.validateOkpKeyLength(curve, x).map(_ => OkpPublic(curve, x.clone()))

  def okpPrivate(curve: OkpCurve, x: Array[Byte], d: Array[Byte]): Either[KufuliError, CryptoKey] =
    SecurityChecks.validateOkpKeyLength(curve, x).map(_ => OkpPrivate(curve, x.clone(), d.clone()))

  /** Value-based equality for two crypto keys. Compares all byte array fields using constant-length
    * comparison via `java.util.Arrays.equals`.
    */
  def contentEquals(a: CryptoKey, b: CryptoKey): Boolean =
    (a, b) match
      case (Symmetric(ab), Symmetric(bb))         => Arrays.equals(ab, bb)
      case (RsaPublic(am, ae), RsaPublic(bm, be)) => Arrays.equals(am, bm) && Arrays.equals(ae, be)
      case (RsaPrivate(am, ae, ad, ap, aq, adp, adq, aqi), RsaPrivate(bm, be, bd, bp, bq, bdp, bdq, bqi)) =>
        Arrays.equals(am, bm) && Arrays.equals(ae, be) && Arrays.equals(ad, bd) &&
        Arrays.equals(ap, bp) && Arrays.equals(aq, bq) && Arrays.equals(adp, bdp) &&
        Arrays.equals(adq, bdq) && Arrays.equals(aqi, bqi)
      case (EcPublic(ac, ax, ay), EcPublic(bc, bx, by))           => ac == bc && Arrays.equals(ax, bx) && Arrays.equals(ay, by)
      case (EcPrivate(ac, ax, ay, ad), EcPrivate(bc, bx, by, bd)) =>
        ac == bc && Arrays.equals(ax, bx) && Arrays.equals(ay, by) && Arrays.equals(ad, bd)
      case (OkpPublic(ac, ax), OkpPublic(bc, bx))           => ac == bc && Arrays.equals(ax, bx)
      case (OkpPrivate(ac, ax, ad), OkpPrivate(bc, bx, bd)) => ac == bc && Arrays.equals(ax, bx) && Arrays.equals(ad, bd)
      case _                                                => false
end CryptoKey
