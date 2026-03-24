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

import java.math.BigInteger

/** Weierstrass curve parameters (a, b) for the equation y^2 = x^3 + ax + b mod p. */
final private[kufuli] case class CurveParams(a: BigInteger, b: BigInteger)

/** NIST FIPS 186-5 (February 2023) / SEC 2 v2 (January 2010) elliptic curve constants. All values
  * are cross-platform pure BigInteger constants - no JCA dependency.
  */
private[kufuli] object EcCurveConstants:

  // -- P-256 (secp256r1) --

  private val p256Order: BigInteger =
    BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

  private val p256Prime: BigInteger =
    BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)

  private val p256A: BigInteger =
    BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)

  private val p256B: BigInteger =
    BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)

  // -- P-384 (secp384r1) --

  private val p384Order: BigInteger =
    BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16)

  private val p384Prime: BigInteger =
    BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16)

  private val p384A: BigInteger =
    BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", 16)

  private val p384B: BigInteger =
    BigInteger("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", 16)

  // -- P-521 (secp521r1) --

  private val p521Order: BigInteger = BigInteger(
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
    16
  )

  private val p521Prime: BigInteger = BigInteger(
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    16
  )

  private val p521A: BigInteger = BigInteger(
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
    16
  )

  private val p521B: BigInteger = BigInteger(
    "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
    16
  )

  // -- Accessors --

  def order(curve: EcCurve): BigInteger = curve match
    case EcCurve.P256 => p256Order
    case EcCurve.P384 => p384Order
    case EcCurve.P521 => p521Order

  def prime(curve: EcCurve): BigInteger = curve match
    case EcCurve.P256 => p256Prime
    case EcCurve.P384 => p384Prime
    case EcCurve.P521 => p521Prime

  def params(curve: EcCurve): CurveParams = curve match
    case EcCurve.P256 => CurveParams(p256A, p256B)
    case EcCurve.P384 => CurveParams(p384A, p384B)
    case EcCurve.P521 => CurveParams(p521A, p521B)

end EcCurveConstants
