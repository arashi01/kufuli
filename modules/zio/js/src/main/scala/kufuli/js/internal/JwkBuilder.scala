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
package kufuli.js.internal

import scala.scalajs.js

import kufuli.CryptoKey

/** Constructs JS JWK objects from CryptoKey byte arrays for Node.js key import. All
  * `js.Dynamic.literal` usage is isolated here.
  */
private[kufuli] object JwkBuilder:

  /** Builds a JWK object for Node.js key import. */
  def toJwk(key: CryptoKey): js.Object =
    // scalafix:off DisableSyntax.asInstanceOf; Scala.js js.Dynamic.literal -> typed js.Object coercion
    val jwk: js.Dynamic = key match
      case CryptoKey.Symmetric(bytes) =>
        js.Dynamic.literal(
          kty = "oct",
          k = Base64Url.encode(bytes)
        )

      case CryptoKey.RsaPublic(modulus, exponent) =>
        js.Dynamic.literal(
          kty = "RSA",
          n = Base64Url.encode(modulus),
          e = Base64Url.encode(exponent)
        )

      case CryptoKey.RsaPrivate(modulus, exponent, d, p, q, dp, dq, qi) =>
        js.Dynamic.literal(
          kty = "RSA",
          n = Base64Url.encode(modulus),
          e = Base64Url.encode(exponent),
          d = Base64Url.encode(d),
          p = Base64Url.encode(p),
          q = Base64Url.encode(q),
          dp = Base64Url.encode(dp),
          dq = Base64Url.encode(dq),
          qi = Base64Url.encode(qi)
        )

      case CryptoKey.EcPublic(curve, x, y) =>
        js.Dynamic.literal(
          kty = "EC",
          crv = curve.jwkName,
          x = Base64Url.encode(x),
          y = Base64Url.encode(y)
        )

      case CryptoKey.EcPrivate(curve, x, y, d) =>
        js.Dynamic.literal(
          kty = "EC",
          crv = curve.jwkName,
          x = Base64Url.encode(x),
          y = Base64Url.encode(y),
          d = Base64Url.encode(d)
        )

      case CryptoKey.OkpPublic(curve, x) =>
        js.Dynamic.literal(
          kty = "OKP",
          crv = curve.jwkName,
          x = Base64Url.encode(x)
        )

      case CryptoKey.OkpPrivate(curve, x, d) =>
        js.Dynamic.literal(
          kty = "OKP",
          crv = curve.jwkName,
          x = Base64Url.encode(x),
          d = Base64Url.encode(d)
        )
    jwk.asInstanceOf[js.Object]
    // scalafix:on
  end toJwk

end JwkBuilder
