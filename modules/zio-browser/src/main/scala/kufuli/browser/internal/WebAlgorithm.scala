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
package kufuli.browser.internal

import scala.scalajs.js

import kufuli.DigestAlgorithm
import kufuli.SignAlgorithm

/** Web Crypto algorithm parameter construction for `importKey`, `sign`, and `verify` operations. */
private[kufuli] object WebAlgorithm:

  extension (alg: SignAlgorithm)

    /** Algorithm parameter object for `subtle.importKey`. */
    def importParams: js.Any = alg match
      case SignAlgorithm.HmacSha256      => js.Dynamic.literal(name = "HMAC", hash = "SHA-256")
      case SignAlgorithm.HmacSha384      => js.Dynamic.literal(name = "HMAC", hash = "SHA-384")
      case SignAlgorithm.HmacSha512      => js.Dynamic.literal(name = "HMAC", hash = "SHA-512")
      case SignAlgorithm.RsaPkcs1Sha256  => js.Dynamic.literal(name = "RSASSA-PKCS1-v1_5", hash = "SHA-256")
      case SignAlgorithm.RsaPkcs1Sha384  => js.Dynamic.literal(name = "RSASSA-PKCS1-v1_5", hash = "SHA-384")
      case SignAlgorithm.RsaPkcs1Sha512  => js.Dynamic.literal(name = "RSASSA-PKCS1-v1_5", hash = "SHA-512")
      case SignAlgorithm.RsaPssSha256    => js.Dynamic.literal(name = "RSA-PSS", hash = "SHA-256")
      case SignAlgorithm.RsaPssSha384    => js.Dynamic.literal(name = "RSA-PSS", hash = "SHA-384")
      case SignAlgorithm.RsaPssSha512    => js.Dynamic.literal(name = "RSA-PSS", hash = "SHA-512")
      case SignAlgorithm.EcdsaP256Sha256 => js.Dynamic.literal(name = "ECDSA", namedCurve = "P-256")
      case SignAlgorithm.EcdsaP384Sha384 => js.Dynamic.literal(name = "ECDSA", namedCurve = "P-384")
      case SignAlgorithm.EcdsaP521Sha512 => js.Dynamic.literal(name = "ECDSA", namedCurve = "P-521")
      case SignAlgorithm.Ed25519         => js.Dynamic.literal(name = "Ed25519")
      case SignAlgorithm.Ed448           => js.Dynamic.literal(name = "Ed25519") // unreachable; Ed448 rejected by prePrepare

    /** Algorithm parameter object for `subtle.sign` and `subtle.verify`. */
    def signParams: js.Any = alg match
      case SignAlgorithm.HmacSha256 | SignAlgorithm.HmacSha384 | SignAlgorithm.HmacSha512 =>
        js.Dynamic.literal(name = "HMAC")
      case SignAlgorithm.RsaPkcs1Sha256 | SignAlgorithm.RsaPkcs1Sha384 | SignAlgorithm.RsaPkcs1Sha512 =>
        js.Dynamic.literal(name = "RSASSA-PKCS1-v1_5")
      case SignAlgorithm.RsaPssSha256    => js.Dynamic.literal(name = "RSA-PSS", saltLength = 32)
      case SignAlgorithm.RsaPssSha384    => js.Dynamic.literal(name = "RSA-PSS", saltLength = 48)
      case SignAlgorithm.RsaPssSha512    => js.Dynamic.literal(name = "RSA-PSS", saltLength = 64)
      case SignAlgorithm.EcdsaP256Sha256 => js.Dynamic.literal(name = "ECDSA", hash = "SHA-256")
      case SignAlgorithm.EcdsaP384Sha384 => js.Dynamic.literal(name = "ECDSA", hash = "SHA-384")
      case SignAlgorithm.EcdsaP521Sha512 => js.Dynamic.literal(name = "ECDSA", hash = "SHA-512")
      case SignAlgorithm.Ed25519         => js.Dynamic.literal(name = "Ed25519")
      case SignAlgorithm.Ed448           => js.Dynamic.literal(name = "Ed25519") // unreachable
  end extension

  extension (alg: DigestAlgorithm)

    /** Web Crypto algorithm string for `subtle.digest`. */
    def webCryptoName: String = alg match
      case DigestAlgorithm.Sha1   => "SHA-1"
      case DigestAlgorithm.Sha256 => "SHA-256"
      case DigestAlgorithm.Sha384 => "SHA-384"
      case DigestAlgorithm.Sha512 => "SHA-512"

end WebAlgorithm
