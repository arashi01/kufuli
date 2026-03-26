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

/** Octet key pair curve identifiers for EdDSA signing per RFC 8037 (January 2018) and RFC 8032
  * (January 2017), and X25519 key agreement per RFC 7748 (January 2016).
  */
enum OkpCurve derives CanEqual:
  case Ed25519, Ed448, X25519

object OkpCurve:

  extension (curve: OkpCurve)

    /** Public key byte length per RFC 8032 (January 2017) and RFC 7748 (January 2016). */
    inline def keyLength: Int = curve match
      case Ed25519 | X25519 => 32
      case Ed448            => 57

    /** Signature byte length per RFC 8032 (January 2017). Returns `None` for key agreement curves
      * (X25519) which do not produce signatures.
      */
    def signatureLength: Option[Int] = curve match
      case Ed25519 => Some(64)
      case Ed448   => Some(114)
      case X25519  => None

    /** JWK "crv" parameter value per RFC 8037 (January 2018) ss2 and RFC 7748 (January 2016). */
    inline def jwkName: String = curve match
      case Ed25519 => "Ed25519"
      case Ed448   => "Ed448"
      case X25519  => "X25519"
  end extension
end OkpCurve
