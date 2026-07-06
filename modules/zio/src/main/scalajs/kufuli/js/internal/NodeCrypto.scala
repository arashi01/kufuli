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
import scala.scalajs.js.annotation.JSImport
import scala.scalajs.js.typedarray.Uint8Array

/** Typed facades for the Node.js `crypto` module. */
@js.native
@JSImport("crypto", JSImport.Namespace)
private[kufuli] object NodeCrypto extends js.Object:

  def createPublicKey(key: JwkKeyInput): KeyObject = js.native

  def createPrivateKey(key: JwkKeyInput): KeyObject = js.native

  def createSecretKey(key: Uint8Array): KeyObject = js.native

  /** Signs data. `algorithm` is `undefined` for EdDSA. */
  def sign(algorithm: js.UndefOr[String], data: Uint8Array, key: KeyObject): NodeBuffer = js.native

  /** Signs data with key options (for RSA-PSS padding, ECDSA dsaEncoding). */
  def sign(algorithm: String, data: Uint8Array, key: SignKeyOptions): NodeBuffer = js.native

  /** Verifies a signature. `algorithm` is `undefined` for EdDSA. */
  def verify(algorithm: js.UndefOr[String], data: Uint8Array, key: KeyObject, signature: Uint8Array): Boolean =
    js.native

  /** Verifies a signature with key options (for RSA-PSS, ECDSA). */
  def verify(algorithm: String, data: Uint8Array, key: VerifyKeyOptions, signature: Uint8Array): Boolean = js.native

  def createHash(algorithm: String): Hash = js.native

  def createHmac(algorithm: String, key: KeyObject): Hmac = js.native

  def timingSafeEqual(a: Uint8Array, b: Uint8Array): Boolean = js.native

  val constants: CryptoConstants = js.native
end NodeCrypto

/** Node.js `KeyObject` - opaque key handle created by `create*Key` functions. */
@js.native
private[kufuli] trait KeyObject extends js.Object

/** Node.js `Hash` instance from `createHash`. */
@js.native
private[kufuli] trait Hash extends js.Object:
  def update(data: Uint8Array): Hash = js.native
  def digest(): NodeBuffer = js.native

/** Node.js `Hmac` instance from `createHmac`. */
@js.native
private[kufuli] trait Hmac extends js.Object:
  def update(data: Uint8Array): Hmac = js.native
  def digest(): NodeBuffer = js.native

/** Node.js `Buffer` - extends `Uint8Array` at runtime. */
@js.native
private[kufuli] trait NodeBuffer extends Uint8Array

/** Node.js `crypto.constants` for RSA padding modes. */
@js.native
private[kufuli] trait CryptoConstants extends js.Object:
  val RSA_PKCS1_PSS_PADDING: Int = js.native
  val RSA_PSS_SALTLEN_DIGEST: Int = js.native

/** Input object for JWK key import via `createPublicKey` / `createPrivateKey`. */
private[kufuli] trait JwkKeyInput extends js.Object:
  val key: js.Object
  val format: String

private[kufuli] object JwkKeyInput:

  def apply(jwk: js.Object): JwkKeyInput =
    // scalafix:off DisableSyntax.asInstanceOf; Scala.js js.Dynamic.literal -> typed trait coercion
    js.Dynamic.literal(key = jwk, format = "jwk").asInstanceOf[JwkKeyInput]
    // scalafix:on

/** Key options for `crypto.sign` with RSA-PSS or ECDSA. */
private[kufuli] trait SignKeyOptions extends js.Object:
  val key: KeyObject

private[kufuli] object SignKeyOptions:

  /** Creates PSS signing options. */
  def pss(keyObject: KeyObject, padding: Int, saltLength: Int): SignKeyOptions =
    // scalafix:off DisableSyntax.asInstanceOf; Scala.js js.Dynamic.literal -> typed trait coercion
    js.Dynamic.literal(key = keyObject, padding = padding, saltLength = saltLength).asInstanceOf[SignKeyOptions]
    // scalafix:on

  /** Creates ECDSA signing options with ieee-p1363 encoding. */
  def ecdsa(keyObject: KeyObject): SignKeyOptions =
    // scalafix:off DisableSyntax.asInstanceOf; Scala.js js.Dynamic.literal -> typed trait coercion
    js.Dynamic.literal(key = keyObject, dsaEncoding = "ieee-p1363").asInstanceOf[SignKeyOptions]
    // scalafix:on
end SignKeyOptions

/** Key options for `crypto.verify` with RSA-PSS or ECDSA. */
private[kufuli] trait VerifyKeyOptions extends js.Object:
  val key: KeyObject

private[kufuli] object VerifyKeyOptions:

  /** Creates PSS verification options. */
  def pss(keyObject: KeyObject, padding: Int, saltLength: Int): VerifyKeyOptions =
    // scalafix:off DisableSyntax.asInstanceOf; Scala.js js.Dynamic.literal -> typed trait coercion
    js.Dynamic.literal(key = keyObject, padding = padding, saltLength = saltLength).asInstanceOf[VerifyKeyOptions]
    // scalafix:on

  /** Creates ECDSA verification options with ieee-p1363 encoding. */
  def ecdsa(keyObject: KeyObject): VerifyKeyOptions =
    // scalafix:off DisableSyntax.asInstanceOf; Scala.js js.Dynamic.literal -> typed trait coercion
    js.Dynamic.literal(key = keyObject, dsaEncoding = "ieee-p1363").asInstanceOf[VerifyKeyOptions]
    // scalafix:on
end VerifyKeyOptions
