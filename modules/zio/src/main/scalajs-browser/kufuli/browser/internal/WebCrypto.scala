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
import scala.scalajs.js.annotation.JSGlobal
import scala.scalajs.js.typedarray.ArrayBuffer
import scala.scalajs.js.typedarray.Uint8Array

/** Typed facade for the browser Web Crypto API (`crypto.subtle`). */
@js.native
@JSGlobal("crypto")
private[kufuli] object WebCryptoGlobal extends js.Object:
  val subtle: SubtleCrypto = js.native

/** Typed facade for `SubtleCrypto` - the cryptographic operations interface. */
@js.native
private[kufuli] trait SubtleCrypto extends js.Object:

  def importKey(
    format: String,
    keyData: js.Any,
    algorithm: js.Any,
    extractable: Boolean,
    keyUsages: js.Array[String]
  ): js.Promise[WebCryptoKey] = js.native

  def sign(algorithm: js.Any, key: WebCryptoKey, data: Uint8Array): js.Promise[ArrayBuffer] = js.native

  def verify(algorithm: js.Any, key: WebCryptoKey, signature: Uint8Array, data: Uint8Array): js.Promise[Boolean] = js.native

  def digest(algorithm: String, data: Uint8Array): js.Promise[ArrayBuffer] = js.native
end SubtleCrypto

/** Web Crypto `CryptoKey` - opaque key handle returned by `importKey`. */
@js.native
private[kufuli] trait WebCryptoKey extends js.Object
