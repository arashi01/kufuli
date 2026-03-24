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
package kufuli.zio

import scala.scalajs.js.typedarray.Uint8Array

import zio.IO
import zio.ZIO

import _root_.kufuli.browser.internal.WebAlgorithm.*
import _root_.kufuli.browser.internal.WebCryptoGlobal
import _root_.kufuli.browser.internal.WebPreparedKey
import _root_.kufuli.js.internal.ByteConversions

import kufuli.KufuliError
import kufuli.Signing
import kufuli.zio.PreparedKey
import kufuli.zio.Signer

/** Web Crypto (SubtleCrypto) implementation of [[kufuli.zio.Signer Signer]]. */
given Signer with

  extension (key: PreparedKey[Signing])

    def sign(data: Array[Byte]): IO[KufuliError, Array[Byte]] =
      PreparedKey.unwrapKey[Signing](key) match
        case webKey: WebPreparedKey =>
          val dataArr = ByteConversions.toUint8Array(data)
          ZIO
            .fromPromiseJS(WebCryptoGlobal.subtle.sign(webKey.algorithm.signParams, webKey.cryptoKey, dataArr))
            .map(ab => ByteConversions.toByteArray(new Uint8Array(ab)))
            .mapError(_ => KufuliError.SignatureFailure("Web Crypto signing failed"))
        case _ => ZIO.fail(KufuliError.SignatureFailure("Unexpected prepared key type"))
  end extension
end given
