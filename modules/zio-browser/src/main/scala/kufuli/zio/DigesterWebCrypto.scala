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
import _root_.kufuli.js.internal.ByteConversions

import kufuli.DigestAlgorithm
import kufuli.KufuliError
import kufuli.zio.Digester

/** Web Crypto (SubtleCrypto) implementation of [[kufuli.zio.Digester Digester]]. */
given Digester with

  extension (data: Array[Byte])

    def digest(algorithm: DigestAlgorithm): IO[KufuliError, Array[Byte]] =
      ZIO
        .fromPromiseJS(WebCryptoGlobal.subtle.digest(algorithm.webCryptoName, ByteConversions.toUint8Array(data)))
        .map(ab => ByteConversions.toByteArray(new Uint8Array(ab)))
        .mapError(_ => KufuliError.DigestFailure("Web Crypto digest computation failed"))
