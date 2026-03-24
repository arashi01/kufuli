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

import zio.IO
import zio.ZIO

import _root_.kufuli.browser.internal.WebAlgorithm.*
import _root_.kufuli.browser.internal.WebCryptoGlobal
import _root_.kufuli.browser.internal.WebPreparedKey
import _root_.kufuli.js.internal.ByteConversions

import kufuli.KufuliError
import kufuli.SecurityChecks
import kufuli.Verifying
import kufuli.zio.PreparedKey
import kufuli.zio.Verifier

/** Web Crypto (SubtleCrypto) implementation of [[kufuli.zio.Verifier Verifier]]. */
given Verifier with

  extension (key: PreparedKey[Verifying])

    def verify(data: Array[Byte], signature: Array[Byte]): IO[KufuliError, Unit] =
      PreparedKey.unwrapKey[Verifying](key) match
        case webKey: WebPreparedKey =>
          val alg = webKey.algorithm
          ZIO.fromEither(SecurityChecks.preVerify(alg, signature)).flatMap { _ =>
            val dataArr = ByteConversions.toUint8Array(data)
            val sigArr = ByteConversions.toUint8Array(signature)
            ZIO
              .fromPromiseJS(WebCryptoGlobal.subtle.verify(alg.signParams, webKey.cryptoKey, sigArr, dataArr))
              .mapError(_ => KufuliError.InvalidSignature("Signature verification failed"))
              .flatMap { valid =>
                ZIO.cond(valid, (), KufuliError.InvalidSignature("Signature verification failed"))
              }
          }
        case _ => ZIO.fail(KufuliError.VerificationFailure("Unexpected prepared key type"))
  end extension
end given
