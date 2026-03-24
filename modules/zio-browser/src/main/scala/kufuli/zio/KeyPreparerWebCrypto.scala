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

import scala.scalajs.js

import zio.IO
import zio.ZIO

import _root_.kufuli.browser.internal.WebAlgorithm.*
import _root_.kufuli.browser.internal.WebCryptoGlobal
import _root_.kufuli.browser.internal.WebCryptoKey
import _root_.kufuli.browser.internal.WebPreparedKey
import _root_.kufuli.js.internal.ByteConversions
import _root_.kufuli.js.internal.JwkBuilder

import kufuli.CryptoKey
import kufuli.KufuliError
import kufuli.SecurityChecks
import kufuli.SignAlgorithm
import kufuli.Signing
import kufuli.Verifying
import kufuli.zio.KeyPreparer
import kufuli.zio.PreparedKey

/** Web Crypto (SubtleCrypto) implementation of [[kufuli.zio.KeyPreparer KeyPreparer]]. */
given KeyPreparer with

  extension (key: CryptoKey)

    def prepareSigning(algorithm: SignAlgorithm): IO[KufuliError, PreparedKey[Signing]] =
      prepare(key, algorithm, js.Array("sign")).map(PreparedKey.wrapKey[Signing])

    def prepareVerifying(algorithm: SignAlgorithm): IO[KufuliError, PreparedKey[Verifying]] =
      prepare(key, algorithm, js.Array("verify")).map(PreparedKey.wrapKey[Verifying])

private def prepare(key: CryptoKey, alg: SignAlgorithm, usages: js.Array[String]): IO[KufuliError, WebPreparedKey] =
  ZIO.fromEither(SecurityChecks.prePrepare(key, alg)).flatMap { _ =>
    alg match
      case SignAlgorithm.Ed448 =>
        ZIO.fail(KufuliError.UnsupportedAlgorithm("Ed448 is not supported by Web Crypto"))
      case _ =>
        webCryptoImportKey(key, alg, usages).map(WebPreparedKey(_, alg))
  }

private def webCryptoImportKey(
  key: CryptoKey,
  alg: SignAlgorithm,
  usages: js.Array[String]
): IO[KufuliError, WebCryptoKey] =
  ZIO
    .fromPromiseJS {
      key match
        case CryptoKey.Symmetric(bytes) =>
          WebCryptoGlobal.subtle.importKey("raw", ByteConversions.toUint8Array(bytes), alg.importParams, false, usages)
        case _ =>
          WebCryptoGlobal.subtle.importKey("jwk", JwkBuilder.toJwk(key), alg.importParams, false, usages)
    }
    .mapError(_ => KufuliError.InvalidKey("Web Crypto key import failed"))
