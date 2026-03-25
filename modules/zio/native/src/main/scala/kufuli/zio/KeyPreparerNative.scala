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

import _root_.kufuli.native.internal.DerCodec
import _root_.kufuli.native.internal.NativeAlgorithmId
import _root_.kufuli.native.internal.NativePreparedKey

import kufuli.CryptoKey
import kufuli.KufuliError
import kufuli.SecurityChecks
import kufuli.SignAlgorithm
import kufuli.Signing
import kufuli.Verifying

/** Native (OpenSSL / Security.framework / BCrypt) implementation of [[KeyPreparer]]. */
given KeyPreparer with

  extension (key: CryptoKey)

    def prepareSigning(algorithm: SignAlgorithm): IO[KufuliError, PreparedKey[Signing]] =
      prepareNative(key, algorithm).map(PreparedKey.wrapKey[Signing])

    def prepareVerifying(algorithm: SignAlgorithm): IO[KufuliError, PreparedKey[Verifying]] =
      prepareNative(key, algorithm).map(PreparedKey.wrapKey[Verifying])

private def prepareNative(key: CryptoKey, alg: SignAlgorithm): IO[KufuliError, NativePreparedKey] =
  ZIO.fromEither(SecurityChecks.prePrepare(key, alg)).map { _ =>
    val keyBytes = DerCodec.encode(key)
    val algId = NativeAlgorithmId.fromSign(alg)
    NativePreparedKey(keyBytes, algId, alg)
  }
