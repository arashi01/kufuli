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

import _root_.kufuli.js.internal.ByteConversions
import _root_.kufuli.js.internal.JwkBuilder
import _root_.kufuli.js.internal.JwkKeyInput
import _root_.kufuli.js.internal.KeyObject
import _root_.kufuli.js.internal.NodeCrypto
import _root_.kufuli.js.internal.NodePreparedKey

import kufuli.CryptoKey
import kufuli.KufuliError
import kufuli.SecurityChecks
import kufuli.SignAlgorithm
import kufuli.Signing
import kufuli.Verifying

/** Node.js implementation of [[KeyPreparer]]. */
given KeyPreparer with

  extension (key: CryptoKey)

    def prepareSigning(algorithm: SignAlgorithm): IO[KufuliError, PreparedKey[Signing]] =
      prepare(key, algorithm).map(PreparedKey.wrapKey[Signing])

    def prepareVerifying(algorithm: SignAlgorithm): IO[KufuliError, PreparedKey[Verifying]] =
      prepare(key, algorithm).map(PreparedKey.wrapKey[Verifying])

private def prepare(key: CryptoKey, alg: SignAlgorithm): IO[KufuliError, NodePreparedKey] =
  ZIO.fromEither(SecurityChecks.prePrepare(key, alg)).flatMap { _ =>
    ZIO
      .attempt {
        val keyObject = toNodeKeyObject(key)
        NodePreparedKey(keyObject, alg)
      }
      .mapError(_ => KufuliError.InvalidKey("Node.js key construction failed"))
  }

private def toNodeKeyObject(key: CryptoKey): KeyObject =
  key match
    case CryptoKey.Symmetric(bytes) =>
      NodeCrypto.createSecretKey(ByteConversions.toUint8Array(bytes))
    case _: CryptoKey.RsaPublic | _: CryptoKey.EcPublic | _: CryptoKey.OkpPublic =>
      NodeCrypto.createPublicKey(JwkKeyInput(JwkBuilder.toJwk(key)))
    case _: CryptoKey.RsaPrivate | _: CryptoKey.EcPrivate | _: CryptoKey.OkpPrivate =>
      NodeCrypto.createPrivateKey(JwkKeyInput(JwkBuilder.toJwk(key)))
