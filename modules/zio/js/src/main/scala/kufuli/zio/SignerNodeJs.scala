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
import scala.scalajs.js.typedarray.Uint8Array

import zio.IO
import zio.ZIO

import _root_.kufuli.js.internal.ByteConversions
import _root_.kufuli.js.internal.KeyObject
import _root_.kufuli.js.internal.NodeAlgorithm.*
import _root_.kufuli.js.internal.NodeCrypto
import _root_.kufuli.js.internal.NodePreparedKey
import _root_.kufuli.js.internal.SignKeyOptions

import kufuli.KufuliError
import kufuli.SignAlgorithm
import kufuli.Signature
import kufuli.Signing

/** Node.js implementation of [[Signer]]. */
given Signer with

  extension (key: PreparedKey[Signing])

    def sign(data: Array[Byte]): IO[KufuliError, Signature] =
      PreparedKey.unwrapKey[Signing](key) match
        case nodeKey: NodePreparedKey =>
          val alg = nodeKey.algorithm
          val dataArr = ByteConversions.toUint8Array(data)

          val rawEffect = alg.digestAlgorithm match
            case Some(digest) =>
              val digestName = digest.nodeName
              if alg.isHmac then hmacSign(nodeKey.keyObject, dataArr, digestName)
              else if alg.isPss then pssSign(nodeKey.keyObject, dataArr, digestName)
              else if alg.isEcdsa then ecdsaSign(nodeKey.keyObject, dataArr, digestName)
              else rsaPkcs1Sign(nodeKey.keyObject, dataArr, digestName)
            case None =>
              eddsaSign(nodeKey.keyObject, dataArr)
          rawEffect.map(Signature.wrapRaw)
        case _ => ZIO.fail(KufuliError.SignatureFailure("Unexpected prepared key type"))
  end extension
end given

private def hmacSign(keyObject: KeyObject, data: Uint8Array, digestName: String): IO[KufuliError, Array[Byte]] =
  ZIO
    .attempt {
      ByteConversions.toByteArray(
        NodeCrypto.createHmac(digestName, keyObject).update(data).digest()
      )
    }
    .mapError(_ => KufuliError.SignatureFailure("HMAC computation failed"))

private def pssSign(keyObject: KeyObject, data: Uint8Array, digestName: String): IO[KufuliError, Array[Byte]] =
  ZIO
    .attempt {
      val opts =
        SignKeyOptions.pss(keyObject, NodeCrypto.constants.RSA_PKCS1_PSS_PADDING, NodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST)
      ByteConversions.toByteArray(NodeCrypto.sign(digestName, data, opts))
    }
    .mapError(_ => KufuliError.SignatureFailure("Node.js signing failed"))

private def ecdsaSign(keyObject: KeyObject, data: Uint8Array, digestName: String): IO[KufuliError, Array[Byte]] =
  ZIO
    .attempt {
      val opts = SignKeyOptions.ecdsa(keyObject)
      ByteConversions.toByteArray(NodeCrypto.sign(digestName, data, opts))
    }
    .mapError(_ => KufuliError.SignatureFailure("Node.js signing failed"))

private def rsaPkcs1Sign(
  keyObject: KeyObject,
  data: Uint8Array,
  digestName: String
): IO[KufuliError, Array[Byte]] =
  ZIO
    .attempt(ByteConversions.toByteArray(NodeCrypto.sign(digestName, data, keyObject)))
    .mapError(_ => KufuliError.SignatureFailure("Node.js signing failed"))

private def eddsaSign(keyObject: KeyObject, data: Uint8Array): IO[KufuliError, Array[Byte]] =
  ZIO
    .attempt(ByteConversions.toByteArray(NodeCrypto.sign(js.undefined, data, keyObject)))
    .mapError(_ => KufuliError.SignatureFailure("Node.js signing failed"))
