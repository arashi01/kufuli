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
import _root_.kufuli.js.internal.VerifyKeyOptions

import kufuli.KufuliError
import kufuli.SecurityChecks
import kufuli.SignAlgorithm
import kufuli.Signature
import kufuli.Verifying

/** Node.js implementation of [[Verifier]]. */
given Verifier with

  extension (key: PreparedKey[Verifying])

    def verify(data: Array[Byte], signature: Signature): IO[KufuliError, Unit] =
      val sigBytes = Signature.unwrapRaw(signature)
      PreparedKey.unwrapKey[Verifying](key) match
        case nodeKey: NodePreparedKey =>
          val alg = nodeKey.signAlgorithm
          ZIO.fromEither(SecurityChecks.preVerify(alg, sigBytes)).flatMap { _ =>
            val dataArr = ByteConversions.toUint8Array(data)
            val sigArr = ByteConversions.toUint8Array(sigBytes)

            alg.digestAlgorithm match
              case Some(digest) =>
                val digestName = digest.nodeName
                if alg.isHmac then hmacVerify(nodeKey.keyObject, dataArr, sigArr, digestName)
                else if alg.isPss then pssVerify(nodeKey.keyObject, dataArr, sigArr, digestName)
                else if alg.isEcdsa then ecdsaVerify(nodeKey.keyObject, dataArr, sigArr, digestName)
                else rsaPkcs1Verify(nodeKey.keyObject, dataArr, sigArr, digestName)
              case None =>
                eddsaVerify(nodeKey.keyObject, dataArr, sigArr)
          }
        case _ => ZIO.fail(KufuliError.VerificationFailure("Unexpected prepared key type"))
      end match
  end extension
end given

private def hmacVerify(keyObject: KeyObject, data: Uint8Array, signature: Uint8Array, digestName: String): IO[KufuliError, Unit] =
  ZIO
    .attempt {
      val computed = NodeCrypto.createHmac(digestName, keyObject).update(data).digest()
      computed.length == signature.length && NodeCrypto.timingSafeEqual(computed, signature)
    }
    .mapError(_ => KufuliError.VerificationFailure("HMAC computation failed"))
    .flatMap { valid =>
      ZIO.cond(valid, (), KufuliError.SignatureMismatch("HMAC mismatch"))
    }

private def pssVerify(keyObject: KeyObject, data: Uint8Array, signature: Uint8Array, digestName: String): IO[KufuliError, Unit] =
  ZIO
    .attempt {
      val opts =
        VerifyKeyOptions.pss(keyObject, NodeCrypto.constants.RSA_PKCS1_PSS_PADDING, NodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST)
      NodeCrypto.verify(digestName, data, opts, signature)
    }
    .mapError(_ => KufuliError.VerificationFailure("Node.js verification threw"))
    .flatMap(valid => ZIO.cond(valid, (), KufuliError.SignatureMismatch("Signature verification failed")))

private def ecdsaVerify(keyObject: KeyObject, data: Uint8Array, signature: Uint8Array, digestName: String): IO[KufuliError, Unit] =
  ZIO
    .attempt {
      val opts = VerifyKeyOptions.ecdsa(keyObject)
      NodeCrypto.verify(digestName, data, opts, signature)
    }
    .mapError(_ => KufuliError.VerificationFailure("Node.js verification threw"))
    .flatMap(valid => ZIO.cond(valid, (), KufuliError.SignatureMismatch("Signature verification failed")))

private def rsaPkcs1Verify(keyObject: KeyObject, data: Uint8Array, signature: Uint8Array, digestName: String): IO[KufuliError, Unit] =
  ZIO
    .attempt(NodeCrypto.verify(digestName, data, keyObject, signature))
    .mapError(_ => KufuliError.VerificationFailure("Node.js verification threw"))
    .flatMap(valid => ZIO.cond(valid, (), KufuliError.SignatureMismatch("Signature verification failed")))

private def eddsaVerify(keyObject: KeyObject, data: Uint8Array, signature: Uint8Array): IO[KufuliError, Unit] =
  ZIO
    .attempt(NodeCrypto.verify(js.undefined, data, keyObject, signature))
    .mapError(_ => KufuliError.VerificationFailure("Node.js verification threw"))
    .flatMap(valid => ZIO.cond(valid, (), KufuliError.SignatureMismatch("Signature verification failed")))
