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

import java.security.PrivateKey
import javax.crypto.Mac
import javax.crypto.SecretKey

import zio.IO
import zio.ZIO

import _root_.kufuli.jvm.internal.JcaAlgorithm.*
import _root_.kufuli.jvm.internal.JvmPreparedKey
import boilerplate.nullable.*

import kufuli.EcdsaCodec
import kufuli.KufuliError
import kufuli.SignAlgorithm
import kufuli.Signature
import kufuli.Signing

/** JVM (JCA) implementation of [[Signer]]. */
given Signer with

  extension (key: PreparedKey[Signing])

    def sign(data: Array[Byte]): IO[KufuliError, Signature] =
      // Pattern match narrows PreparedKeyInternal -> JvmPreparedKey, Key -> SecretKey/PrivateKey
      PreparedKey.unwrapKey[Signing](key) match
        case jvmKey: JvmPreparedKey =>
          val alg = jvmKey.signAlgorithm
          (alg, jvmKey.jcaKey) match
            case (_: SignAlgorithm.HmacSha256.type | _: SignAlgorithm.HmacSha384.type | _: SignAlgorithm.HmacSha512.type, sk: SecretKey) =>
              hmacSign(sk, data, alg).map(Signature.wrapRaw)
            case (_, pk: PrivateKey) =>
              alg.ecCurve match
                case Some(curve) =>
                  jcaSign(pk, data, alg)
                    .flatMap { derSig =>
                      ZIO.fromEither(EcdsaCodec.derToConcat(derSig, curve.componentLength))
                    }
                    .map(Signature.wrapRaw)
                case None => jcaSign(pk, data, alg).map(Signature.wrapRaw)
            case _ => ZIO.fail(KufuliError.SignatureFailure("Unexpected JCA key type for signing"))
          end match
        case _ => ZIO.fail(KufuliError.SignatureFailure("Unexpected prepared key type"))
  end extension
end given

private def hmacSign(key: SecretKey, data: Array[Byte], alg: SignAlgorithm): IO[KufuliError, Array[Byte]] =
  ZIO
    .attempt {
      val mac = Mac.getInstance(alg.jcaName).unsafe
      mac.init(key)
      mac.doFinal(data).unsafe
    }
    .mapError(_ => KufuliError.SignatureFailure("HMAC computation failed"))

private def jcaSign(key: PrivateKey, data: Array[Byte], alg: SignAlgorithm): IO[KufuliError, Array[Byte]] =
  ZIO
    .attempt {
      val sig = java.security.Signature.getInstance(alg.jcaName).unsafe
      alg.pssParams.foreach(sig.setParameter(_))
      sig.initSign(key)
      sig.update(data)
      sig.sign().unsafe
    }
    .mapError(_ => KufuliError.SignatureFailure("JCA signing failed"))
