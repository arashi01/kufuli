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

import java.security.PublicKey
import javax.crypto.Mac
import javax.crypto.SecretKey

import zio.IO
import zio.ZIO

import _root_.kufuli.jvm.internal.JcaAlgorithm.*
import _root_.kufuli.jvm.internal.JvmPreparedKey
import boilerplate.nullable.*

import kufuli.ConstantTime
import kufuli.EcdsaCodec
import kufuli.KufuliError
import kufuli.SecurityChecks
import kufuli.SignAlgorithm
import kufuli.Signature
import kufuli.Verifying

/** JVM (JCA) implementation of [[Verifier]]. */
given Verifier with

  extension (key: PreparedKey[Verifying])

    def verify(data: Array[Byte], signature: Signature): IO[KufuliError, Unit] =
      val sigBytes = Signature.unwrapRaw(signature)
      // Pattern match narrows PreparedKeyInternal -> JvmPreparedKey, Key -> SecretKey/PublicKey
      PreparedKey.unwrapKey[Verifying](key) match
        case jvmKey: JvmPreparedKey =>
          val alg = jvmKey.signAlgorithm
          ZIO.fromEither(SecurityChecks.preVerify(alg, sigBytes)).flatMap { _ =>
            (alg, jvmKey.jcaKey) match
              case (_: SignAlgorithm.HmacSha256.type | _: SignAlgorithm.HmacSha384.type | _: SignAlgorithm.HmacSha512.type,
                    sk: SecretKey
                  ) =>
                hmacVerify(sk, data, sigBytes, alg)
              case (_, pk: PublicKey) =>
                alg.ecCurve match
                  case Some(_) =>
                    ZIO.fromEither(EcdsaCodec.concatToDer(sigBytes)).flatMap { derSig =>
                      jcaVerify(pk, data, derSig, alg)
                    }
                  case None => jcaVerify(pk, data, sigBytes, alg)
              case _ => ZIO.fail(KufuliError.VerificationFailure("Unexpected JCA key type for verification"))
          }
        case _ => ZIO.fail(KufuliError.VerificationFailure("Unexpected prepared key type"))
      end match
  end extension
end given

private def hmacVerify(key: SecretKey, data: Array[Byte], signature: Array[Byte], alg: SignAlgorithm): IO[KufuliError, Unit] =
  ZIO
    .attempt {
      val mac = Mac.getInstance(alg.jcaName).unsafe
      mac.init(key)
      mac.doFinal(data).unsafe
    }
    .mapError(_ => KufuliError.VerificationFailure("HMAC computation failed"))
    .flatMap { computed =>
      ZIO.cond(ConstantTime.equals(computed, signature), (), KufuliError.InvalidSignature("HMAC mismatch"))
    }

private def jcaVerify(key: PublicKey, data: Array[Byte], signature: Array[Byte], alg: SignAlgorithm): IO[KufuliError, Unit] =
  ZIO
    .attempt {
      val sig = java.security.Signature.getInstance(alg.jcaName).unsafe
      alg.pssParams.foreach(sig.setParameter(_))
      sig.initVerify(key)
      sig.update(data)
      sig.verify(signature)
    }
    .mapError(_ => KufuliError.InvalidSignature("Signature verification failed"))
    .flatMap { valid =>
      ZIO.cond(valid, (), KufuliError.InvalidSignature("Signature verification failed"))
    }
