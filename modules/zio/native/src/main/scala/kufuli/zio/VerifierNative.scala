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

import scala.scalanative.unsafe.Zone
import scala.scalanative.unsigned.UnsignedRichInt

import zio.IO
import zio.ZIO

import _root_.kufuli.native.internal.NativeCrypto
import _root_.kufuli.native.internal.NativeErrors
import _root_.kufuli.native.internal.NativeMemory
import _root_.kufuli.native.internal.NativePreparedKey

import kufuli.EcdsaCodec
import kufuli.KufuliError
import kufuli.SecurityChecks
import kufuli.Signature
import kufuli.Verifying

/** Native implementation of [[Verifier]]. */
given Verifier with

  extension (key: PreparedKey[Verifying])

    def verify(data: Array[Byte], signature: Signature): IO[KufuliError, Unit] =
      val sigBytes = Signature.unwrapRaw(signature)
      PreparedKey.unwrapKey[Verifying](key) match
        case nk: NativePreparedKey =>
          val alg = nk.algorithm
          ZIO.fromEither(SecurityChecks.preVerify(alg, sigBytes)).flatMap { _ =>
            // ECDSA: transcode R||S to DER for OpenSSL
            val sigEffect = alg.ecCurve match
              case Some(_) => ZIO.fromEither(EcdsaCodec.concatToDer(sigBytes))
              case None    => ZIO.succeed(sigBytes)
            sigEffect.flatMap(nativeVerify(nk, data, _))
          }
        case _ => ZIO.fail(KufuliError.VerificationFailure("Unexpected prepared key type"))
  end extension
end given

private def nativeVerify(nk: NativePreparedKey, data: Array[Byte], sig: Array[Byte]): IO[KufuliError, Unit] =
  ZIO
    .attempt {
      Zone:
        val keyPtr = NativeMemory.allocAndCopy(nk.keyBytes)
        val dataPtr = NativeMemory.allocAndCopy(data)
        val sigPtr = NativeMemory.allocAndCopy(sig)

        NativeCrypto.kufuli_verify(
          nk.nativeAlgId,
          keyPtr,
          nk.keyBytes.length.toUSize,
          dataPtr,
          data.length.toUSize,
          sigPtr,
          sig.length.toUSize
        )
    }
    .mapError(_ => KufuliError.VerificationFailure("Native verification failed"))
    .flatMap { rc =>
      if rc == 0 then ZIO.unit
      else ZIO.fail(NativeErrors.verifyError(rc))
    }
