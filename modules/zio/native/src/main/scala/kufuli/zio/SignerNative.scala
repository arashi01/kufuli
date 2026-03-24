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

import scala.scalanative.unsafe.CSize
import scala.scalanative.unsafe.Zone
import scala.scalanative.unsafe.alloc
import scala.scalanative.unsigned.UnsignedRichInt

import zio.IO
import zio.ZIO

import _root_.kufuli.native.internal.NativeCrypto
import _root_.kufuli.native.internal.NativeErrors
import _root_.kufuli.native.internal.NativeMemory
import _root_.kufuli.native.internal.NativePreparedKey

import kufuli.EcdsaCodec
import kufuli.KufuliError
import kufuli.Signing

/** Native implementation of [[Signer]]. */
given Signer with

  extension (key: PreparedKey[Signing])

    def sign(data: Array[Byte]): IO[KufuliError, Array[Byte]] =
      PreparedKey.unwrapKey[Signing](key) match
        case nk: NativePreparedKey => nativeSign(nk, data)
        case _                     => ZIO.fail(KufuliError.SignatureFailure("Unexpected prepared key type"))

private val MaxSigLen = 1024

private def nativeSign(nk: NativePreparedKey, data: Array[Byte]): IO[KufuliError, Array[Byte]] =
  ZIO
    .attempt {
      Zone:
        val keyPtr = NativeMemory.allocAndCopy(nk.keyBytes)
        val dataPtr = NativeMemory.allocAndCopy(data)
        val sigOut = alloc[Byte](MaxSigLen)
        val sigLen = alloc[CSize](1)
        !sigLen = MaxSigLen.toUSize

        val rc = NativeCrypto.kufuli_sign(
          nk.nativeAlgId,
          keyPtr,
          nk.keyBytes.length.toUSize,
          dataPtr,
          data.length.toUSize,
          sigOut,
          sigLen
        )

        if rc != 0 then Left(NativeErrors.signError(rc))
        else
          val len = (!sigLen).toInt
          val result = new Array[Byte](len)
          NativeMemory.copyFromNative(sigOut, result, len)
          Right(result)
    }
    .mapError(_ => KufuliError.SignatureFailure("Native signing failed"))
    .flatMap(ZIO.fromEither(_))
    .flatMap { rawSig =>
      // ECDSA: OpenSSL returns DER-encoded signatures, transcode to R||S
      nk.algorithm.ecCurve match
        case Some(curve) => ZIO.fromEither(EcdsaCodec.derToConcat(rawSig, curve.componentLength))
        case None        => ZIO.succeed(rawSig)
    }
