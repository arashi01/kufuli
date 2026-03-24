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

import _root_.kufuli.native.internal.NativeAlgorithmId
import _root_.kufuli.native.internal.NativeCrypto
import _root_.kufuli.native.internal.NativeErrors
import _root_.kufuli.native.internal.NativeMemory

import kufuli.DigestAlgorithm
import kufuli.KufuliError

/** Native implementation of [[Digester]]. */
given Digester with

  extension (data: Array[Byte])

    def digest(algorithm: DigestAlgorithm): IO[KufuliError, Array[Byte]] =
      val algId = NativeAlgorithmId.fromDigest(algorithm)
      ZIO
        .attempt {
          Zone:
            val dataPtr = NativeMemory.allocAndCopy(data)
            val maxLen = 64 // SHA-512 output is 64 bytes, the maximum
            val out = alloc[Byte](maxLen)
            val outLen = alloc[CSize](1)
            !outLen = maxLen.toUSize

            val rc = NativeCrypto.kufuli_digest(
              algId,
              dataPtr,
              data.length.toUSize,
              out,
              outLen
            )

            if rc != 0 then Left(NativeErrors.digestError(rc))
            else
              val len = (!outLen).toInt
              val result = new Array[Byte](len)
              NativeMemory.copyFromNative(out, result, len)
              Right(result)
        }
        .mapError(_ => KufuliError.DigestFailure("Native digest computation failed"))
        .flatMap(ZIO.fromEither(_))
  end extension
end given
