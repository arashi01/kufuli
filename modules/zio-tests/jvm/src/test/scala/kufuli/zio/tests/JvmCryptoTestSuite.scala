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
package kufuli.zio.tests

import zio.Runtime
import zio.Unsafe
import zio.ZIO

import kufuli.CryptoKey
import kufuli.DigestAlgorithm
import kufuli.KufuliError
import kufuli.SignAlgorithm
import kufuli.testkit.CryptoTestSuite
import kufuli.zio.given

class JvmCryptoTestSuite extends CryptoTestSuite:

  private def run[A](zio: ZIO[Any, KufuliError, A]): A =
    Unsafe.unsafe { u ?=>
      Runtime.default.unsafe.run(zio).getOrThrowFiberFailure()
    }

  def prepareAndSign(key: CryptoKey, algorithm: SignAlgorithm, data: Array[Byte]): Array[Byte] =
    run(key.prepareSigning(algorithm).flatMap(_.sign(data)))

  def prepareAndVerify(key: CryptoKey, algorithm: SignAlgorithm, data: Array[Byte], signature: Array[Byte]): Unit =
    run(key.prepareVerifying(algorithm).flatMap(_.verify(data, signature)))

  def computeDigest(data: Array[Byte], algorithm: DigestAlgorithm): Array[Byte] =
    run(data.digest(algorithm))

  def prepareSigningError(key: CryptoKey, algorithm: SignAlgorithm): Option[KufuliError] =
    Unsafe.unsafe { u ?=>
      Runtime.default.unsafe.run(key.prepareSigning(algorithm)) match
        case zio.Exit.Failure(cause) => cause.failureOption
        case zio.Exit.Success(_)     => None
    }

end JvmCryptoTestSuite
