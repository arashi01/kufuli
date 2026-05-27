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
package kufuli.tests

import scala.concurrent.Future

import zio.Runtime
import zio.Unsafe
import zio.ZIO

import kufuli.CryptoKey
import kufuli.Digest
import kufuli.DigestAlgorithm
import kufuli.KufuliError
import kufuli.SignAlgorithm
import kufuli.Signature
import kufuli.testkit.CryptoTestSuite
import kufuli.zio.given

/** Cross-platform crypto test suite. The same class is compiled for JVM, JS Node.js, Scala Native,
  * and JS Browser - each picks up its platform's `given` backend instances via standard given
  * resolution. ZIO programs execute via [[zio.Runtime.unsafe.runToFuture]], the only path that
  * works on every target including SubtleCrypto in browsers.
  */
class ZioCryptoTestSuite extends CryptoTestSuite:

  private def run[A](zio: ZIO[Any, KufuliError, A]): Future[A] =
    Unsafe.unsafe { u ?=>
      Runtime.default.unsafe.runToFuture(zio)
    }

  def prepareAndSign(key: CryptoKey, algorithm: SignAlgorithm, data: Array[Byte]): Future[Signature] =
    run(key.prepareSigning(algorithm).flatMap(_.sign(data)))

  def prepareAndVerify(key: CryptoKey, algorithm: SignAlgorithm, data: Array[Byte], signature: Signature): Future[Unit] =
    run(key.prepareVerifying(algorithm).flatMap(_.verify(data, signature)))

  def computeDigest(data: Array[Byte], algorithm: DigestAlgorithm): Future[Digest] =
    run(data.digest(algorithm))

  def prepareSigningError(key: CryptoKey, algorithm: SignAlgorithm): Future[Option[KufuliError]] =
    run(key.prepareSigning(algorithm).either.map(_.left.toOption))

end ZioCryptoTestSuite
