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

import scala.concurrent.ExecutionContext
import scala.concurrent.Future

import zio.Runtime
import zio.Unsafe
import zio.ZIO

import munit.FunSuite

import kufuli.KufuliError

/** Shared base for kufuli's cross-platform test suites. Bridges ZIO into munit's `Future`-based
  * test harness using `Runtime.unsafe.runToFuture`, the one execution mode that works uniformly on
  * every supported runtime - JVM, Scala Native, Node.js, and the JavaScript single-threaded event
  * loop in browsers (where Web Crypto `SubtleCrypto` calls are Promise-based and cannot block).
  *
  * Suites running large vector batches should build a single ZIO program (e.g. via `ZIO.foreach`)
  * and submit it through [[runIo]] once, not run a Future per vector - one execution amortises the
  * runtime boundary and keeps the Browser event loop responsive.
  */
abstract class AsyncCryptoSuite extends FunSuite:

  given ExecutionContext = ExecutionContext.parasitic

  /** Submit a ZIO program through the default runtime and surface its result as a `Future`. */
  protected def runIo[A](zio: ZIO[Any, KufuliError, A]): Future[A] =
    Unsafe.unsafe { u ?=>
      Runtime.default.unsafe.runToFuture(zio)
    }

  /** Submit a ZIO program and surface its outcome as `Future[Either[KufuliError, A]]`. Used in
    * adversarial suites that expect specific failures.
    */
  protected def runIoEither[A](zio: ZIO[Any, KufuliError, A]): Future[Either[KufuliError, A]] =
    Unsafe.unsafe { u ?=>
      Runtime.default.unsafe.runToFuture(zio.either)
    }

end AsyncCryptoSuite
