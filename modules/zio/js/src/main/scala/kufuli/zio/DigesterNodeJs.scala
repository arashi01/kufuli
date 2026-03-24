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

import zio.IO
import zio.ZIO

import _root_.kufuli.js.internal.ByteConversions
import _root_.kufuli.js.internal.NodeAlgorithm.*
import _root_.kufuli.js.internal.NodeCrypto

import kufuli.Digest
import kufuli.DigestAlgorithm
import kufuli.KufuliError

/** Node.js implementation of [[Digester]]. */
given Digester with

  extension (data: Array[Byte])

    def digest(algorithm: DigestAlgorithm): IO[KufuliError, Digest] =
      ZIO
        .attempt {
          Digest.wrap(
            ByteConversions.toByteArray(
              NodeCrypto.createHash(algorithm.nodeName).update(ByteConversions.toUint8Array(data)).digest()
            )
          )
        }
        .mapError(_ => KufuliError.DigestFailure("Node.js digest computation failed"))
  end extension
end given
