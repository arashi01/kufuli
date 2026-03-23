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
package kufuli.js.internal

import kufuli.DigestAlgorithm
import kufuli.SignAlgorithm

/** Node.js algorithm name mappings for kufuli algorithm types. JS-only extensions. */
private[kufuli] object NodeAlgorithm:

  extension (alg: SignAlgorithm)

    /** Whether this algorithm uses RSA-PSS padding. */
    def isPss: Boolean = alg match
      case SignAlgorithm.RsaPssSha256 | SignAlgorithm.RsaPssSha384 | SignAlgorithm.RsaPssSha512 => true
      case _                                                                                    => false

    /** Whether this algorithm uses ECDSA. */
    def isEcdsa: Boolean = alg.ecCurve.isDefined

    /** Whether this algorithm uses HMAC. */
    def isHmac: Boolean = alg match
      case SignAlgorithm.HmacSha256 | SignAlgorithm.HmacSha384 | SignAlgorithm.HmacSha512 => true
      case _                                                                              => false
  end extension

  extension (alg: DigestAlgorithm)

    /** Node.js hash algorithm name for `createHash`. */
    def nodeName: String = alg match
      case DigestAlgorithm.Sha1   => "sha1"
      case DigestAlgorithm.Sha256 => "sha256"
      case DigestAlgorithm.Sha384 => "sha384"
      case DigestAlgorithm.Sha512 => "sha512"

end NodeAlgorithm
