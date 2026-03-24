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
package kufuli.native.internal

import kufuli.DigestAlgorithm
import kufuli.SignAlgorithm

/** Explicit mapping from kufuli algorithm types to C integer constants. Decoupled from enum
  * ordinals to survive reordering.
  */
private[kufuli] object NativeAlgorithmId:

  /** Maps a [[kufuli.SignAlgorithm SignAlgorithm]] to the corresponding C `KUFULI_ALG_*` constant. */
  def fromSign(alg: SignAlgorithm): Int = alg match
    case SignAlgorithm.HmacSha256      => 0
    case SignAlgorithm.HmacSha384      => 1
    case SignAlgorithm.HmacSha512      => 2
    case SignAlgorithm.RsaPkcs1Sha256  => 3
    case SignAlgorithm.RsaPkcs1Sha384  => 4
    case SignAlgorithm.RsaPkcs1Sha512  => 5
    case SignAlgorithm.RsaPssSha256    => 6
    case SignAlgorithm.RsaPssSha384    => 7
    case SignAlgorithm.RsaPssSha512    => 8
    case SignAlgorithm.EcdsaP256Sha256 => 9
    case SignAlgorithm.EcdsaP384Sha384 => 10
    case SignAlgorithm.EcdsaP521Sha512 => 11
    case SignAlgorithm.Ed25519         => 12
    case SignAlgorithm.Ed448           => 13

  /** Maps a [[kufuli.DigestAlgorithm DigestAlgorithm]] to the corresponding C `KUFULI_DIGEST_*`
    * constant.
    */
  def fromDigest(alg: DigestAlgorithm): Int = alg match
    case DigestAlgorithm.Sha1   => 100
    case DigestAlgorithm.Sha256 => 101
    case DigestAlgorithm.Sha384 => 102
    case DigestAlgorithm.Sha512 => 103

end NativeAlgorithmId
