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
package kufuli

/** Cryptographic digest (hash) output from a hashing operation.
  *
  * `CanEqual` is intentionally omitted: the underlying `Array[Byte]` representation makes `==`
  * reference equality, producing silently wrong results. Under strict equality this is a compile
  * error, forcing use of [[Digest$.constantTimeEquals]] for timing-safe comparison.
  *
  * @see [[Digest$ Digest]] companion for construction and comparison
  */
opaque type Digest = Array[Byte]

/** Smart constructors and timing-safe comparison for [[Digest]].
  *
  * Does not extend [[boilerplate.OpaqueType OpaqueType]] because array-backed types require
  * `CanEqual` suppression to prevent silently wrong reference equality (same rationale as
  * [[CryptoKey]] and [[Signature]]).
  */
object Digest:

  /** Constructs a Digest from known bytes, validating length matches the given algorithm output. */
  def from(bytes: Array[Byte], algorithm: DigestAlgorithm): Either[KufuliError, Digest] =
    val expected = digestLength(algorithm)
    Either.cond(
      bytes.length == expected,
      bytes.clone(): Digest,
      KufuliError.DigestFailure(
        s"Expected $expected bytes for ${algorithm.toString}, got ${bytes.length}"
      )
    )

  /** Runtime digest output length. Mirrors [[DigestAlgorithm$.outputLength]] which is `inline` and
    * requires compile-time known values.
    */
  private def digestLength(alg: DigestAlgorithm): Int = alg match
    case DigestAlgorithm.Sha1   => 20
    case DigestAlgorithm.Sha256 => 32
    case DigestAlgorithm.Sha384 => 48
    case DigestAlgorithm.Sha512 => 64

  /** Timing-safe comparison of two digests. Uses constant-time XOR accumulation to prevent timing
    * side-channel attacks on hash-based authentication (e.g. JWK thumbprint matching).
    */
  def constantTimeEquals(a: Digest, b: Digest): Boolean = ConstantTime.equals(a, b)

  extension (d: Digest)

    /** Returns a defensive copy of the raw digest bytes. */
    def bytes: Array[Byte] = d.clone()

    /** Returns the byte length of this digest. */
    def length: Int = d.length

  /** Wraps raw bytes without cloning. For internal use by platform backends that produce freshly
    * allocated digest bytes.
    */
  private[kufuli] def wrap(bytes: Array[Byte]): Digest = bytes

end Digest
