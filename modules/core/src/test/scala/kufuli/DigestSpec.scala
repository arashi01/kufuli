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

import munit.FunSuite

class DigestSpec extends FunSuite:

  test("Digest.from accepts correct length for SHA-256"):
    assert(Digest.from(new Array[Byte](32), DigestAlgorithm.Sha256).isRight)

  test("Digest.from rejects wrong length for SHA-256"):
    assert(Digest.from(new Array[Byte](16), DigestAlgorithm.Sha256).isLeft)

  test("Digest.from accepts correct length for SHA-384"):
    assert(Digest.from(new Array[Byte](48), DigestAlgorithm.Sha384).isRight)

  test("Digest.from rejects wrong length for SHA-384"):
    assert(Digest.from(new Array[Byte](32), DigestAlgorithm.Sha384).isLeft)

  test("Digest.from accepts correct length for SHA-512"):
    assert(Digest.from(new Array[Byte](64), DigestAlgorithm.Sha512).isRight)

  test("Digest.from rejects wrong length for SHA-512"):
    assert(Digest.from(new Array[Byte](32), DigestAlgorithm.Sha512).isLeft)

  test("Digest.from accepts correct length for SHA-1"):
    assert(Digest.from(new Array[Byte](20), DigestAlgorithm.Sha1).isRight)

  test("Digest.from clones input bytes"):
    val original = Array[Byte](1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20)
    val digest = Digest.from(original, DigestAlgorithm.Sha1).toOption.get
    original(0) = 99
    assertEquals(digest.bytes(0), 1.toByte)

  test("Digest.constantTimeEquals returns true for equal digests"):
    val a = Digest.from(new Array[Byte](32), DigestAlgorithm.Sha256).toOption.get
    val b = Digest.from(new Array[Byte](32), DigestAlgorithm.Sha256).toOption.get
    assert(Digest.constantTimeEquals(a, b))

  test("Digest.constantTimeEquals returns false for different digests"):
    val aBytes = new Array[Byte](32)
    val bBytes = new Array[Byte](32)
    bBytes(0) = 1
    val a = Digest.from(aBytes, DigestAlgorithm.Sha256).toOption.get
    val b = Digest.from(bBytes, DigestAlgorithm.Sha256).toOption.get
    assert(!Digest.constantTimeEquals(a, b))

end DigestSpec
