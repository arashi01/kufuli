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

class EcParamsSpec extends FunSuite:

  // Valid R||S signature: R=1, S=1 (both in [1, n-1] for all NIST curves)
  private def validSignature(componentLength: Int): Array[Byte] =
    val sig = new Array[Byte](componentLength * 2)
    sig(componentLength - 1) = 1 // R = 1
    sig(componentLength * 2 - 1) = 1 // S = 1
    sig

  test("accepts valid P-256 signature"):
    val result = EcParams.validateSignature(EcCurve.P256, validSignature(32))
    assert(result.isRight)

  test("accepts valid P-384 signature"):
    val result = EcParams.validateSignature(EcCurve.P384, validSignature(48))
    assert(result.isRight)

  test("accepts valid P-521 signature"):
    val result = EcParams.validateSignature(EcCurve.P521, validSignature(66))
    assert(result.isRight)

  test("rejects wrong-length signature"):
    val tooShort = new Array[Byte](32) // P-256 expects 64
    tooShort(31) = 1
    val result = EcParams.validateSignature(EcCurve.P256, tooShort)
    assert(result.isLeft)

  test("rejects all-zero signature (CVE-2022-21449)"):
    val allZero = new Array[Byte](64)
    val result = EcParams.validateSignature(EcCurve.P256, allZero)
    assert(result.isLeft)

  test("rejects R = 0"):
    val sig = new Array[Byte](64)
    // R = 0 (all zeros in first half), S = 1
    sig(63) = 1
    val result = EcParams.validateSignature(EcCurve.P256, sig)
    assert(result.isLeft)

  test("rejects S = 0"):
    val sig = new Array[Byte](64)
    // R = 1, S = 0 (all zeros in second half)
    sig(31) = 1
    val result = EcParams.validateSignature(EcCurve.P256, sig)
    assert(result.isLeft)

  test("rejects R >= curve order"):
    // P-256 order starts with 0xFF..., so a value of all 0xFF bytes exceeds it
    val sig = new Array[Byte](64)
    java.util.Arrays.fill(sig, 0, 32, 0xff.toByte) // R = max value
    sig(63) = 1 // S = 1
    val result = EcParams.validateSignature(EcCurve.P256, sig)
    assert(result.isLeft)

  test("rejects S >= curve order"):
    val sig = new Array[Byte](64)
    sig(31) = 1 // R = 1
    java.util.Arrays.fill(sig, 32, 64, 0xff.toByte) // S = max value
    val result = EcParams.validateSignature(EcCurve.P256, sig)
    assert(result.isLeft)
end EcParamsSpec
