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

class SignatureSpec extends FunSuite:

  test("Signature.raw clones input bytes"):
    val original = Array[Byte](1, 2, 3)
    val sig = Signature.raw(original)
    original(0) = 99
    assertEquals(sig.bytes(0), 1.toByte)

  test("Signature.bytes returns a defensive copy"):
    val sig = Signature.raw(Array[Byte](1, 2, 3))
    val bytes1 = sig.bytes
    bytes1(0) = 99
    assertEquals(sig.bytes(0), 1.toByte)

  test("Signature.toEcdsaConcat accepts correct length for P-256"):
    val rs = new Array[Byte](64)
    rs(31) = 1; rs(63) = 1
    val sig = Signature.ecdsaConcat(rs, EcCurve.P256).toOption.get
    assert(sig.toEcdsaConcat(EcCurve.P256).isRight)

  test("Signature.toEcdsaConcat rejects wrong length for P-256"):
    // Create a signature with 96 bytes (P-384 size) and try to extract as P-256
    val rs = new Array[Byte](96)
    rs(47) = 1; rs(95) = 1
    val sig = Signature.ecdsaConcat(rs, EcCurve.P384).toOption.get
    assert(sig.toEcdsaConcat(EcCurve.P256).isLeft)

  test("Signature.toEcdsaConcat accepts correct length for P-521"):
    val rs = new Array[Byte](132)
    rs(65) = 1; rs(131) = 1
    val sig = Signature.ecdsaConcat(rs, EcCurve.P521).toOption.get
    assert(sig.toEcdsaConcat(EcCurve.P521).isRight)

  test("Signature.toEcdsaDer round-trips with ecdsaDer"):
    val rs = new Array[Byte](64)
    rs(31) = 0x7f; rs(63) = 0x42
    val sig = Signature.ecdsaConcat(rs, EcCurve.P256).toOption.get
    val derBytes = sig.toEcdsaDer.toOption.get
    val recovered = Signature.ecdsaDer(derBytes, EcCurve.P256).toOption.get
    assertEquals(recovered.bytes.toList, sig.bytes.toList)

end SignatureSpec
