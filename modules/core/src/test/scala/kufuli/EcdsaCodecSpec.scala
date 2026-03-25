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

class EcdsaCodecSpec extends FunSuite:

  // Hand-crafted DER encoding for R=1, S=1 with P-256 (componentLength=32):
  // SEQUENCE { INTEGER 0x01, INTEGER 0x01 }
  // 30 06 02 01 01 02 01 01
  private val simpleDer = Array[Byte](0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)

  // Expected R||S: 32 bytes of zero-padded R=1 + 32 bytes of zero-padded S=1
  private def expectedConcat(componentLength: Int): Array[Byte] =
    val out = new Array[Byte](componentLength * 2)
    out(componentLength - 1) = 1 // R = 1 (big-endian, zero-padded)
    out(componentLength * 2 - 1) = 1 // S = 1 (big-endian, zero-padded)
    out

  test("derToConcat decodes simple DER (R=1, S=1)"):
    val result = EcdsaCodec.derToConcat(simpleDer, 32)
    assert(result.isRight, s"Expected Right, got $result")
    val concat = result.toOption.get
    assertEquals(concat.length, 64)
    assertEquals(concat.toList, expectedConcat(32).toList)

  test("concatToDer encodes R||S to DER"):
    val concat = expectedConcat(32)
    val result = EcdsaCodec.concatToDer(concat)
    assert(result.isRight, s"Expected Right, got $result")
    val der = result.toOption.get
    // Should start with SEQUENCE tag
    assertEquals(der(0), 0x30.toByte)

  test("round-trip: concatToDer then derToConcat"):
    val original = expectedConcat(32)
    val der = EcdsaCodec.concatToDer(original).toOption.get
    val roundTripped = EcdsaCodec.derToConcat(der, 32).toOption.get
    assertEquals(roundTripped.toList, original.toList)

  test("round-trip with larger values"):
    // R and S are both 32 bytes of 0xFF (maximum value for P-256 component length)
    val concat = Array.fill[Byte](64)(0xff.toByte)
    val der = EcdsaCodec.concatToDer(concat).toOption.get
    val roundTripped = EcdsaCodec.derToConcat(der, 32).toOption.get
    assertEquals(roundTripped.toList, concat.toList)

  test("round-trip with P-384 component length"):
    val concat = expectedConcat(48)
    val der = EcdsaCodec.concatToDer(concat).toOption.get
    val roundTripped = EcdsaCodec.derToConcat(der, 48).toOption.get
    assertEquals(roundTripped.toList, concat.toList)

  test("round-trip with P-521 component length"):
    val concat = expectedConcat(66)
    val der = EcdsaCodec.concatToDer(concat).toOption.get
    val roundTripped = EcdsaCodec.derToConcat(der, 66).toOption.get
    assertEquals(roundTripped.toList, concat.toList)

  test("derToConcat rejects truncated DER"):
    val truncated = Array[Byte](0x30, 0x06, 0x02)
    val result = EcdsaCodec.derToConcat(truncated, 32)
    assert(result.isLeft)

  test("derToConcat rejects invalid tag"):
    val badTag = Array[Byte](0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)
    val result = EcdsaCodec.derToConcat(badTag, 32)
    assert(result.isLeft)

  test("concatToDer rejects empty input"):
    val result = EcdsaCodec.concatToDer(Array.empty[Byte])
    assert(result.isLeft)

  test("concatToDer rejects odd-length input"):
    val result = EcdsaCodec.concatToDer(Array[Byte](1, 2, 3))
    assert(result.isLeft)

  test("DER with leading zero sign byte round-trips"):
    // R = 0x80 (high bit set, needs leading zero in DER), S = 0x01
    val concat = new Array[Byte](64)
    concat(31) = 0x80.toByte // R at last position of first half
    concat(63) = 0x01 // S = 1
    val der = EcdsaCodec.concatToDer(concat).toOption.get
    val roundTripped = EcdsaCodec.derToConcat(der, 32).toOption.get
    assertEquals(roundTripped.toList, concat.toList)
  // -- Strict DER rejection tests --

  test("derToConcat rejects indefinite-length BER encoding (0x80)"):
    // SEQUENCE with indefinite length: 30 80 ... 00 00
    val ber = Array[Byte](0x30, 0x80.toByte, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00)
    assert(EcdsaCodec.derToConcat(ber, 32).isLeft)

  test("derToConcat rejects non-minimal SEQUENCE length (long form for short value)"):
    // SEQUENCE length 6 encoded as 0x81 0x06 instead of just 0x06
    val nonMinimal = Array[Byte](0x30, 0x81.toByte, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)
    assert(EcdsaCodec.derToConcat(nonMinimal, 32).isLeft)

  test("derToConcat rejects non-minimal INTEGER encoding (unnecessary leading zero)"):
    // R encoded as 02 02 00 01 (two bytes with unnecessary leading zero for value 1)
    val nonMinimalInt = Array[Byte](0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x02, 0x00, 0x01)
    assert(EcdsaCodec.derToConcat(nonMinimalInt, 32).isLeft)

  test("derToConcat rejects negative INTEGER (high bit set without leading zero)"):
    // R = 0x80 encoded directly without sign byte: 02 01 80
    val negativeInt = Array[Byte](0x30, 0x06, 0x02, 0x01, 0x80.toByte, 0x02, 0x01, 0x01)
    assert(EcdsaCodec.derToConcat(negativeInt, 32).isLeft)

  test("derToConcat rejects zero-length INTEGER"):
    // R with length 0: 02 00
    val zeroLenInt = Array[Byte](0x30, 0x04, 0x02, 0x00, 0x02, 0x01, 0x01)
    assert(EcdsaCodec.derToConcat(zeroLenInt, 32).isLeft)

  test("derToConcat rejects SEQUENCE length mismatch"):
    // SEQUENCE says 8 bytes but only 6 bytes of content follow
    val mismatch = Array[Byte](0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)
    assert(EcdsaCodec.derToConcat(mismatch, 32).isLeft)

  test("derToConcat rejects wrong INTEGER tag for S"):
    // Second element tagged 0x03 (BIT STRING) instead of 0x02 (INTEGER)
    val wrongTag = Array[Byte](0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x01)
    assert(EcdsaCodec.derToConcat(wrongTag, 32).isLeft)

  // -- P-521 maximum-length component round-trip --

  test("round-trip with P-521 maximum-length components (high bit set)"):
    // Both R and S are 66 bytes with high bit set (requires sign padding in DER)
    val concat = new Array[Byte](132)
    java.util.Arrays.fill(concat, 0, 66, 0xff.toByte) // R = all 0xFF
    java.util.Arrays.fill(concat, 66, 132, 0xfe.toByte) // S = all 0xFE
    val der = EcdsaCodec.concatToDer(concat).toOption.get
    val roundTripped = EcdsaCodec.derToConcat(der, 66).toOption.get
    assertEquals(roundTripped.toList, concat.toList)

  test("derToConcat rejects component larger than componentLength"):
    // Build a DER where R is 33 bytes but componentLength is 32
    val rBytes = new Array[Byte](33)
    rBytes(0) = 0x01
    val sBytes = Array[Byte](0x01)
    val contentLen = 2 + rBytes.length + 2 + sBytes.length
    val der =
      Array[Byte](0x30, contentLen.toByte, 0x02, rBytes.length.toByte) ++ rBytes ++ Array[Byte](0x02, sBytes.length.toByte) ++ sBytes
    assert(EcdsaCodec.derToConcat(der, 32).isLeft)

end EcdsaCodecSpec
