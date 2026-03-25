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

import java.math.BigInteger

import munit.FunSuite

class CryptoKeySpec extends FunSuite:

  // -- Symmetric --

  test("symmetric accepts non-empty byte array"):
    assert(CryptoKey.symmetric(Array[Byte](1, 2, 3)).isRight)

  test("symmetric rejects empty byte array"):
    assert(CryptoKey.symmetric(Array.empty[Byte]).isLeft)

  test("symmetric clones input array"):
    val bytes = Array[Byte](1, 2, 3)
    val key = CryptoKey.symmetric(bytes).toOption.get
    bytes(0) = 99 // Mutate original
    key match
      case CryptoKey.Symmetric(keyBytes) => assertEquals(keyBytes(0), 1.toByte)
      case _                             => fail("Expected Symmetric")

  // -- RSA --

  test("rsaPublic accepts 2048-bit modulus"):
    val modulus = new Array[Byte](256)
    modulus(0) = 0x80.toByte
    assert(CryptoKey.rsaPublic(modulus, Array[Byte](1, 0, 1)).isRight)

  test("rsaPublic rejects 1024-bit modulus"):
    val modulus = new Array[Byte](128)
    modulus(0) = 0x80.toByte
    assert(CryptoKey.rsaPublic(modulus, Array[Byte](1, 0, 1)).isLeft)

  test("rsaPrivate rejects mismatched CRT parameters"):
    val p = BigInteger.valueOf(61)
    val q = BigInteger.valueOf(53)
    // Pad modulus to 256 bytes to pass key size check (n != p*q, so CRT will fail)
    val paddedModulus = new Array[Byte](256)
    paddedModulus(0) = 0x80.toByte
    assert(
      CryptoKey
        .rsaPrivate(
          paddedModulus,
          Array[Byte](1, 0, 1),
          Array[Byte](1),
          p.toByteArray,
          q.toByteArray,
          Array[Byte](1),
          Array[Byte](1),
          Array[Byte](1)
        )
        .isLeft
    )

  // -- EC --

  // NIST P-256 generator point (FIPS 186-5 (February 2023))
  private val p256Gx: Array[Byte] =
    BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16).toByteArray.dropWhile(_ == 0)

  private val p256Gy: Array[Byte] =
    BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16).toByteArray.dropWhile(_ == 0)

  test("ecPublic accepts valid P-256 point (generator)"):
    assert(CryptoKey.ecPublic(EcCurve.P256, p256Gx, p256Gy).isRight)

  test("ecPublic rejects off-curve point"):
    assert(CryptoKey.ecPublic(EcCurve.P256, Array[Byte](1), Array[Byte](1)).isLeft)

  test("ecPrivate accepts valid P-256 point"):
    val d = new Array[Byte](32)
    d(31) = 1
    assert(CryptoKey.ecPrivate(EcCurve.P256, p256Gx, p256Gy, d).isRight)

  test("ecPrivate rejects d = 0"):
    val d = new Array[Byte](32)
    assert(CryptoKey.ecPrivate(EcCurve.P256, p256Gx, p256Gy, d).isLeft)

  test("ecPrivate rejects d >= curve order"):
    val d = Array.fill[Byte](32)(0xff.toByte)
    assert(CryptoKey.ecPrivate(EcCurve.P256, p256Gx, p256Gy, d).isLeft)

  // -- OKP --

  test("okpPublic accepts 32-byte Ed25519 key"):
    assert(CryptoKey.okpPublic(OkpCurve.Ed25519, new Array[Byte](32)).isRight)

  test("okpPublic rejects wrong-length Ed25519 key"):
    assert(CryptoKey.okpPublic(OkpCurve.Ed25519, new Array[Byte](16)).isLeft)

  test("okpPrivate accepts valid Ed25519 key"):
    assert(CryptoKey.okpPrivate(OkpCurve.Ed25519, new Array[Byte](32), new Array[Byte](32)).isRight)

  test("okpPrivate rejects wrong-length d for Ed25519"):
    assert(CryptoKey.okpPrivate(OkpCurve.Ed25519, new Array[Byte](32), new Array[Byte](16)).isLeft)

  test("okpPrivate rejects wrong-length d for Ed448"):
    assert(CryptoKey.okpPrivate(OkpCurve.Ed448, new Array[Byte](57), new Array[Byte](32)).isLeft)

  test("okpPublic accepts 57-byte Ed448 key"):
    assert(CryptoKey.okpPublic(OkpCurve.Ed448, new Array[Byte](57)).isRight)

  // -- contentEquals --

  test("contentEquals returns true for identical symmetric keys"):
    val k1 = CryptoKey.symmetric(Array[Byte](1, 2, 3)).toOption.get
    val k2 = CryptoKey.symmetric(Array[Byte](1, 2, 3)).toOption.get
    assert(CryptoKey.contentEquals(k1, k2))

  test("contentEquals returns false for different symmetric keys"):
    val k1 = CryptoKey.symmetric(Array[Byte](1, 2, 3)).toOption.get
    val k2 = CryptoKey.symmetric(Array[Byte](4, 5, 6)).toOption.get
    assert(!CryptoKey.contentEquals(k1, k2))

  test("contentEquals returns false for different key types"):
    val symKey = CryptoKey.symmetric(Array[Byte](1, 2, 3)).toOption.get
    val okpKey = CryptoKey.okpPublic(OkpCurve.Ed25519, new Array[Byte](32)).toOption.get
    assert(!CryptoKey.contentEquals(symKey, okpKey))

  test("contentEquals returns true for identical EC public keys"):
    val k1 = CryptoKey.ecPublic(EcCurve.P256, p256Gx, p256Gy).toOption.get
    val k2 = CryptoKey.ecPublic(EcCurve.P256, p256Gx, p256Gy).toOption.get
    assert(CryptoKey.contentEquals(k1, k2))

  test("contentEquals returns false for EC keys on different curves"):
    // P-384 generator point (FIPS 186-5 (February 2023))
    val p384Gx =
      BigInteger(
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
        16
      ).toByteArray.dropWhile(_ == 0)
    val p384Gy =
      BigInteger(
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
        16
      ).toByteArray.dropWhile(_ == 0)

    val k1 = CryptoKey.ecPublic(EcCurve.P256, p256Gx, p256Gy).toOption.get
    val k2 = CryptoKey.ecPublic(EcCurve.P384, p384Gx, p384Gy).toOption.get
    assert(!CryptoKey.contentEquals(k1, k2))
end CryptoKeySpec
