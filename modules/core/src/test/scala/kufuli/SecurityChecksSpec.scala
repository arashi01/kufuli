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

class SecurityChecksSpec extends FunSuite:

  // -- Phase 1: RSA key size --

  test("validateRsaKeySize accepts 2048-bit modulus"):
    // A 2048-bit number has a byte array of 256 bytes with the high bit set
    val modulus = new Array[Byte](256)
    modulus(0) = 0x80.toByte // Ensures bitLength >= 2048
    assert(SecurityChecks.validateRsaKeySize(modulus).isRight)

  test("validateRsaKeySize rejects 1024-bit modulus"):
    val modulus = new Array[Byte](128)
    modulus(0) = 0x80.toByte // 1024 bits
    assert(SecurityChecks.validateRsaKeySize(modulus).isLeft)

  test("validateRsaKeySize accepts 4096-bit modulus"):
    val modulus = new Array[Byte](512)
    modulus(0) = 0x80.toByte
    assert(SecurityChecks.validateRsaKeySize(modulus).isRight)

  // -- Phase 1: RSA CRT --

  test("validateRsaCrt accepts matching p * q == n"):
    val p = BigInteger.valueOf(61)
    val q = BigInteger.valueOf(53)
    val n = p.multiply(q) // 3233
    assert(SecurityChecks.validateRsaCrt(n.toByteArray, p.toByteArray, q.toByteArray).isRight)

  test("validateRsaCrt rejects mismatched p * q != n"):
    val p = BigInteger.valueOf(61)
    val q = BigInteger.valueOf(53)
    val wrongN = BigInteger.valueOf(9999)
    assert(SecurityChecks.validateRsaCrt(wrongN.toByteArray, p.toByteArray, q.toByteArray).isLeft)

  // -- Phase 1: Point on curve --

  // NIST P-256 generator point (FIPS 186-4, Section D.1.2.3)
  private val p256Gx: Array[Byte] =
    BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16).toByteArray.dropWhile(_ == 0)

  private val p256Gy: Array[Byte] =
    BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16).toByteArray.dropWhile(_ == 0)

  test("validatePointOnCurve accepts P-256 generator point"):
    assert(SecurityChecks.validatePointOnCurve(EcCurve.P256, p256Gx, p256Gy).isRight)

  test("validatePointOnCurve rejects off-curve point"):
    // (1, 1) is not on P-256
    val x = Array[Byte](1)
    val y = Array[Byte](1)
    assert(SecurityChecks.validatePointOnCurve(EcCurve.P256, x, y).isLeft)

  // -- Phase 1: OKP key length --

  test("validateOkpKeyLength accepts 32-byte Ed25519 key"):
    assert(SecurityChecks.validateOkpKeyLength(OkpCurve.Ed25519, new Array[Byte](32)).isRight)

  test("validateOkpKeyLength rejects wrong length Ed25519 key"):
    assert(SecurityChecks.validateOkpKeyLength(OkpCurve.Ed25519, new Array[Byte](16)).isLeft)

  test("validateOkpKeyLength accepts 57-byte Ed448 key"):
    assert(SecurityChecks.validateOkpKeyLength(OkpCurve.Ed448, new Array[Byte](57)).isRight)

  // -- Phase 2: prePrepare --

  test("prePrepare accepts HMAC key with sufficient size"):
    val key = CryptoKey.Symmetric(new Array[Byte](32))
    assert(SecurityChecks.prePrepare(key, SignAlgorithm.HmacSha256).isRight)

  test("prePrepare rejects undersized HMAC key"):
    val key = CryptoKey.Symmetric(new Array[Byte](16))
    assert(SecurityChecks.prePrepare(key, SignAlgorithm.HmacSha256).isLeft)

  test("prePrepare rejects symmetric key with RSA algorithm"):
    val key = CryptoKey.Symmetric(new Array[Byte](32))
    assert(SecurityChecks.prePrepare(key, SignAlgorithm.RsaPkcs1Sha256).isLeft)

  test("prePrepare accepts RSA public key with RSA algorithm"):
    val modulus = new Array[Byte](256)
    modulus(0) = 0x80.toByte
    val key = CryptoKey.RsaPublic(modulus, Array[Byte](1, 0, 1))
    assert(SecurityChecks.prePrepare(key, SignAlgorithm.RsaPkcs1Sha256).isRight)

  test("prePrepare accepts EC key with matching ECDSA algorithm"):
    val key = CryptoKey.EcPublic(EcCurve.P256, p256Gx, p256Gy)
    assert(SecurityChecks.prePrepare(key, SignAlgorithm.EcdsaP256Sha256).isRight)

  test("prePrepare rejects EC key with mismatched ECDSA algorithm"):
    val key = CryptoKey.EcPublic(EcCurve.P256, p256Gx, p256Gy)
    assert(SecurityChecks.prePrepare(key, SignAlgorithm.EcdsaP384Sha384).isLeft)

  test("prePrepare accepts OKP key with matching EdDSA algorithm"):
    val key = CryptoKey.OkpPublic(OkpCurve.Ed25519, new Array[Byte](32))
    assert(SecurityChecks.prePrepare(key, SignAlgorithm.Ed25519).isRight)

  test("prePrepare rejects OKP key with mismatched EdDSA algorithm"):
    val key = CryptoKey.OkpPublic(OkpCurve.Ed25519, new Array[Byte](32))
    assert(SecurityChecks.prePrepare(key, SignAlgorithm.Ed448).isLeft)

  // -- Phase 3: preVerify --

  test("preVerify delegates to EcParams for ECDSA"):
    // Valid signature for P-256: R=1, S=1
    val sig = new Array[Byte](64)
    sig(31) = 1; sig(63) = 1
    assert(SecurityChecks.preVerify(SignAlgorithm.EcdsaP256Sha256, sig).isRight)

  test("preVerify rejects invalid ECDSA signature"):
    val allZero = new Array[Byte](64)
    assert(SecurityChecks.preVerify(SignAlgorithm.EcdsaP256Sha256, allZero).isLeft)

  test("preVerify checks EdDSA signature length"):
    val validSig = new Array[Byte](64)
    validSig(0) = 1
    assert(SecurityChecks.preVerify(SignAlgorithm.Ed25519, validSig).isRight)

  test("preVerify rejects wrong EdDSA signature length"):
    val wrongLen = new Array[Byte](32)
    wrongLen(0) = 1
    assert(SecurityChecks.preVerify(SignAlgorithm.Ed25519, wrongLen).isLeft)

  test("preVerify passes through for HMAC"):
    assert(SecurityChecks.preVerify(SignAlgorithm.HmacSha256, Array[Byte](1, 2, 3)).isRight)

  test("preVerify passes through for RSA"):
    assert(SecurityChecks.preVerify(SignAlgorithm.RsaPkcs1Sha256, Array[Byte](1, 2, 3)).isRight)
end SecurityChecksSpec
