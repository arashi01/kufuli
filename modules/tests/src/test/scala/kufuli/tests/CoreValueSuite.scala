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
package kufuli.tests

import java.util.Arrays

import kufuli.*

// Pure value-layer checks; these run on every artifact, browser included.
class CoreValueSuite extends munit.FunSuite:

  test("nonce derivation (RFC 8446 sec 5.3): XOR self-inverse, low bytes carry the sequence") {
    val iv = Array.tabulate[Byte](12)(i => (i * 3).toByte)
    val n1 = Nonce.xor(iv, 0x0102030405060708L)
    assert(!Arrays.equals(n1, iv), "nonce differs from iv")
    assert(Arrays.equals(Nonce.xor(n1, 0x0102030405060708L), iv), "xor self-inverse")
    assert(Nonce.xor(iv, 0L).sameElements(iv), "sequence 0 is identity")
  }

  test("key import validation carries diagnostics (never secrets)") {
    assert(
      AesGcm256.key(new Array[Byte](31)) match
        case Left(InvalidKey.WrongLength(32, 31)) => true
        case _                                    => false,
      "AES-256 key length diagnostic"
    )
    assert(HmacSha256.key(new Array[Byte](16)).isLeft, "HMAC key below hash length rejected")
    assert(HmacSha256.key(new Array[Byte](48)).isRight, "HMAC accepts longer keys")
    assert(PublicKey.fromRaw(X25519)(new Array[Byte](31)).isLeft, "X25519 wire key must be 32 bytes")
  }

  test("programmer-error domains are defects (require), not error values") {
    val _ = intercept[IllegalArgumentException](Rsa.bits(1024))
    val _ = intercept[IllegalArgumentException](AeadLimits(0, 1, 1))
  }

  test("value-type persistence round-trips") {
    val digest = Digest.of(Array.fill[Byte](32)(7)).toOption.get
    assert(digest.hex.length == 64 && digest.eqv(digest), "digest hex + constant-time eqv")
    assert(Digest.of(new Array[Byte](15)).isLeft, "digest length validated")
    assert(SealedBox.of(AesGcm256)(new Array[Byte](5)).isLeft, "truncated box rejected at parse")
    assert(SealedBox.of(AesGcm256)(Array.fill[Byte](64)(9)).isLeft, "unknown layout version rejected at parse")
    assert(Signature.fromRaw(Ed25519)(new Array[Byte](63)).isLeft, "ed25519 signature is 64 bytes")
    assert(Signature.fromRaw(P256)(new Array[Byte](64)).isRight, "P-256 raw r||s is 64 bytes")
    assert(PEM.decode("no pem here").isLeft && PEM.decode("-----BEGIN X-----").isRight, "PEM parse")
  }
end CoreValueSuite
