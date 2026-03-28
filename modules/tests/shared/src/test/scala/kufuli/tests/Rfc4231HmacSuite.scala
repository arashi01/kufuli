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

import zio.Runtime
import zio.Unsafe
import zio.ZIO

import munit.FunSuite

import kufuli.CryptoKey
import kufuli.KufuliError
import kufuli.SignAlgorithm
import kufuli.testkit.HexCodec
import kufuli.zio.given

/** RFC 4231 (December 2005) ss4 HMAC-SHA known-answer test vectors. Cross-platform.
  *
  * Only cases 6 and 7 are applicable: they use 131-byte keys which satisfy the minimum key size
  * requirement of RFC 7518 (May 2015) ss3.2 (key >= hash output length). Cases 1-5 use 4-25 byte
  * keys which kufuli correctly rejects per RFC 7518.
  */
class Rfc4231HmacSuite extends FunSuite:

  private def run[A](zio: ZIO[Any, KufuliError, A]): A =
    Unsafe.unsafe { u ?=>
      Runtime.default.unsafe.run(zio).getOrThrowFiberFailure()
    }

  private def hmacTest(keyHex: String, dataHex: String, expectedHex: String, alg: SignAlgorithm): Unit =
    val key = CryptoKey.symmetric(HexCodec.decode(keyHex)).toOption.get
    val data = HexCodec.decode(dataHex)
    val expected = HexCodec.decode(expectedHex)
    val sig = run(key.prepareSigning(alg).flatMap(_.sign(data)))
    assertEquals(sig.bytes.toSeq, expected.toSeq)

  // 131 bytes of 0xaa
  private val key131 = "aa" * 131

  // Test Case 6: 131-byte key, "Test Using Larger Than Block-Size Key - Hash Key First"
  private val data6 = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374"

  test("RFC 4231 Case 6: HMAC-SHA-256"):
    hmacTest(key131, data6, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", SignAlgorithm.HmacSha256)

  test("RFC 4231 Case 6: HMAC-SHA-384"):
    hmacTest(key131,
             data6,
             "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
             SignAlgorithm.HmacSha384
    )

  test("RFC 4231 Case 6: HMAC-SHA-512"):
    hmacTest(
      key131,
      data6,
      "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
      SignAlgorithm.HmacSha512
    )

  // Test Case 7: 131-byte key, "This is a test using a larger than block-size key and a larger than block-size data..."
  private val data7 =
    "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e"

  test("RFC 4231 Case 7: HMAC-SHA-256"):
    hmacTest(key131, data7, "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2", SignAlgorithm.HmacSha256)

  test("RFC 4231 Case 7: HMAC-SHA-384"):
    hmacTest(key131,
             data7,
             "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
             SignAlgorithm.HmacSha384
    )

  test("RFC 4231 Case 7: HMAC-SHA-512"):
    hmacTest(
      key131,
      data7,
      "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
      SignAlgorithm.HmacSha512
    )

end Rfc4231HmacSuite
