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
package kufuli.testkit

import java.util.Base64

/** RFC test vectors for verifying cryptographic backend implementations. All byte arrays are
  * pre-computed from authoritative RFC sources.
  *
  * @see [[CryptoTestSuite$ CryptoTestSuite]] for abstract test suites consuming these vectors
  */
object RfcVectors:

  // ---------------------------------------------------------------------------
  // RFC 7515 Appendix A.1 - HMAC SHA-256 test vector
  // ---------------------------------------------------------------------------

  /** HMAC-SHA256 symmetric key from RFC 7515 A.1 (JWK "k" field, Base64URL-decoded). 64 bytes (512
    * bits).
    */
  val hmacSha256Key: Array[Byte] =
    Base64.getUrlDecoder.decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")

  /** JWS Signing Input from RFC 7515 A.1 - the ASCII octets of
    * `BASE64URL(header).BASE64URL(payload)`.
    */
  val hmacSha256SigningInput: Array[Byte] = Array[Byte](
    101, 121, 74, 48, 101, 88, 65, 105, 79, 105, 74, 75, 86, 49, 81, 105, 76, 65, 48, 75, 73, 67, 74, 104, 98, 71, 99, 105, 79, 105, 74, 73,
    85, 122, 73, 49, 78, 105, 74, 57, 46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76, 65, 48, 75, 73, 67, 74,
    108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52, 77, 84, 107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72,
    65, 54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118, 98, 83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73,
    106, 112, 48, 99, 110, 86, 108, 102, 81
  )

  /** Expected HMAC-SHA256 signature from RFC 7515 A.1. 32 bytes. */
  val hmacSha256ExpectedSignature: Array[Byte] = Array[Byte](
    116, 24, -33, -76, -105, -103, -32, 37, 79, -6, 96, 125, -40, -83, -69, -70, 22, -44, 37, 77, 105, -42, -65, -16, 91, 88, 5, 88, 83,
    -124, -115, 121
  )

  // ---------------------------------------------------------------------------
  // SHA-2 known-answer test vectors (NIST FIPS 180-4)
  // ---------------------------------------------------------------------------

  /** SHA-256 of empty string. */
  val sha256EmptyDigest: Array[Byte] = hexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

  /** SHA-384 of empty string. */
  val sha384EmptyDigest: Array[Byte] =
    hexToBytes("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")

  /** SHA-512 of empty string. */
  val sha512EmptyDigest: Array[Byte] = hexToBytes(
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
  )

  /** The empty byte array - used as input for empty-string digest tests. */
  val emptyInput: Array[Byte] = Array.empty[Byte]

  private def hexToBytes(hex: String): Array[Byte] =
    hex
      .grouped(2)
      .map(pair => ((Character.digit(pair.charAt(0), 16) << 4) + Character.digit(pair.charAt(1), 16)).toByte)
      .toArray

end RfcVectors
