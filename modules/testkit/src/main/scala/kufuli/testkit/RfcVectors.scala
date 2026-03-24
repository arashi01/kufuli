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
  // RFC 7515 Appendix A.2 - RSASSA-PKCS1-v1_5 SHA-256 test vector
  // ---------------------------------------------------------------------------

  /** JWS Signing Input from RFC 7515 A.2 - ASCII octets of `BASE64URL(header).BASE64URL(payload)`
    * with `{"alg":"RS256"}` header.
    */
  val rsaSha256SigningInput: Array[Byte] = Array[Byte](
    101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 74, 57, 46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105,
    74, 113, 98, 50, 85, 105, 76, 65, 48, 75, 73, 67, 74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52, 77, 84, 107, 122, 79, 68,
    65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72, 65, 54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118, 98,
    83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73, 106, 112, 48, 99, 110, 86, 108, 102, 81
  )

  /** RSA-2048 public modulus from RFC 7515 A.2 JWK "n" field. */
  val rsaModulus: Array[Byte] = b64url(
    "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs" +
      "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV" +
      "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
  )

  /** RSA public exponent from RFC 7515 A.2 JWK "e" field. */
  val rsaExponent: Array[Byte] = b64url("AQAB")

  /** RSA private exponent from RFC 7515 A.2 JWK "d" field. */
  val rsaD: Array[Byte] = b64url(
    "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0" +
      "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT" +
      "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"
  )

  /** RSA prime p from RFC 7515 A.2 JWK "p" field. */
  val rsaP: Array[Byte] = b64url(
    "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG" +
      "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"
  )

  /** RSA prime q from RFC 7515 A.2 JWK "q" field. */
  val rsaQ: Array[Byte] = b64url(
    "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA" +
      "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"
  )

  /** RSA CRT exponent dp from RFC 7515 A.2 JWK "dp" field. */
  val rsaDp: Array[Byte] = b64url(
    "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb" +
      "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0"
  )

  /** RSA CRT exponent dq from RFC 7515 A.2 JWK "dq" field. */
  val rsaDq: Array[Byte] = b64url(
    "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky" +
      "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU"
  )

  /** RSA CRT coefficient qi from RFC 7515 A.2 JWK "qi" field. */
  val rsaQi: Array[Byte] = b64url(
    "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU" +
      "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
  )

  /** Expected RSA PKCS#1 v1.5 SHA-256 signature from RFC 7515 A.2. 256 bytes. PKCS#1 v1.5 is
    * deterministic so this value can be verified as exact output.
    */
  val rsaSha256ExpectedSignature: Array[Byte] = Array[Byte](
    112, 46, 33, -119, 67, -24, -113, -47, 30, -75, -40, 45, -65, 120, 69, -13, 65, 6, -82, 27, -127, -1, -9, 115, 17, 22, -83, -47, 113,
    125, -125, 101, 109, 66, 10, -3, 60, -106, -18, -35, 115, -94, 102, 62, 81, 102, 104, 123, 0, 11, -121, 34, 110, 1, -121, -19, 16, 115,
    -7, 69, -27, -126, -83, -4, -17, 22, -40, 90, 121, -114, -24, -58, 109, -37, 61, -72, -105, 91, 23, -48, -108, 2, -66, -19, -43, -39,
    -39, 112, 7, 16, -115, -78, -127, 96, -43, -8, 4, 12, -89, 68, 87, 98, -72, 31, -66, 127, -7, -39, 46, 10, -25, 111, 36, -14, 91, 51,
    -69, -26, -12, 74, -26, 30, -79, 4, 10, -53, 32, 4, 77, 62, -7, 18, -114, -44, 1, 48, 121, 91, -44, -67, 59, 65, -18, -54, -48, 102, -85,
    101, 25, -127, -3, -28, -115, -9, 127, 55, 45, -61, -117, -97, -81, -35, 59, -17, -79, -117, 93, -93, -52, 60, 46, -80, 47, -98, 58, 65,
    -42, 18, -54, -83, 21, -111, 18, 115, -96, 95, 35, -71, -24, 56, -6, -81, -124, -99, 105, -124, 41, -17, 90, 30, -120, 121, -126, 54,
    -61, -44, 14, 96, 69, 34, -91, 68, -56, -14, 122, 122, 45, -72, 6, 99, -47, 108, -9, -54, -22, 86, -34, 64, 92, -78, 33, 90, 69, -78,
    -62, 85, 102, -75, 90, -63, -89, 72, -96, 112, -33, -56, -93, 42, 70, -107, 67, -48, 25, -18, -5, 71
  )

  // ---------------------------------------------------------------------------
  // RFC 7515 Appendix A.3 - ECDSA P-256 SHA-256 test vector
  // ---------------------------------------------------------------------------

  /** JWS Signing Input from RFC 7515 A.3 - ASCII octets with `{"alg":"ES256"}` header. */
  val ecdsaP256SigningInput: Array[Byte] = Array[Byte](
    101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 70, 85, 122, 73, 49, 78, 105, 74, 57, 46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105,
    74, 113, 98, 50, 85, 105, 76, 65, 48, 75, 73, 67, 74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52, 77, 84, 107, 122, 79, 68,
    65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72, 65, 54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118, 98,
    83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73, 106, 112, 48, 99, 110, 86, 108, 102, 81
  )

  /** EC P-256 public key x coordinate from RFC 7515 A.3 JWK. */
  val ecP256X: Array[Byte] = b64url("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")

  /** EC P-256 public key y coordinate from RFC 7515 A.3 JWK. */
  val ecP256Y: Array[Byte] = b64url("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")

  /** EC P-256 private key d from RFC 7515 A.3 JWK. */
  val ecP256D: Array[Byte] = b64url("jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI")

  /** Expected ECDSA P-256 SHA-256 R||S signature from RFC 7515 A.3. 64 bytes (32 + 32). ECDSA is
    * non-deterministic so this can only be used for VERIFY tests, not sign output comparison.
    */
  val ecdsaP256ExpectedSignature: Array[Byte] = Array[Byte](
    14, -47, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, -44, 2, -93, -78, 40, 3, 58, -7, 124, 126, 23, -127, -102, -61, 22, -98, -90,
    101, -59, 10, 7, -45, -116, 60, 112, -27, -40, -15, 45, -81, 8, 74, 84, -128, -90, 101, -112, -59, -14, -109, 80, -102, -113, 63, 127,
    -118, -125, -93, 84, -43
  )

  // ---------------------------------------------------------------------------
  // SHA digest known-answer test vectors (NIST FIPS 180-4)
  // ---------------------------------------------------------------------------

  /** SHA-1 of empty string. */
  val sha1EmptyDigest: Array[Byte] = hexToBytes("da39a3ee5e6b4b0d3255bfef95601890afd80709")

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

  private def b64url(s: String): Array[Byte] =
    Base64.getUrlDecoder.decode(s)

end RfcVectors
