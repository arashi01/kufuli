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

import zio.ZIO

import kufuli.CryptoKey
import kufuli.EcCurve
import kufuli.OkpCurve
import kufuli.SignAlgorithm
import kufuli.Signature
import kufuli.testkit.RfcVectors
import kufuli.zio.given

/** Cross-platform sign-then-verify round-trips for the curves and EdDSA algorithm not covered by
  * the testkit's primary `CryptoTestSuite`, plus algorithm-agility negative tests. Uses fixed key
  * pairs from RFC 6979 (August 2013) and RFC 8032 (January 2017) so all platforms can produce a
  * signature without depending on platform-specific key generation.
  */
class RoundTripCryptoSuite extends AsyncCryptoSuite:

  test("ECDSA P-384 SHA-384 sign-verify round-trip"):
    val privKey = CryptoKey.ecPrivate(EcCurve.P384, RfcVectors.ecP384X, RfcVectors.ecP384Y, RfcVectors.ecP384D).toOption.get
    val pubKey = CryptoKey.ecPublic(EcCurve.P384, RfcVectors.ecP384X, RfcVectors.ecP384Y).toOption.get
    val data = "ECDSA P-384 round-trip test".getBytes("UTF-8")
    runIo:
      for
        sig <- privKey.prepareSigning(SignAlgorithm.EcdsaP384Sha384).flatMap(_.sign(data))
        _ = assertEquals(sig.bytes.length, 96) // R||S = 48 + 48
        _ <- pubKey.prepareVerifying(SignAlgorithm.EcdsaP384Sha384).flatMap(_.verify(data, sig))
      yield ()

  test("ECDSA P-521 SHA-512 sign-verify round-trip"):
    val privKey = CryptoKey.ecPrivate(EcCurve.P521, RfcVectors.ecP521X, RfcVectors.ecP521Y, RfcVectors.ecP521D).toOption.get
    val pubKey = CryptoKey.ecPublic(EcCurve.P521, RfcVectors.ecP521X, RfcVectors.ecP521Y).toOption.get
    val data = "ECDSA P-521 round-trip test".getBytes("UTF-8")
    runIo:
      for
        sig <- privKey.prepareSigning(SignAlgorithm.EcdsaP521Sha512).flatMap(_.sign(data))
        _ = assertEquals(sig.bytes.length, 132) // R||S = 66 + 66
        _ <- pubKey.prepareVerifying(SignAlgorithm.EcdsaP521Sha512).flatMap(_.verify(data, sig))
      yield ()

  test("Ed25519 sign produces RFC 8032 ss7.1 TEST 1 deterministic signature"):
    assume(PlatformAlgorithms.supports(SignAlgorithm.Ed25519), "Ed25519 not supported on this platform")
    val privKey = CryptoKey.okpPrivate(OkpCurve.Ed25519, RfcVectors.ed25519PublicKey, RfcVectors.ed25519Seed).toOption.get
    runIo(privKey.prepareSigning(SignAlgorithm.Ed25519).flatMap(_.sign(Array.emptyByteArray))).map { sig =>
      assertEquals(sig.bytes.toSeq, RfcVectors.ed25519EmptySignature.toSeq)
    }

  test("Ed25519 sign-verify round-trip"):
    assume(PlatformAlgorithms.supports(SignAlgorithm.Ed25519), "Ed25519 not supported on this platform")
    val privKey = CryptoKey.okpPrivate(OkpCurve.Ed25519, RfcVectors.ed25519PublicKey, RfcVectors.ed25519Seed).toOption.get
    val pubKey = CryptoKey.okpPublic(OkpCurve.Ed25519, RfcVectors.ed25519PublicKey).toOption.get
    val data = "Ed25519 round-trip test".getBytes("UTF-8")
    runIo:
      for
        sig <- privKey.prepareSigning(SignAlgorithm.Ed25519).flatMap(_.sign(data))
        _ = assertEquals(sig.bytes.length, 64)
        _ <- pubKey.prepareVerifying(SignAlgorithm.Ed25519).flatMap(_.verify(data, sig))
      yield ()

  test("RSA PKCS#1 verification rejects signature made with different hash algorithm"):
    val privKey = CryptoKey
      .rsaPrivate(
        RfcVectors.rsaModulus,
        RfcVectors.rsaExponent,
        RfcVectors.rsaD,
        RfcVectors.rsaP,
        RfcVectors.rsaQ,
        RfcVectors.rsaDp,
        RfcVectors.rsaDq,
        RfcVectors.rsaQi
      )
      .toOption
      .get
    val pubKey = CryptoKey.rsaPublic(RfcVectors.rsaModulus, RfcVectors.rsaExponent).toOption.get
    val data = "hash mismatch test".getBytes("UTF-8")
    val program =
      privKey
        .prepareSigning(SignAlgorithm.RsaPkcs1Sha256)
        .flatMap(_.sign(data))
        .flatMap { sig =>
          pubKey
            .prepareVerifying(SignAlgorithm.RsaPkcs1Sha512)
            .flatMap(_.verify(data, sig))
            .as(false)
            .catchAll(_ => ZIO.succeed(true))
        }
    runIo(program).map(rejected => assert(rejected, "Cross-hash signature should not verify"))

end RoundTripCryptoSuite
