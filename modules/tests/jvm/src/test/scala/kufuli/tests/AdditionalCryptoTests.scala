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
import kufuli.EcCurve
import kufuli.KufuliError
import kufuli.OkpCurve
import kufuli.SignAlgorithm
import kufuli.Signature
import kufuli.zio.given

/** Additional integration tests: cross-curve ECDSA round-trips, Ed25519 RFC 8032 (January 2017)
  * deterministic vectors, and negative/rejection tests.
  */
class AdditionalCryptoTests extends FunSuite:

  private def run[A](zio: ZIO[Any, KufuliError, A]): A =
    Unsafe.unsafe { u ?=>
      Runtime.default.unsafe.run(zio).getOrThrowFiberFailure()
    }

  // ---------------------------------------------------------------------------
  // Cross-curve ECDSA round-trip tests (P-384 and P-521)
  // ---------------------------------------------------------------------------

  test("ECDSA P-384 SHA-384 sign-verify round-trip"):
    // Generate a JCA P-384 key pair for a proper round-trip test
    val kpg = java.security.KeyPairGenerator.getInstance("EC")
    kpg.initialize(java.security.spec.ECGenParameterSpec("secp384r1"))
    val kp = kpg.generateKeyPair()
    val ecPub = kp.getPublic.asInstanceOf[java.security.interfaces.ECPublicKey] // scalafix:ok DisableSyntax.asInstanceOf; JCA test helper
    val ecPriv = kp.getPrivate.asInstanceOf[java.security.interfaces.ECPrivateKey] // scalafix:ok DisableSyntax.asInstanceOf; JCA test helper
    def pad(b: Array[Byte], len: Int): Array[Byte] =
      val stripped = b.dropWhile(_ == 0)
      if stripped.length >= len then stripped.takeRight(len)
      else Array.fill[Byte](len - stripped.length)(0) ++ stripped
    val x = pad(ecPub.getW.getAffineX.toByteArray, 48)
    val y = pad(ecPub.getW.getAffineY.toByteArray, 48)
    val d = pad(ecPriv.getS.toByteArray, 48)
    val privKey = CryptoKey.ecPrivate(EcCurve.P384, x, y, d).toOption.get
    val pubKey = CryptoKey.ecPublic(EcCurve.P384, x, y).toOption.get
    val data = "ECDSA P-384 round-trip test".getBytes("UTF-8")
    val sig = run(privKey.prepareSigning(SignAlgorithm.EcdsaP384Sha384).flatMap(_.sign(data)))
    assertEquals(sig.bytes.length, 96) // R||S = 48 + 48
    run(pubKey.prepareVerifying(SignAlgorithm.EcdsaP384Sha384).flatMap(_.verify(data, sig)))

  test("ECDSA P-521 SHA-512 sign-verify round-trip"):
    // Generate a P-521 key pair via JCA for a proper round-trip test
    val kpg = java.security.KeyPairGenerator.getInstance("EC")
    kpg.initialize(java.security.spec.ECGenParameterSpec("secp521r1"))
    val kp = kpg.generateKeyPair()
    val ecPub = kp.getPublic.asInstanceOf[java.security.interfaces.ECPublicKey] // scalafix:ok DisableSyntax.asInstanceOf; JCA test helper
    val ecPriv = kp.getPrivate.asInstanceOf[java.security.interfaces.ECPrivateKey] // scalafix:ok DisableSyntax.asInstanceOf; JCA test helper
    val x = ecPub.getW.getAffineX.toByteArray.dropWhile(_ == 0)
    val y = ecPub.getW.getAffineY.toByteArray.dropWhile(_ == 0)
    val d = ecPriv.getS.toByteArray.dropWhile(_ == 0)
    // Pad coordinates to 66 bytes (P-521 component length)
    def pad66(b: Array[Byte]): Array[Byte] =
      if b.length >= 66 then b.takeRight(66)
      else Array.fill[Byte](66 - b.length)(0) ++ b
    val privKey = CryptoKey.ecPrivate(EcCurve.P521, pad66(x), pad66(y), pad66(d)).toOption.get
    val pubKey = CryptoKey.ecPublic(EcCurve.P521, pad66(x), pad66(y)).toOption.get
    val data = "ECDSA P-521 round-trip test".getBytes("UTF-8")
    val sig = run(privKey.prepareSigning(SignAlgorithm.EcdsaP521Sha512).flatMap(_.sign(data)))
    assertEquals(sig.bytes.length, 132) // R||S = 66 + 66
    run(pubKey.prepareVerifying(SignAlgorithm.EcdsaP521Sha512).flatMap(_.verify(data, sig)))

  // ---------------------------------------------------------------------------
  // Ed25519 sign-verify round-trip test (JVM-only, JCA EdDSA)
  // Deterministic known-answer verification covered by WycheproofEd25519Suite (150 vectors).
  // ---------------------------------------------------------------------------

  test("Ed25519 sign-verify round-trip"):
    // Generate a JCA Ed25519 key pair and extract raw bytes via DER encoding
    val kpg = java.security.KeyPairGenerator.getInstance("Ed25519")
    val kp = kpg.generateKeyPair()
    // Extract raw 32-byte seed from PKCS#8 DER (last 32 bytes)
    val pkcs8 = kp.getPrivate.getEncoded
    val seed = java.util.Arrays.copyOfRange(pkcs8, pkcs8.length - 32, pkcs8.length)
    // Extract raw 32-byte public key from X.509 DER (last 32 bytes)
    val x509 = kp.getPublic.getEncoded
    val rawPub = java.util.Arrays.copyOfRange(x509, x509.length - 32, x509.length)
    // Sign with JCA directly to get a reference signature, then verify through kufuli
    val jcaSig = java.security.Signature.getInstance("Ed25519")
    jcaSig.initSign(kp.getPrivate)
    val data = "Ed25519 round-trip test".getBytes("UTF-8")
    jcaSig.update(data)
    val refSigBytes = jcaSig.sign()
    // Verify the JCA signature through kufuli's pipeline
    val pubKey = CryptoKey.okpPublic(OkpCurve.Ed25519, rawPub).toOption.get
    run(pubKey.prepareVerifying(SignAlgorithm.Ed25519).flatMap(_.verify(data, Signature.raw(refSigBytes))))
    // Also do a full kufuli sign-then-verify round-trip
    val privKey = CryptoKey.okpPrivate(OkpCurve.Ed25519, rawPub, seed).toOption.get
    val sig = run(privKey.prepareSigning(SignAlgorithm.Ed25519).flatMap(_.sign(data)))
    assertEquals(sig.bytes.length, 64)
    run(pubKey.prepareVerifying(SignAlgorithm.Ed25519).flatMap(_.verify(data, sig)))

  // ---------------------------------------------------------------------------
  // Negative/rejection tests
  // ---------------------------------------------------------------------------

  test("Signature.ecdsaConcat rejects r=0 for P-256"):
    val sig = new Array[Byte](64)
    sig(63) = 1 // S = 1, R = 0
    assert(Signature.ecdsaConcat(sig, EcCurve.P256).isLeft)

  test("Signature.ecdsaConcat rejects s=0 for P-256"):
    val sig = new Array[Byte](64)
    sig(31) = 1 // R = 1, S = 0
    assert(Signature.ecdsaConcat(sig, EcCurve.P256).isLeft)

  test("Signature.ecdsaConcat rejects r >= n for P-256"):
    val sig = new Array[Byte](64)
    java.util.Arrays.fill(sig, 0, 32, 0xff.toByte) // R = max
    sig(63) = 1 // S = 1
    assert(Signature.ecdsaConcat(sig, EcCurve.P256).isLeft)

  test("Signature.ecdsaConcat rejects s >= n for P-256"):
    val sig = new Array[Byte](64)
    sig(31) = 1 // R = 1
    java.util.Arrays.fill(sig, 32, 64, 0xff.toByte) // S = max
    assert(Signature.ecdsaConcat(sig, EcCurve.P256).isLeft)

  test("Signature.ecdsaConcat rejects wrong length"):
    val sig = new Array[Byte](32)
    sig(31) = 1
    assert(Signature.ecdsaConcat(sig, EcCurve.P256).isLeft)

  test("Signature.ecdsaConcat rejects all zeros"):
    val sig = new Array[Byte](64)
    assert(Signature.ecdsaConcat(sig, EcCurve.P256).isLeft)

  test("RSA PKCS#1 verification rejects signature made with wrong hash algorithm"):
    val privKey = CryptoKey
      .rsaPrivate(
        kufuli.testkit.RfcVectors.rsaModulus,
        kufuli.testkit.RfcVectors.rsaExponent,
        kufuli.testkit.RfcVectors.rsaD,
        kufuli.testkit.RfcVectors.rsaP,
        kufuli.testkit.RfcVectors.rsaQ,
        kufuli.testkit.RfcVectors.rsaDp,
        kufuli.testkit.RfcVectors.rsaDq,
        kufuli.testkit.RfcVectors.rsaQi
      )
      .toOption
      .get
    val pubKey = CryptoKey.rsaPublic(kufuli.testkit.RfcVectors.rsaModulus, kufuli.testkit.RfcVectors.rsaExponent).toOption.get
    val data = "hash mismatch test".getBytes("UTF-8")
    // Sign with SHA-256
    val sig = run(privKey.prepareSigning(SignAlgorithm.RsaPkcs1Sha256).flatMap(_.sign(data)))
    // Verify expecting SHA-512 - must fail
    intercept[Throwable]:
      run(pubKey.prepareVerifying(SignAlgorithm.RsaPkcs1Sha512).flatMap(_.verify(data, sig)))

end AdditionalCryptoTests
