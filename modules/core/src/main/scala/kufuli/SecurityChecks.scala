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

/** Three-phase security validation for cryptographic operations.
  *
  *   - Phase 1: Key construction (point-on-curve, RSA key size, CRT, OKP key length)
  *   - Phase 2: Key preparation (algorithm-key compatibility, HMAC minimum key size per RFC 7518
  *     ss3.2)
  *   - Phase 3: Pre-verification (ECDSA signature validation per CVE-2022-21449, EdDSA signature
  *     length)
  */
object SecurityChecks:

  private val MinRsaKeyBits = 2048

  // ---------------------------------------------------------------------------
  // Phase 1: Key construction validation
  // ---------------------------------------------------------------------------

  /** Validates that an RSA modulus is at least 2048 bits. */
  private[kufuli] def validateRsaKeySize(modulus: Array[Byte]): Either[KufuliError, Unit] =
    val bits = BigInteger(1, modulus).bitLength()
    Either.cond(
      bits >= MinRsaKeyBits,
      (),
      KufuliError.InvalidKey(s"RSA key must be at least $MinRsaKeyBits bits, got $bits")
    )

  /** Validates the RSA CRT invariant: n == p * q. */
  private[kufuli] def validateRsaCrt(
    modulus: Array[Byte],
    p: Array[Byte],
    q: Array[Byte]
  ): Either[KufuliError, Unit] =
    val n = BigInteger(1, modulus)
    val pInt = BigInteger(1, p)
    val qInt = BigInteger(1, q)
    Either.cond(
      pInt.multiply(qInt).compareTo(n) == 0,
      (),
      KufuliError.InvalidKey("RSA CRT check failed: n != p * q")
    )
  end validateRsaCrt

  /** Validates that (x, y) lies on the given elliptic curve using pure BigInteger arithmetic.
    * Verifies coordinates are in range [0, p-1] and satisfy y^2 = x^3 + ax + b (mod p).
    */
  private[kufuli] def validatePointOnCurve(
    curve: EcCurve,
    x: Array[Byte],
    y: Array[Byte]
  ): Either[KufuliError, Unit] =
    val p = EcCurveConstants.prime(curve)
    val curveParams = EcCurveConstants.params(curve)
    val xInt = BigInteger(1, x)
    val yInt = BigInteger(1, y)
    for
      // Coordinates must be in [0, p-1]
      _ <- Either.cond(
             xInt.signum() >= 0 && xInt.compareTo(p) < 0,
             (),
             KufuliError.InvalidKey("EC x coordinate out of range")
           )
      _ <- Either.cond(
             yInt.signum() >= 0 && yInt.compareTo(p) < 0,
             (),
             KufuliError.InvalidKey("EC y coordinate out of range")
           )

      // y^2 mod p == (x^3 + a*x + b) mod p
      lhs = yInt.modPow(BigInteger.TWO, p)
      x3 = xInt.modPow(BigInteger.valueOf(3L), p)
      ax = curveParams.a.multiply(xInt).mod(p)
      rhs = x3.add(ax).add(curveParams.b).mod(p)
      _ <- Either.cond(
             lhs.compareTo(rhs) == 0,
             (),
             KufuliError.InvalidKey("EC point is not on curve")
           )
    yield ()
    end for
  end validatePointOnCurve

  /** Validates that an OKP public key has the correct byte length for its curve. */
  private[kufuli] def validateOkpKeyLength(
    curve: OkpCurve,
    x: Array[Byte]
  ): Either[KufuliError, Unit] =
    Either.cond(
      x.length == curve.keyLength,
      (),
      KufuliError.InvalidKey(s"OKP key length must be ${curve.keyLength} bytes for ${curve.jwkName}, got ${x.length}")
    )

  // ---------------------------------------------------------------------------
  // Phase 2: Key-algorithm compatibility (called from KeyPreparer implementations)
  // ---------------------------------------------------------------------------

  /** Validates that a key is compatible with a signing algorithm, including HMAC minimum key size
    * per RFC 7518 ss3.2.
    */
  def prePrepare(key: CryptoKey, alg: SignAlgorithm): Either[KufuliError, Unit] =
    import CryptoKey.*
    import SignAlgorithm.*

    (key, alg) match
      // HMAC requires symmetric key with minimum size
      case (Symmetric(bytes), HmacSha256) => validateHmacKeySize(bytes, 32)
      case (Symmetric(bytes), HmacSha384) => validateHmacKeySize(bytes, 48)
      case (Symmetric(bytes), HmacSha512) => validateHmacKeySize(bytes, 64)

      // RSA PKCS#1 / PSS accept RSA public or private keys
      case (_: RsaPublic, _: RsaPkcs1Sha256.type | _: RsaPkcs1Sha384.type | _: RsaPkcs1Sha512.type)  => Right(())
      case (_: RsaPrivate, _: RsaPkcs1Sha256.type | _: RsaPkcs1Sha384.type | _: RsaPkcs1Sha512.type) => Right(())
      case (_: RsaPublic, _: RsaPssSha256.type | _: RsaPssSha384.type | _: RsaPssSha512.type)        => Right(())
      case (_: RsaPrivate, _: RsaPssSha256.type | _: RsaPssSha384.type | _: RsaPssSha512.type)       => Right(())

      // ECDSA requires matching curve
      case (k: EcPublic, a)  => validateEcdsaCurveMatch(k.curve, a)
      case (k: EcPrivate, a) => validateEcdsaCurveMatch(k.curve, a)

      // EdDSA requires matching curve
      case (k: OkpPublic, a)  => validateOkpCurveMatch(k.curve, a)
      case (k: OkpPrivate, a) => validateOkpCurveMatch(k.curve, a)

      case _ => Left(KufuliError.InvalidKey(s"Key type is not compatible with algorithm ${alg.toString}"))
    end match
  end prePrepare

  private def validateHmacKeySize(keyBytes: Array[Byte], minBytes: Int): Either[KufuliError, Unit] =
    Either.cond(
      keyBytes.length >= minBytes,
      (),
      KufuliError.InvalidKey(s"HMAC key must be at least ${minBytes * 8} bits, got ${keyBytes.length * 8}")
    )

  private def validateEcdsaCurveMatch(keyCurve: EcCurve, alg: SignAlgorithm): Either[KufuliError, Unit] =
    alg.ecCurve match
      case Some(algCurve) if algCurve == keyCurve => Right(())
      case Some(algCurve) => Left(KufuliError.InvalidKey(s"Key curve ${keyCurve.jwkName} does not match algorithm curve ${algCurve.jwkName}"))
      case None => Left(KufuliError.InvalidKey(s"EC key is not compatible with algorithm ${alg.toString}"))

  private def validateOkpCurveMatch(keyCurve: OkpCurve, alg: SignAlgorithm): Either[KufuliError, Unit] =
    alg.okpCurve match
      case Some(algCurve) if algCurve == keyCurve => Right(())
      case Some(algCurve) => Left(KufuliError.InvalidKey(s"Key curve ${keyCurve.jwkName} does not match algorithm curve ${algCurve.jwkName}"))
      case None => Left(KufuliError.InvalidKey(s"OKP key is not compatible with algorithm ${alg.toString}"))

  // ---------------------------------------------------------------------------
  // Phase 3: Pre-verification (called from Verifier implementations)
  // ---------------------------------------------------------------------------

  /** Validates a signature before passing it to the platform verification engine. */
  def preVerify(alg: SignAlgorithm, signature: Array[Byte]): Either[KufuliError, Unit] =
    alg.ecCurve match
      case Some(curve) => EcParams.validateSignature(curve, signature)
      case None        =>
        alg.okpCurve match
          case Some(curve) =>
            Either.cond(
              signature.length == curve.signatureLength,
              (),
              KufuliError.InvalidSignature
            )
          case None => Right(())

end SecurityChecks
