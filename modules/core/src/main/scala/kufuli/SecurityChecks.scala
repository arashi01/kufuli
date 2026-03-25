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
  *   - Phase 1: Key construction (point-on-curve, RSA key size per NIST SP 800-131A Rev. 2 (March
  *     2019), CRT invariant, EC private scalar range, OKP key length)
  *   - Phase 2: Key preparation (algorithm-key compatibility, signing direction - public keys
  *     rejected for signing, HMAC minimum key size per RFC 7518 (May 2015) ss3.2)
  *   - Phase 3: Pre-verification (ECDSA signature component range per CVE-2022-21449 / NIST FIPS
  *     186-5 (February 2023), EdDSA signature length per RFC 8032 (January 2017))
  */
private[kufuli] object SecurityChecks:

  /** Minimum RSA key size per NIST SP 800-131A Rev. 2 (March 2019) ss2. */
  private val MinRsaKeyBits = 2048

  // ---------------------------------------------------------------------------
  // Phase 1: Key construction validation
  // ---------------------------------------------------------------------------

  /** Validates that an RSA modulus is at least 2048 bits per NIST SP 800-131A Rev. 2 (March 2019). */
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
    *
    * Note: uses `BigInteger.modPow` which is not constant-time. This is acceptable because this
    * method is called during key construction (not a repeated operation on secret data), and the
    * public key coordinates are not secret.
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
      lhs = yInt.modPow(BigInteger.valueOf(2L), p)
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

  /** Validates that an EC private key scalar d is in [1, n-1] per SEC 1 v2 (May 2009) ss3.2.1. */
  private[kufuli] def validateEcPrivateScalar(
    curve: EcCurve,
    d: Array[Byte]
  ): Either[KufuliError, Unit] =
    val dInt = BigInteger(1, d)
    Either.cond(
      dInt.signum() > 0 && dInt.compareTo(curve.order) < 0,
      (),
      KufuliError.InvalidKey("EC private key scalar d is not in [1, n-1]")
    )

  /** Validates that an OKP public key has the correct byte length for its curve per RFC 8032
    * (January 2017).
    */
  private[kufuli] def validateOkpKeyLength(
    curve: OkpCurve,
    x: Array[Byte]
  ): Either[KufuliError, Unit] =
    Either.cond(
      x.length == curve.keyLength,
      (),
      KufuliError.InvalidKey(s"OKP key length must be ${curve.keyLength} bytes for ${curve.jwkName}, got ${x.length}")
    )

  /** Validates that an OKP private key seed has the correct byte length for its curve per RFC 8032
    * (January 2017). Ed25519 seeds are 32 bytes; Ed448 seeds are 57 bytes.
    */
  private[kufuli] def validateOkpPrivateKeyLength(
    curve: OkpCurve,
    d: Array[Byte]
  ): Either[KufuliError, Unit] =
    Either.cond(
      d.length == curve.keyLength,
      (),
      KufuliError.InvalidKey(s"OKP private key seed must be ${curve.keyLength} bytes for ${curve.jwkName}, got ${d.length}")
    )

  // ---------------------------------------------------------------------------
  // Phase 2: Key-algorithm compatibility (called from KeyPreparer implementations)
  // ---------------------------------------------------------------------------

  /** Validates that a key can produce signatures. Symmetric keys can both sign and verify; for
    * asymmetric algorithms, only private keys can sign.
    */
  def validateSigningRole(key: CryptoKey): Either[KufuliError, Unit] =
    import CryptoKey.*
    key match
      case _: Symmetric | _: RsaPrivate | _: EcPrivate | _: OkpPrivate => Right(())
      case _ => Left(KufuliError.InvalidKey("Public keys cannot be used for signing"))

  /** Validates that a key is compatible with a signing algorithm, including HMAC minimum key size
    * per RFC 7518 (May 2015) ss3.2.
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
              KufuliError.InvalidSignature(
                s"Expected ${curve.signatureLength} bytes for ${curve.jwkName}, got ${signature.length}"
              )
            )
          case None => Right(())

end SecurityChecks
