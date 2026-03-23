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
package kufuli.zio

import java.math.BigInteger
import java.security.KeyFactory
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.EdECPoint
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.EdECPublicKeySpec
import java.security.spec.NamedParameterSpec
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPublicKeySpec
import javax.crypto.spec.SecretKeySpec

import zio.IO
import zio.ZIO

import _root_.kufuli.jvm.internal.JcaAlgorithm.*
import _root_.kufuli.jvm.internal.JvmPreparedKey

import kufuli.CryptoKey
import kufuli.EcCurve
import kufuli.KufuliError
import kufuli.OkpCurve
import kufuli.SecurityChecks
import kufuli.SignAlgorithm
import kufuli.Signing
import kufuli.Verifying

/** JVM (JCA) implementation of [[KeyPreparer]]. */
given KeyPreparer with

  extension (key: CryptoKey)

    def prepareSigning(algorithm: SignAlgorithm): IO[KufuliError, PreparedKey[Signing]] =
      prepare(key, algorithm).map(PreparedKey.wrapKey[Signing])

    def prepareVerifying(algorithm: SignAlgorithm): IO[KufuliError, PreparedKey[Verifying]] =
      prepare(key, algorithm).map(PreparedKey.wrapKey[Verifying])

private def prepare(key: CryptoKey, alg: SignAlgorithm): IO[KufuliError, JvmPreparedKey] =
  ZIO.fromEither(SecurityChecks.prePrepare(key, alg)).flatMap { _ =>
    ZIO
      .attempt {
        import scala.language.unsafeNulls
        val jcaKey = toJcaKey(key, alg)
        JvmPreparedKey(jcaKey, alg)
      }
      .mapError(_ => KufuliError.InvalidKey("JCA key construction failed"))
  }

private def toJcaKey(key: CryptoKey, alg: SignAlgorithm): java.security.Key =
  import scala.language.unsafeNulls
  key match
    case CryptoKey.Symmetric(bytes) =>
      SecretKeySpec(bytes, alg.jcaName)

    case CryptoKey.RsaPublic(modulus, exponent) =>
      val spec = RSAPublicKeySpec(BigInteger(1, modulus), BigInteger(1, exponent))
      KeyFactory.getInstance("RSA").generatePublic(spec)

    case CryptoKey.RsaPrivate(modulus, exponent, d, p, q, dp, dq, qi) =>
      val spec = RSAPrivateCrtKeySpec(
        BigInteger(1, modulus),
        BigInteger(1, exponent),
        BigInteger(1, d),
        BigInteger(1, p),
        BigInteger(1, q),
        BigInteger(1, dp),
        BigInteger(1, dq),
        BigInteger(1, qi)
      )
      KeyFactory.getInstance("RSA").generatePrivate(spec)

    case CryptoKey.EcPublic(curve, x, y) =>
      val point = ECPoint(BigInteger(1, x), BigInteger(1, y))
      val ecParams = ecParameterSpec(curve)
      val spec = ECPublicKeySpec(point, ecParams)
      KeyFactory.getInstance("EC").generatePublic(spec)

    case CryptoKey.EcPrivate(curve, x, y, d) =>
      val ecParams = ecParameterSpec(curve)
      val spec = ECPrivateKeySpec(BigInteger(1, d), ecParams)
      KeyFactory.getInstance("EC").generatePrivate(spec)

    case CryptoKey.OkpPublic(curve, xBytes) =>
      val edPoint = okpBytesToEdECPoint(curve, xBytes)
      val namedSpec = NamedParameterSpec(curve.jwkName)
      val spec = EdECPublicKeySpec(namedSpec, edPoint)
      KeyFactory.getInstance("EdDSA").generatePublic(spec)

    case CryptoKey.OkpPrivate(curve, xBytes, d) =>
      val namedSpec = NamedParameterSpec(curve.jwkName)
      val spec = EdECPrivateKeySpec(namedSpec, d)
      KeyFactory.getInstance("EdDSA").generatePrivate(spec)
  end match
end toJcaKey

// AlgorithmParameters lookup avoids generating a throwaway key pair
private def ecParameterSpec(curve: EcCurve): ECParameterSpec =
  import scala.language.unsafeNulls
  val name = curve match
    case EcCurve.P256 => "secp256r1"
    case EcCurve.P384 => "secp384r1"
    case EcCurve.P521 => "secp521r1"
  val params = java.security.AlgorithmParameters.getInstance("EC")
  params.init(ECGenParameterSpec(name))
  params.getParameterSpec(classOf[ECParameterSpec])

/** Converts RFC 8032 little-endian public key bytes to a JCA EdECPoint. */
private def okpBytesToEdECPoint(curve: OkpCurve, xBytes: Array[Byte]): EdECPoint =
  val keyLen = curve.keyLength
  val le = if xBytes.length == keyLen then xBytes.clone() else java.util.Arrays.copyOf(xBytes, keyLen)
  val isXOdd = (le(keyLen - 1) & 0x80) != 0
  le(keyLen - 1) = (le(keyLen - 1) & 0x7f).toByte
  // scalafix:off DisableSyntax.var, DisableSyntax.while; RFC 8032 little-endian to big-endian reversal
  val be = new Array[Byte](keyLen)
  var i = 0
  while i < keyLen do
    be(i) = le(keyLen - 1 - i)
    i += 1
  // scalafix:on
  val y = BigInteger(1, be)
  EdECPoint(isXOdd, y)
end okpBytesToEdECPoint
