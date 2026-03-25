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
package kufuli.native.internal

import _root_.kufuli.CryptoKey
import _root_.kufuli.EcCurve
import _root_.kufuli.OkpCurve

/** ASN.1 DER encoding of [[kufuli.CryptoKey CryptoKey]] variants for the Native C layer.
  *
  * Returns raw bytes for symmetric keys, SubjectPublicKeyInfo (RFC 5280 (May 2008)) DER for public
  * keys, and PKCS#8 PrivateKeyInfo (RFC 5958 (August 2010)) DER for private keys. EC private keys
  * use the ECPrivateKey structure from RFC 5915 (June 2010). EdDSA key encoding follows RFC 8410
  * (August 2018). RSA keys use PKCS#1 (RFC 8017 (November 2016)) structures wrapped in the
  * appropriate outer format.
  */
private[kufuli] object DerCodec:

  // -- DER tag constants --

  private val TagInteger: Byte = 0x02
  private val TagBitString: Byte = 0x03
  private val TagOctetString: Byte = 0x04
  private val TagNull: Byte = 0x05
  private val TagSequence: Byte = 0x30
  private val TagContextual1: Byte = 0xa1.toByte

  // -- Pre-encoded OIDs (tag + length + value) --

  /** OID 1.2.840.113549.1.1.1 (rsaEncryption) */
  private val OidRsa: Array[Byte] =
    Array[Byte](0x06, 0x09, 0x2a, 0x86.toByte, 0x48, 0x86.toByte, 0xf7.toByte, 0x0d, 0x01, 0x01, 0x01)

  /** OID 1.2.840.10045.2.1 (ecPublicKey) */
  private val OidEc: Array[Byte] =
    Array[Byte](0x06, 0x07, 0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x3d, 0x02, 0x01)

  /** OID 1.2.840.10045.3.1.7 (P-256 / secp256r1) */
  private val OidP256: Array[Byte] =
    Array[Byte](0x06, 0x08, 0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x3d, 0x03, 0x01, 0x07)

  /** OID 1.3.132.0.34 (P-384 / secp384r1) */
  private val OidP384: Array[Byte] =
    Array[Byte](0x06, 0x05, 0x2b, 0x81.toByte, 0x04, 0x00, 0x22)

  /** OID 1.3.132.0.35 (P-521 / secp521r1) */
  private val OidP521: Array[Byte] =
    Array[Byte](0x06, 0x05, 0x2b, 0x81.toByte, 0x04, 0x00, 0x23)

  /** OID 1.3.101.112 (Ed25519) */
  private val OidEd25519: Array[Byte] =
    Array[Byte](0x06, 0x03, 0x2b, 0x65, 0x70)

  /** OID 1.3.101.113 (Ed448) */
  private val OidEd448: Array[Byte] =
    Array[Byte](0x06, 0x03, 0x2b, 0x65, 0x71)

  /** OID 1.3.101.110 (X25519) per RFC 8410 (August 2018) */
  private val OidX25519: Array[Byte] =
    Array[Byte](0x06, 0x03, 0x2b, 0x65, 0x6e)

  // -- Public API --

  /** Encodes a [[kufuli.CryptoKey CryptoKey]] to bytes for the C layer. */
  def encode(key: CryptoKey): Array[Byte] = key match
    case CryptoKey.Symmetric(bytes)                                   => bytes
    case CryptoKey.RsaPublic(modulus, exponent)                       => encodeRsaPublic(modulus, exponent)
    case CryptoKey.RsaPrivate(modulus, exponent, d, p, q, dp, dq, qi) => encodeRsaPrivate(modulus, exponent, d, p, q, dp, dq, qi)
    case CryptoKey.EcPublic(curve, x, y)                              => encodeEcPublic(curve, x, y)
    case CryptoKey.EcPrivate(curve, x, y, d)                          => encodeEcPrivate(curve, x, y, d)
    case CryptoKey.OkpPublic(curve, x)                                => encodeOkpPublic(curve, x)
    case CryptoKey.OkpPrivate(curve, _, d)                            => encodeOkpPrivate(curve, d)

  // -- DER primitives --

  /** Encodes a DER length. */
  private def derLength(length: Int): Array[Byte] =
    if length < 128 then Array(length.toByte)
    else if length < 256 then Array(0x81.toByte, length.toByte)
    else Array(0x82.toByte, (length >> 8).toByte, (length & 0xff).toByte)

  /** Wraps content in a DER TLV (tag-length-value). */
  private def derTlv(tag: Byte, content: Array[Byte]): Array[Byte] =
    Array(tag) ++ derLength(content.length) ++ content

  /** Encodes an unsigned big-endian byte array as a DER INTEGER. */
  private def derInteger(bytes: Array[Byte]): Array[Byte] =
    val stripped = bytes.dropWhile(_ == 0) match
      case a if a.isEmpty => Array(0.toByte)
      case a              => a
    val content = if (stripped(0) & 0x80) != 0 then Array(0.toByte) ++ stripped else stripped
    derTlv(TagInteger, content)

  /** Encodes a small non-negative value as a DER INTEGER. */
  private def derSmallInt(value: Int): Array[Byte] =
    derTlv(TagInteger, Array(value.toByte))

  /** Wraps content bytes in a DER SEQUENCE. */
  private def derSequence(parts: Array[Byte]*): Array[Byte] =
    val body = parts.foldLeft(Array.empty[Byte])(_ ++ _)
    derTlv(TagSequence, body)

  /** Wraps content bytes in a DER OCTET STRING. */
  private def derOctetString(content: Array[Byte]): Array[Byte] =
    derTlv(TagOctetString, content)

  /** Wraps content bytes in a DER BIT STRING (with zero padding bits). */
  private def derBitString(content: Array[Byte]): Array[Byte] =
    derTlv(TagBitString, Array(0x00.toByte) ++ content)

  /** DER NULL encoding. */
  private val DerNull: Array[Byte] = Array(TagNull, 0x00)

  // -- RSA --

  /** SubjectPublicKeyInfo for RSA public key. */
  private def encodeRsaPublic(modulus: Array[Byte], exponent: Array[Byte]): Array[Byte] =
    val algorithmId = derSequence(OidRsa, DerNull)
    val rsaPubKey = derSequence(derInteger(modulus), derInteger(exponent))
    derSequence(algorithmId, derBitString(rsaPubKey))

  /** PKCS#8 PrivateKeyInfo for RSA private key. */
  private def encodeRsaPrivate(
    modulus: Array[Byte],
    exponent: Array[Byte],
    d: Array[Byte],
    p: Array[Byte],
    q: Array[Byte],
    dp: Array[Byte],
    dq: Array[Byte],
    qi: Array[Byte]
  ): Array[Byte] =
    val algorithmId = derSequence(OidRsa, DerNull)
    val rsaPrivKey = derSequence(
      derSmallInt(0),
      derInteger(modulus),
      derInteger(exponent),
      derInteger(d),
      derInteger(p),
      derInteger(q),
      derInteger(dp),
      derInteger(dq),
      derInteger(qi)
    )
    derSequence(derSmallInt(0), algorithmId, derOctetString(rsaPrivKey))
  end encodeRsaPrivate

  // -- EC (ECDSA) --

  private def ecCurveOid(curve: EcCurve): Array[Byte] = curve match
    case EcCurve.P256 => OidP256
    case EcCurve.P384 => OidP384
    case EcCurve.P521 => OidP521

  /** Uncompressed EC point: 04 || x || y */
  private def uncompressedPoint(x: Array[Byte], y: Array[Byte]): Array[Byte] =
    Array(0x04.toByte) ++ x ++ y

  /** SubjectPublicKeyInfo for EC public key. */
  private def encodeEcPublic(curve: EcCurve, x: Array[Byte], y: Array[Byte]): Array[Byte] =
    val algorithmId = derSequence(OidEc, ecCurveOid(curve))
    derSequence(algorithmId, derBitString(uncompressedPoint(x, y)))

  /** PKCS#8 PrivateKeyInfo for EC private key (RFC 5915 ECPrivateKey inside PKCS#8). */
  private def encodeEcPrivate(curve: EcCurve, x: Array[Byte], y: Array[Byte], d: Array[Byte]): Array[Byte] =
    val algorithmId = derSequence(OidEc, ecCurveOid(curve))
    // ECPrivateKey ::= SEQUENCE { version 1, privateKey d, [1] publicKey }
    val publicKeyBits = derBitString(uncompressedPoint(x, y))
    val contextual1 = derTlv(TagContextual1, publicKeyBits)
    val ecPrivKey = derSequence(derSmallInt(1), derOctetString(d), contextual1)
    derSequence(derSmallInt(0), algorithmId, derOctetString(ecPrivKey))

  // -- OKP (EdDSA / X25519) --

  private def okpCurveOid(curve: OkpCurve): Array[Byte] = curve match
    case OkpCurve.Ed25519 => OidEd25519
    case OkpCurve.Ed448   => OidEd448
    case OkpCurve.X25519  => OidX25519

  /** SubjectPublicKeyInfo for OKP public key. */
  private def encodeOkpPublic(curve: OkpCurve, x: Array[Byte]): Array[Byte] =
    val algorithmId = derSequence(okpCurveOid(curve))
    derSequence(algorithmId, derBitString(x))

  /** PKCS#8 PrivateKeyInfo for OKP private key (CurvePrivateKey per RFC 8410). */
  private def encodeOkpPrivate(curve: OkpCurve, d: Array[Byte]): Array[Byte] =
    val algorithmId = derSequence(okpCurveOid(curve))
    // CurvePrivateKey ::= OCTET STRING (the raw private key bytes)
    val curvePrivKey = derOctetString(d)
    derSequence(derSmallInt(0), algorithmId, derOctetString(curvePrivKey))

end DerCodec
