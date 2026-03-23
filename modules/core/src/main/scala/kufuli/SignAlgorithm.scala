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

/** Signing algorithm identifiers for all supported JWS algorithm families. */
enum SignAlgorithm derives CanEqual:

  // HMAC with SHA-2 (RFC 7518 ss3.2)
  case HmacSha256, HmacSha384, HmacSha512

  // RSASSA-PKCS1-v1_5 (RFC 7518 ss3.3)
  case RsaPkcs1Sha256, RsaPkcs1Sha384, RsaPkcs1Sha512

  // RSASSA-PSS (RFC 7518 ss3.5)
  case RsaPssSha256, RsaPssSha384, RsaPssSha512

  // ECDSA (RFC 7518 ss3.4)
  case EcdsaP256Sha256, EcdsaP384Sha384, EcdsaP521Sha512

  // EdDSA (RFC 8037)
  case Ed25519, Ed448
end SignAlgorithm

object SignAlgorithm:

  // Family union types for internal pattern matching (private per core_requirements.md ss5.5)
  private[kufuli] type HmacAlgorithm = HmacSha256.type | HmacSha384.type | HmacSha512.type
  private[kufuli] type RsaPkcs1Algorithm = RsaPkcs1Sha256.type | RsaPkcs1Sha384.type | RsaPkcs1Sha512.type
  private[kufuli] type RsaPssAlgorithm = RsaPssSha256.type | RsaPssSha384.type | RsaPssSha512.type
  private[kufuli] type RsaAlgorithm = RsaPkcs1Algorithm | RsaPssAlgorithm
  private[kufuli] type EcdsaAlgorithm = EcdsaP256Sha256.type | EcdsaP384Sha384.type | EcdsaP521Sha512.type
  private[kufuli] type OkpAlgorithm = Ed25519.type | Ed448.type

  extension (alg: SignAlgorithm)

    /** The digest algorithm used internally by this signing algorithm. Returns `None` for EdDSA
      * algorithms, which handle hashing internally (Ed25519 uses SHA-512, Ed448 uses SHAKE256).
      */
    def digestAlgorithm: Option[DigestAlgorithm] = alg match
      case HmacSha256 | RsaPkcs1Sha256 | RsaPssSha256 | EcdsaP256Sha256 => Some(DigestAlgorithm.Sha256)
      case HmacSha384 | RsaPkcs1Sha384 | RsaPssSha384 | EcdsaP384Sha384 => Some(DigestAlgorithm.Sha384)
      case HmacSha512 | RsaPkcs1Sha512 | RsaPssSha512 | EcdsaP521Sha512 => Some(DigestAlgorithm.Sha512)
      case Ed25519 | Ed448                                              => None

    /** JWS "alg" header value per RFC 7518 ss3.1. */
    inline def jwsName: String = inline alg match
      case HmacSha256      => "HS256"
      case HmacSha384      => "HS384"
      case HmacSha512      => "HS512"
      case RsaPkcs1Sha256  => "RS256"
      case RsaPkcs1Sha384  => "RS384"
      case RsaPkcs1Sha512  => "RS512"
      case RsaPssSha256    => "PS256"
      case RsaPssSha384    => "PS384"
      case RsaPssSha512    => "PS512"
      case EcdsaP256Sha256 => "ES256"
      case EcdsaP384Sha384 => "ES384"
      case EcdsaP521Sha512 => "ES512"
      case Ed25519         => "EdDSA"
      case Ed448           => "EdDSA"

    /** The associated EC curve, if this is an ECDSA algorithm. */
    def ecCurve: Option[EcCurve] = alg match
      case EcdsaP256Sha256 => Some(EcCurve.P256)
      case EcdsaP384Sha384 => Some(EcCurve.P384)
      case EcdsaP521Sha512 => Some(EcCurve.P521)
      case _               => None

    /** The associated OKP curve, if this is an EdDSA algorithm. */
    def okpCurve: Option[OkpCurve] = alg match
      case Ed25519 => Some(OkpCurve.Ed25519)
      case Ed448   => Some(OkpCurve.Ed448)
      case _       => None
  end extension
end SignAlgorithm
