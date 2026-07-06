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
package kufuli.jvm.internal

import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

import kufuli.DigestAlgorithm
import kufuli.SignAlgorithm

/** JCA name mappings for kufuli algorithm types. JVM-only extensions. */
private[kufuli] object JcaAlgorithm:

  extension (alg: SignAlgorithm)

    /** JCA algorithm name for `javax.crypto.Mac` or `java.security.Signature`. */
    def jcaName: String = alg match
      case SignAlgorithm.HmacSha256      => "HmacSHA256"
      case SignAlgorithm.HmacSha384      => "HmacSHA384"
      case SignAlgorithm.HmacSha512      => "HmacSHA512"
      case SignAlgorithm.RsaPkcs1Sha256  => "SHA256withRSA"
      case SignAlgorithm.RsaPkcs1Sha384  => "SHA384withRSA"
      case SignAlgorithm.RsaPkcs1Sha512  => "SHA512withRSA"
      case SignAlgorithm.RsaPssSha256    => "RSASSA-PSS"
      case SignAlgorithm.RsaPssSha384    => "RSASSA-PSS"
      case SignAlgorithm.RsaPssSha512    => "RSASSA-PSS"
      case SignAlgorithm.EcdsaP256Sha256 => "SHA256withECDSA"
      case SignAlgorithm.EcdsaP384Sha384 => "SHA384withECDSA"
      case SignAlgorithm.EcdsaP521Sha512 => "SHA512withECDSA"
      case SignAlgorithm.Ed25519         => "EdDSA"
      case SignAlgorithm.Ed448           => "EdDSA"

    /** RSA-PSS parameter spec per RFC 8017 (PKCS#1 v2.2, November 2016). Salt length = hash output
      * length (32/48/64 bytes for SHA-256/384/512). All platform backends use this same salt length
      * convention: OpenSSL `pss_salt_len`, macOS Security.framework default, BCrypt `cbSalt`, and
      * Node.js `RSA_PSS_SALTLEN_DIGEST`.
      */
    def pssParams: Option[PSSParameterSpec] = alg match
      case SignAlgorithm.RsaPssSha256 => Some(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
      case SignAlgorithm.RsaPssSha384 => Some(PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1))
      case SignAlgorithm.RsaPssSha512 => Some(PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1))
      case _                          => None
  end extension

  extension (alg: DigestAlgorithm)

    /** JCA algorithm name for `java.security.MessageDigest`. */
    def jcaName: String = alg match
      case DigestAlgorithm.Sha1   => "SHA-1"
      case DigestAlgorithm.Sha256 => "SHA-256"
      case DigestAlgorithm.Sha384 => "SHA-384"
      case DigestAlgorithm.Sha512 => "SHA-512"

end JcaAlgorithm
