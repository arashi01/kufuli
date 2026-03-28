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

/** Cryptographic signature produced by a signing operation or received for verification.
  *
  * For ECDSA, the internal representation is fixed-length R||S concatenation (JWS / IEEE P1363
  * format per RFC 7515 (May 2015) ss3.4). Construct from either format via
  * [[Signature$.ecdsaConcat]] or [[Signature$.ecdsaDer]]; convert to either format via
  * [[Signature.toEcdsaConcat]] or [[Signature.toEcdsaDer]].
  *
  * For HMAC, RSA, and EdDSA, the signature bytes have no format ambiguity. Use [[Signature$.raw]].
  *
  * `CanEqual` is intentionally omitted: the underlying `Array[Byte]` representation makes `==`
  * reference equality, producing silently wrong results. Under strict equality this is a compile
  * error. Timing-safe comparison for HMAC signatures is handled internally by
  * [[kufuli.zio.Verifier]].
  *
  * @see [[Signature$ Signature]] companion for construction and format conversion
  */
opaque type Signature = Array[Byte]

/** Smart constructors and format conversion for [[Signature]].
  *
  * Does not extend [[boilerplate.OpaqueType OpaqueType]] because the smart constructors require
  * additional parameters beyond the wrapped value ([[ecdsaConcat]] and [[ecdsaDer]] take an
  * [[EcCurve]]), which cannot be expressed via `OpaqueType.from(value: Repr)`. Additionally,
  * `OpaqueType.wrap` is public and would bypass defensive cloning and ECDSA validation.
  *
  * `CanEqual` is intentionally omitted: array-backed `==` is reference equality, producing silently
  * wrong results. Under strict equality this is a compile error.
  */
object Signature:

  /** Wraps raw signature bytes. For HMAC, RSA, and EdDSA signatures where the wire format is
    * unambiguous. Defensively clones the input.
    */
  def raw(bytes: Array[Byte]): Signature = bytes.clone()

  /** Constructs a Signature from fixed-length R||S ECDSA format (JWS / IEEE P1363 per RFC 7515 (May
    * 2015) ss3.4). Validates component range per NIST FIPS 186-5 (February 2023): rejects zero,
    * out-of-range, and trivially forgeable R/S values (CVE-2022-21449 mitigation).
    */
  def ecdsaConcat(rs: Array[Byte], curve: EcCurve): Either[KufuliError, Signature] =
    EcParams.validateSignature(curve, rs).map(_ => rs.clone(): Signature)

  /** Constructs a Signature from DER-encoded ECDSA format (X.509 / SEC 1 v2 (May 2009) C.8).
    * Transcodes to internal R||S representation and validates component range.
    */
  def ecdsaDer(der: Array[Byte], curve: EcCurve): Either[KufuliError, Signature] =
    EcdsaCodec
      .derToConcat(der, curve.componentLength)
      .flatMap(rs => EcParams.validateSignature(curve, rs).map(_ => rs: Signature))

  extension (sig: Signature)

    /** Returns a defensive copy of the raw signature bytes. */
    def bytes: Array[Byte] = sig.clone()

    /** Converts to DER-encoded ECDSA format (SEC 1 v2 (May 2009) C.8). Only meaningful for ECDSA
      * signatures in R||S format.
      */
    def toEcdsaDer: Either[KufuliError, Array[Byte]] =
      EcdsaCodec.concatToDer(sig)

    /** Returns a copy of the R||S bytes. Only meaningful for ECDSA signatures. Validates length
      * against the given curve.
      */
    def toEcdsaConcat(curve: EcCurve): Either[KufuliError, Array[Byte]] =
      val expected = curve.componentLength * 2
      Either.cond(
        sig.length == expected,
        sig.clone(),
        KufuliError.InvalidSignature(s"Expected $expected bytes for ${curve.jwkName} R||S, got ${sig.length}")
      )

  end extension

  /** Wraps raw bytes without cloning. For internal use by platform backends that produce freshly
    * allocated signature bytes.
    */
  private[kufuli] def wrapRaw(bytes: Array[Byte]): Signature = bytes

  /** Extracts raw bytes without cloning. For internal use by platform backends. */
  private[kufuli] def unwrapRaw(sig: Signature): Array[Byte] = sig

end Signature
