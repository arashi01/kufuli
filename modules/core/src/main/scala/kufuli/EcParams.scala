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

/** ECDSA signature pre-validation (CVE-2022-21449 mitigations). Must be called before passing a
  * signature to any platform signature engine.
  */
private[kufuli] object EcParams:

  /** Validates an ECDSA R||S signature for the given curve. Rejects malformed and trivially
    * forgeable signatures before they reach the platform crypto layer.
    */
  def validateSignature(curve: EcCurve, signature: Array[Byte]): Either[KufuliError, Unit] =
    val sigLen = curve.componentLength * 2
    for
      // Step 1: reject wrong length
      _ <- Either.cond(
             signature.length == sigLen,
             (),
             KufuliError.InvalidSignature(s"Expected $sigLen bytes for ${curve.jwkName}, got ${signature.length}")
           )

      // Step 2: reject all-zero signatures
      _ <- Either.cond(!signature.forall(_ == 0.toByte), (), KufuliError.InvalidSignature("All-zero signature"))

      // Steps 3-6: validate R and S components
      mid = sigLen / 2
      r = BigInteger(1, signature.slice(0, mid))
      s = BigInteger(1, signature.slice(mid, sigLen))
      n = curve.order

      // Step 4: reject R = 0 or S = 0
      _ <- Either.cond(r.signum() > 0 && s.signum() > 0, (), KufuliError.InvalidSignature("R or S component is zero"))

      // Step 5: reject R >= N or S >= N
      _ <- Either.cond(r.compareTo(n) < 0 && s.compareTo(n) < 0, (), KufuliError.InvalidSignature("R or S exceeds curve order"))

      // Step 6: reject R mod N = 0 or S mod N = 0 (redundant given steps 4+5, but spec-mandated)
      _ <- Either.cond(
             r.mod(n).signum() > 0 && s.mod(n).signum() > 0,
             (),
             KufuliError.InvalidSignature("R or S is a multiple of curve order")
           )
    yield ()
    end for
  end validateSignature

end EcParams
