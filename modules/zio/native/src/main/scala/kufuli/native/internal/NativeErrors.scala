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

import kufuli.KufuliError

/** Maps C error codes to [[kufuli.KufuliError KufuliError]] instances. */
private[kufuli] object NativeErrors:

  private val Unsupported = 1
  private val InvalidKey = 2
  private val InvalidSignature = 6

  /** Converts a non-zero C error code from `kufuli_sign` to a [[kufuli.KufuliError KufuliError]]. */
  def signError(code: Int): KufuliError = code match
    case Unsupported => KufuliError.UnsupportedAlgorithm("Native platform does not support this algorithm")
    case InvalidKey  => KufuliError.InvalidKey("Native key import failed")
    case _           => KufuliError.SignatureFailure("Native signing failed")

  /** Converts a non-zero C error code from `kufuli_verify` to a [[kufuli.KufuliError KufuliError]]. */
  def verifyError(code: Int): KufuliError = code match
    case Unsupported      => KufuliError.UnsupportedAlgorithm("Native platform does not support this algorithm")
    case InvalidKey       => KufuliError.InvalidKey("Native key import failed")
    case InvalidSignature => KufuliError.InvalidSignature("Signature verification failed")
    case _                => KufuliError.VerificationFailure("Native verification failed")

  /** Converts a non-zero C error code from `kufuli_digest` to a [[kufuli.KufuliError KufuliError]]. */
  def digestError(code: Int): KufuliError = code match
    case Unsupported => KufuliError.UnsupportedAlgorithm("Native platform does not support this algorithm")
    case _           => KufuliError.DigestFailure("Native digest computation failed")

end NativeErrors
