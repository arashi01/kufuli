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

import scala.util.control.NoStackTrace

/** Error ADT for all kufuli cryptographic operations.
  *
  * [[InvalidSignature]] indicates structurally invalid signature bytes (wrong length, malformed
  * DER, component out of range). [[SignatureMismatch]] indicates a well-formed signature that does
  * not verify against the provided data and key. This distinction allows consumers to differentiate
  * client errors (malformed input) from cryptographic rejection (potential attack or wrong key).
  */
enum KufuliError extends Throwable with NoStackTrace derives CanEqual:
  case UnsupportedAlgorithm(message: String)
  case InvalidKey(message: String)
  case InvalidSignature(message: String)
  case SignatureMismatch(message: String)
  case SignatureFailure(message: String)
  case VerificationFailure(message: String)
  case DigestFailure(message: String)

  override def getMessage: String = this match
    case UnsupportedAlgorithm(message) => s"Unsupported algorithm: $message"
    case InvalidKey(message)           => s"Invalid key: $message"
    case InvalidSignature(message)     => s"Invalid signature: $message"
    case SignatureMismatch(message)    => s"Signature mismatch: $message"
    case SignatureFailure(message)     => s"Signature failure: $message"
    case VerificationFailure(message)  => s"Verification failure: $message"
    case DigestFailure(message)        => s"Digest failure: $message"
end KufuliError
