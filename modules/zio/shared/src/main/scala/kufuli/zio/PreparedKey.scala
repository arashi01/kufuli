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

import boilerplate.OpaqueType

import kufuli.KeyRole
import kufuli.KufuliError

/** Internal marker for platform-specific prepared key representations. Algorithm binding lives in
  * subtraits such as [[SigningKeyInternal]].
  */
private[kufuli] trait PreparedKeyInternal

/** Signing-algorithm-bound prepared key. RSA backends expose the modulus via [[rsaModulus]] so
  * pre-verification can reject signatures whose integer value is not less than the modulus per RFC
  * 8017 (November 2016) ss5.2.2 step 1.
  */
private[kufuli] trait SigningKeyInternal extends PreparedKeyInternal:
  def signAlgorithm: kufuli.SignAlgorithm
  def rsaModulus: Option[Array[Byte]]

/** Opaque platform-prepared key tagged with a phantom [[kufuli.KeyRole KeyRole]]. Produced by
  * [[KeyPreparer]] and consumed by [[Signer]] / [[Verifier]]; the role parameter prevents using a
  * verifying key for signing (and vice versa) at compile time.
  *
  * @see [[PreparedKey$ PreparedKey]] companion.
  */
opaque type PreparedKey[+R <: KeyRole] = PreparedKeyInternal

/** Factory and extractor for [[PreparedKey]]. `CanEqual` is intentionally not provided: prepared
  * keys wrap platform handles whose reference equality has no meaningful semantics.
  */
object PreparedKey extends OpaqueType[PreparedKey[KeyRole], PreparedKeyInternal]:
  type Error = KufuliError

  inline def wrap(value: PreparedKeyInternal): PreparedKey[KeyRole] = value
  inline def unwrap(value: PreparedKey[KeyRole]): PreparedKeyInternal = value
  inline def apply(inline value: PreparedKeyInternal): PreparedKey[KeyRole] = fromUnsafe(value)
  protected inline def validate(value: PreparedKeyInternal): Option[KufuliError] = None

  private[kufuli] def wrapKey[R <: KeyRole](internal: PreparedKeyInternal): PreparedKey[R] = internal
  private[kufuli] def unwrapKey[R <: KeyRole](key: PreparedKey[R]): PreparedKeyInternal = key
