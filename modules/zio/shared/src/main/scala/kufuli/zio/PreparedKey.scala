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

/** Platform-specific prepared key representation.
  *
  * This base trait carries no algorithm information. Operation-specific subtraits
  * ([[SigningKeyInternal]], and future encryption/key-agreement variants) add the appropriate
  * algorithm type. Platform backends extend the relevant subtrait.
  */
private[kufuli] trait PreparedKeyInternal

/** Subtrait for prepared keys bound to a signing algorithm. */
private[kufuli] trait SigningKeyInternal extends PreparedKeyInternal:
  def signAlgorithm: kufuli.SignAlgorithm

/** Opaque wrapper around a platform-specific prepared key, tagged with a phantom
  * [[kufuli.KeyRole KeyRole]] marker.
  *
  * Instances are constructed via [[KeyPreparer]] and consumed by [[Signer]] and [[Verifier]]. No
  * public API shall return `PreparedKey[SymmetricRole]` - preparers always return specific role
  * types (`PreparedKey[Signing]`, `PreparedKey[Verifying]`, etc.).
  *
  * @see [[PreparedKey$ PreparedKey]] companion for factory operations
  */
opaque type PreparedKey[+R <: KeyRole] = PreparedKeyInternal

/** Factory and unwrap operations for [[PreparedKey]].
  *
  * Extends [[boilerplate.OpaqueType OpaqueType]] per project constraints. `CanEqual` is
  * intentionally omitted (no [[boilerplate.OpaqueType$.Eq Eq]] mixin) - comparing prepared keys is
  * not a meaningful operation and would be misleading. Platform backends use [[wrapKey]] and
  * [[unwrapKey]] for typed construction and extraction.
  */
object PreparedKey extends OpaqueType[PreparedKey[KeyRole], PreparedKeyInternal]:
  type Error = KufuliError

  inline def wrap(value: PreparedKeyInternal): PreparedKey[KeyRole] = value
  inline def unwrap(value: PreparedKey[KeyRole]): PreparedKeyInternal = value
  inline def apply(inline value: PreparedKeyInternal): PreparedKey[KeyRole] = fromUnsafe(value)
  protected inline def validate(value: PreparedKeyInternal): Option[KufuliError] = None

  private[kufuli] def wrapKey[R <: KeyRole](internal: PreparedKeyInternal): PreparedKey[R] = internal
  private[kufuli] def unwrapKey[R <: KeyRole](key: PreparedKey[R]): PreparedKeyInternal = key
