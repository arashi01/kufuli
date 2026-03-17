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

import zio.IO

import kufuli.CryptoKey
import kufuli.KufuliError
import kufuli.SignAlgorithm
import kufuli.Signing
import kufuli.Verifying

/** Typeclass for preparing a [[kufuli.CryptoKey CryptoKey]] for signing or verification operations.
  *
  * Key preparation separates the expensive platform import (e.g. JCA key construction, Node.js
  * KeyObject creation) from cheap sign/verify operations. The algorithm is bound at preparation
  * time.
  *
  * @see [[KeyPreparer$ KeyPreparer]] companion for static aliases
  */
trait KeyPreparer:
  extension (key: CryptoKey)
    def prepareSigning(algorithm: SignAlgorithm): IO[KufuliError, PreparedKey[Signing]]
    def prepareVerifying(algorithm: SignAlgorithm): IO[KufuliError, PreparedKey[Verifying]]

/** Static aliases for [[KeyPreparer]] extension methods. */
object KeyPreparer:

  def prepareSigning(key: CryptoKey, algorithm: SignAlgorithm)(using kp: KeyPreparer): IO[KufuliError, PreparedKey[Signing]] =
    kp.prepareSigning(key)(algorithm)

  def prepareVerifying(key: CryptoKey, algorithm: SignAlgorithm)(using kp: KeyPreparer): IO[KufuliError, PreparedKey[Verifying]] =
    kp.prepareVerifying(key)(algorithm)
