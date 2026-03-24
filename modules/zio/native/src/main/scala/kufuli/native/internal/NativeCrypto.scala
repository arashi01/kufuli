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

import scala.scalanative.unsafe.CInt
import scala.scalanative.unsafe.CSize
import scala.scalanative.unsafe.Ptr
import scala.scalanative.unsafe.extern

/** Scala Native FFI bindings to the kufuli C crypto functions.
  *
  * Symbols are provided by C source files in `resources/scala-native/` (compiled and linked
  * automatically by Scala Native). No `@link` annotation needed since symbols come from our own C
  * compilation unit, not an external library.
  */
@extern
private[kufuli] object NativeCrypto:

  def kufuli_sign(
    algId: CInt,
    key: Ptr[Byte],
    keyLen: CSize,
    data: Ptr[Byte],
    dataLen: CSize,
    sigOut: Ptr[Byte],
    sigLen: Ptr[CSize]
  ): CInt = extern

  def kufuli_verify(
    algId: CInt,
    key: Ptr[Byte],
    keyLen: CSize,
    data: Ptr[Byte],
    dataLen: CSize,
    sig: Ptr[Byte],
    sigLen: CSize
  ): CInt = extern

  def kufuli_digest(
    algId: CInt,
    data: Ptr[Byte],
    dataLen: CSize,
    out: Ptr[Byte],
    outLen: Ptr[CSize]
  ): CInt = extern

end NativeCrypto
