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

import scala.scalanative.unsafe.Ptr
import scala.scalanative.unsafe.Zone
import scala.scalanative.unsafe.alloc
import scala.scalanative.unsigned.UnsignedRichInt

/** Native memory allocation and copy utilities for C FFI. */
private[kufuli] object NativeMemory:

  /** Allocates native memory and copies a Scala `Array[Byte]` into it. */
  def allocAndCopy(bytes: Array[Byte])(using Zone): Ptr[Byte] =
    val ptr = alloc[Byte](bytes.length.toUSize)
    // scalafix:off DisableSyntax.var, DisableSyntax.while; C FFI buffer copy
    var i = 0
    while i < bytes.length do
      ptr(i) = bytes(i)
      i += 1
    // scalafix:on
    ptr

  /** Copies bytes from native memory to a Scala `Array[Byte]`. */
  def copyFromNative(src: Ptr[Byte], dst: Array[Byte], len: Int): Unit =
    // scalafix:off DisableSyntax.var, DisableSyntax.while; C FFI buffer copy
    var i = 0
    while i < len do
      dst(i) = src(i)
      i += 1
    // scalafix:on

end NativeMemory
