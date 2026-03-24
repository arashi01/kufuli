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
package kufuli.js.internal

import scala.scalajs.js.typedarray.Uint8Array

/** Conversions between `Array[Byte]` and `Uint8Array`. */
private[kufuli] object ByteConversions:

  /** Converts a Scala `Array[Byte]` to a JS `Uint8Array`. */
  def toUint8Array(bytes: Array[Byte]): Uint8Array =
    // scalafix:off DisableSyntax.var, DisableSyntax.while; byte-level array conversion
    val arr = new Uint8Array(bytes.length)
    var i = 0
    while i < bytes.length do
      arr(i) = (bytes(i) & 0xff).toShort
      i += 1
    // scalafix:on
    arr

  /** Converts a JS `Uint8Array` to a Scala `Array[Byte]`. */
  def toByteArray(uint8: Uint8Array): Array[Byte] =
    // scalafix:off DisableSyntax.var, DisableSyntax.while; byte-level array conversion
    val arr = new Array[Byte](uint8.length)
    var i = 0
    while i < uint8.length do
      arr(i) = uint8(i).toByte
      i += 1
    // scalafix:on
    arr
end ByteConversions
