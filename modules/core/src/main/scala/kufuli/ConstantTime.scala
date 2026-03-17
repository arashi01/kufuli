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

/** Constant-time byte array comparison to prevent timing side-channel attacks. */
private[kufuli] object ConstantTime:

  /** Compares two byte arrays in constant time. On length mismatch, compares `a` against itself
    * (always zero) but returns `false` via the `lenMatch` guard - no short-circuit, no recursion,
    * single pass.
    */
  def equals(a: Array[Byte], b: Array[Byte]): Boolean =
    // Hotpath: single-pass constant-time comparison avoids timing side-channels.
    // Mutable accumulator + tight loop prevents branch-based short-circuit that
    // would leak information about which byte position differs.
    val lenMatch = a.length == b.length
    val cmp = if lenMatch then b else a
    // scalafix:off DisableSyntax.var, DisableSyntax.while; security-critical constant-time loop
    var result = 0
    var i = 0
    while i < a.length do
      result |= (a(i) ^ cmp(i))
      i += 1
    // scalafix:on
    result == 0 && lenMatch
  end equals
end ConstantTime
