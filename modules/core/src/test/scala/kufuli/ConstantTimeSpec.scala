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

import munit.FunSuite

class ConstantTimeSpec extends FunSuite:

  test("equal arrays return true"):
    val a = Array[Byte](1, 2, 3, 4, 5)
    val b = Array[Byte](1, 2, 3, 4, 5)
    assert(ConstantTime.equals(a, b))

  test("differing arrays return false"):
    val a = Array[Byte](1, 2, 3, 4, 5)
    val b = Array[Byte](1, 2, 3, 4, 6)
    assert(!ConstantTime.equals(a, b))

  test("different lengths return false"):
    val a = Array[Byte](1, 2, 3)
    val b = Array[Byte](1, 2, 3, 4)
    assert(!ConstantTime.equals(a, b))

  test("empty arrays return true"):
    assert(ConstantTime.equals(Array.empty[Byte], Array.empty[Byte]))

  test("one empty one non-empty returns false"):
    assert(!ConstantTime.equals(Array.empty[Byte], Array[Byte](1)))
    assert(!ConstantTime.equals(Array[Byte](1), Array.empty[Byte]))

  test("all-zero arrays of same length return true"):
    val a = new Array[Byte](32)
    val b = new Array[Byte](32)
    assert(ConstantTime.equals(a, b))

  test("single byte difference detected"):
    val a = new Array[Byte](256)
    val b = new Array[Byte](256)
    b(128) = 1
    assert(!ConstantTime.equals(a, b))
end ConstantTimeSpec
