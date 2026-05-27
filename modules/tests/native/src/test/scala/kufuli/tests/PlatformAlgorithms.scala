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
package kufuli.tests

import boilerplate.Platform

import kufuli.SignAlgorithm

/** Scala Native: EdDSA support is OS-conditional. OpenSSL (Linux) implements Ed25519 and Ed448
  * since 1.1.1, while Security.framework on macOS and BCrypt on Windows do not expose EdDSA
  * primitives at all. Branches on [[boilerplate.Platform]] reduce to a compile-time constant
  * because exactly one OS source directory is selected when the toolchain links the binary.
  */
object PlatformAlgorithms:

  def supports(alg: SignAlgorithm): Boolean = alg match
    case SignAlgorithm.Ed25519 | SignAlgorithm.Ed448 => Platform.linux
    case _                                           => true
