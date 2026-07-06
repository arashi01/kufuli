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

import scala.compiletime.testing.typeChecks

import kufuli.*

// Node's OWN capability boundary as compile facts. Positive presences are proved by real `summon`
// (compiling IS the proof); absences by `typeChecks`. ML-KEM/XChaCha/GCM-SIV stay off until the
// node:crypto surface is verified against the Node and OpenSSL documentation.
object nodeSubset:
  def run(): Unit =
    val _ = summon[Direct] // node has the synchronous engine
    val _ = summon[Supports[ChaCha20Poly1305]] // node has ChaCha20-Poly1305
    val _ = summon[Supports[AesKwp256]] // node has AES-KWP
    assert(!typeChecks("summon[Supports[MlKem768]]"), "ML-KEM off pending node surface verification")
    assert(!typeChecks("summon[Supports[XChaCha20Poly1305]]"), "no XChaCha in node:crypto")
    assert(!typeChecks("summon[Supports[AesGcmSiv256]]"), "no GCM-SIV in node:crypto")

class NodeSubsetSuite extends munit.FunSuite:
  test("node capability boundary is a compile fact")(nodeSubset.run())
