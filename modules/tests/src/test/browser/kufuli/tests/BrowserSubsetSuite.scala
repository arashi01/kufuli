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

// The browser SUBSET as compile facts: in the WebCrypto artifact (all capability aliases false) the
// gated surface must fail to resolve while the universal surface stays available. Positive presences
// are proved by real `summon`; absences by `typeChecks`.
object browserSubset:
  def aeadKey: SecretKey[AesGcm256] = ??? // referenced only inside a typeChecks string

  def run(): Unit =
    // available: the universal set (WebCrypto composes CBC-HS)
    val _ = summon[Supports[AesGcm256]]
    val _ = summon[Supports[AesKw128]]
    val _ = summon[Supports[A128CbcHs256]]
    // absent: each is a compile error with a capability-specific message, not a runtime surprise
    assert(!typeChecks("summon[Supports[ChaCha20Poly1305]]"), "no ChaCha20-Poly1305 in WebCrypto")
    assert(!typeChecks("ChaCha20Poly1305.generate"), "generating an unusable key is equally impossible")
    assert(!typeChecks("summon[Supports[AesKwp256]]"), "no AES-KWP in WebCrypto")
    assert(!typeChecks("summon[Direct]"), "WebCrypto is async-only: no synchronous engine")
    assert(!typeChecks("aeadKey.cipher"), "no Cipher handles without Direct")
    assert(!typeChecks("Sha256.hasher"), "no incremental hashing without Direct")
    assert(!typeChecks("summon[Supports[kufuli.password.Argon2id]]"), "no Argon2 on the browser")
    assert(!typeChecks("summon[Supports[MlKem768]]"), "no WebCrypto ML-KEM")
    assert(!typeChecks("MlKem768.generate"), "generating an unusable KEM keypair is equally impossible")
    assert(!typeChecks("summon[Supports[XChaCha20Poly1305]]"), "no XChaCha in WebCrypto")
    assert(!typeChecks("summon[Supports[AesGcmSiv256]]"), "no GCM-SIV in WebCrypto")
  end run
end browserSubset

class BrowserSubsetSuite extends munit.FunSuite:
  test("browser capability boundary is a compile fact")(browserSubset.run())
