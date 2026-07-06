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

// STRUCTURAL misuse rejection, cross-module (opaque tags are abstract here). Each assert is a safety
// guarantee; a failure means the type system stopped enforcing it. The jose-pairing negative lives
// in JoseSuite; the capability-subset negatives live in the node/browser subset suites.
object coreNegatives:
  // typed placeholders referenced ONLY inside typeChecks strings (compile-time; never evaluated)
  def aeadKey: SecretKey[AesGcm256] = ???
  def aeadKey128: SecretKey[AesGcm128] = ???
  def hmacKey: SecretKey[HmacSha256] = ???
  def xPriv: PrivateKey[X25519] = ???
  def edPub: PublicKey[Ed25519] = ???
  def p256Priv: PrivateKey[P256] = ???
  def p384Pub: PublicKey[P384] = ???
  def ecPub: PublicKey[P256] = ???
  def rsaPriv: PrivateKey[Rsa] = ???
  def box128: SealedBox[AesGcm128] = ???
  def p256Sig: Signature[P256] = ???
  def kemPriv: PrivateKey[MlKem768] = ???
  def kemPub: PublicKey[MlKem768] = ???

  def run(): Unit =
    assert(!typeChecks("aeadKey.sign(Array.emptyByteArray)"), "an AEAD key must not be signable")
    assert(
      !typeChecks("aeadKey.encrypt(Array.emptyByteArray, Array.emptyByteArray, Array.emptyByteArray)"),
      "explicit-nonce encrypt must be handle-only, never on the key"
    )
    assert(!typeChecks("hmacKey.seal(Array.emptyByteArray)"), "an HMAC key must not seal")
    assert(
      !typeChecks("xPriv.sign(Array.emptyByteArray)"),
      "X25519 must not sign - structurally (no shared family with Ed25519), not by carve-out"
    )
    assert(!typeChecks("xPriv.agree(edPub)"), "X25519/Ed25519 are unrelated types")
    assert(!typeChecks("p256Priv.agree(p384Pub)"), "curve mismatch must not typecheck")
    assert(!typeChecks("ecPub.sign(Array.emptyByteArray)"), "a public key must not sign")
    assert(
      !typeChecks("p256Priv.sign(Array.emptyByteArray, Sha1)"),
      "Sha1 is outside SignatureHash: weak-hash signing is unrepresentable"
    )
    assert(!typeChecks("rsaPriv.sign(Array.emptyByteArray)"), "RSA signing requires an explicit padding spec")
    assert(!typeChecks("aeadKey.open(box128)"), "a box sealed under another algorithm must not open")
    assert(!typeChecks("val k: SecretKey[AesGcm256] = aeadKey128"), "algorithm tags are invariant")
    assert(!typeChecks("edPub.verify(Array.emptyByteArray, p256Sig)"), "signature tags thread the family")
    assert(!typeChecks("kemPriv.sign(Array.emptyByteArray)"), "a KEM key must not sign - structurally")
    assert(!typeChecks("kemPriv.agree(kemPub)"), "KEM is encapsulation, not agreement - no agree op exists")
    assert(!typeChecks("ecPub.encapsulate"), "encapsulation exists only for KEM algorithms")
  end run
end coreNegatives

class CoreNegativesSuite extends munit.FunSuite:
  test("15 core structural misuse patterns rejected at compile time")(coreNegatives.run())
