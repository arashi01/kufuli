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

import java.util.Arrays

import boilerplate.effect.EffIO
import boilerplate.effect.useEffIO
import cats.effect.IO

import kufuli.*
import kufuli.tests.support.check
import kufuli.tests.support.expectRight

// Core universal flows (no jose/x509/password, no Direct, no ML-KEM): every use case is a ROUND-TRIP.
// These run on all four artifacts, the browser included (core surface only).
object coreFlows:

  def sealFlow: IO[Unit] =
    val pt = "account-number".getBytes
    for
      key <- IO.fromEither(AesGcm256.key(new Array[Byte](32)))
      box <- expectRight("seal")(key.seal(pt, aad = "user-42".getBytes))
      stored = Array.from(box.bytes) // -> database column
      parsed <- IO.fromEither(SealedBox.of(AesGcm256)(stored))
      back <- expectRight("open")(key.open(parsed, aad = "user-42".getBytes))
      _ <- check(Arrays.equals(back, pt), "seal/open round-trip")
    yield ()

  def keyringFlow: IO[Unit] =
    for
      k1 <- expectRight("gen")(AesGcm256.generate)
      k2 <- expectRight("gen")(AesGcm256.generate)
      legacyBox <- expectRight("legacy-seal")(k1.seal("v".getBytes))
      ring0 <- IO.fromEither(Keyring.of(KeyId.of(1) -> k1))
      box1 <- expectRight("ring-seal")(ring0.seal("a".getBytes))
      ring1 <- IO.fromEither(ring0.rotated(KeyId.of(2) -> k2))
      box2 <- expectRight("ring-seal-2")(ring1.seal("b".getBytes))
      a <- expectRight("open-old-primary")(ring1.open(box1))
      b <- expectRight("open-new-primary")(ring1.open(box2))
      v <- expectRight("open-legacy")(ring1.open(legacyBox))
      _ <- check(new String(a) == "a" && new String(b) == "b" && new String(v) == "v", "rotation round-trips")
      _ <- check(Keyring.of(KeyId.of(7) -> k1, KeyId.of(7) -> k2).isLeft, "duplicate ids rejected at construction")
    yield ()

  def agreeKdfFlow: IO[Unit] =
    for
      client <- expectRight("gen")(X25519.generate)
      server <- expectRight("gen")(X25519.generate)
      wire <- expectRight("export")(server.publicKey.raw)
      serverPub <- IO.fromEither(PublicKey.fromRaw(X25519)(Array.from(wire)))
      z1 <- expectRight("agree")(client.privateKey.agree(serverPub))
      clientWire <- expectRight("export")(client.publicKey.raw)
      clientPub <- IO.fromEither(PublicKey.fromRaw(X25519)(Array.from(clientWire)))
      z2 <- expectRight("agree")(server.privateKey.agree(clientPub))
      _ <- check(Arrays.equals(z1.bytes, z2.bytes), "shared secrets agree")
      prk <- expectRight("extract")(HKDF.extract(Sha256, Array.emptyByteArray, z1))
      iv <- expectRight("expand-label")(HKDF.expandLabel(Sha256, prk, "iv", Array.emptyByteArray, 12))
      _ <- check(iv.length == 12, "iv length")
      _ <- expectRight("expand-key")(HKDF.expandLabelKey(Sha256, prk, "key", Array.emptyByteArray, AesGcm256))
      _ <- expectRight("derive")(z1.deriveKey(Sha256, Array.emptyByteArray, "ctx".getBytes, AesGcm256))
      salted <- expectRight("pbkdf2")(PBKDF2.derive(Sha256, "pencil".getBytes, "salt".getBytes, 4096, 32))
      _ <- check(salted.length == 32, "SCRAM salted password length")
    yield ()

  def signFlows: IO[Unit] =
    val msg = "handshake transcript".getBytes
    for
      ed <- expectRight("gen")(Ed25519.generate)
      sig <- expectRight("sign")(ed.privateKey.sign(msg))
      _ <- expectRight("verify")(ed.publicKey.verify(msg, sig))
      parsed <- IO.fromEither(Signature.fromRaw(Ed25519)(new Array[Byte](64)))
      ec <- expectRight("gen")(P256.generate)
      esig <- expectRight("sign")(ec.privateKey.sign(msg))
      _ <- expectRight("verify")(ec.publicKey.verify(msg, esig))
      esig384 <- expectRight("sign-hash")(ec.privateKey.sign(msg, Sha384))
      _ <- expectRight("verify-hash")(ec.publicKey.verify(msg, esig384, Sha384))
      hk <- expectRight("gen")(HmacSha256.generate)
      hsig <- expectRight("hmac")(hk.sign(msg))
      _ <- expectRight("hmac-verify")(hk.verify(msg, hsig))
      rsa <- expectRight("gen")(Rsa.generate(Rsa.bits(2048)))
      pss <- expectRight("pss")(rsa.privateKey.sign(msg, RsaPss(Sha256)))
      _ <- expectRight("pss-verify")(rsa.publicKey.verify(msg, pss, RsaPss(Sha256)))
      pk1 <- expectRight("pkcs1")(rsa.privateKey.sign(msg, RsaPkcs1(Sha256)))
      _ <- expectRight("pkcs1-verify")(rsa.publicKey.verify(msg, pk1, RsaPkcs1(Sha256)))
      _ <- check(parsed.bytes.length == 64, "ed25519 wire form")
    yield ()
    end for
  end signFlows

  def signerHandleFlow: IO[Unit] =
    for
      ed <- expectRight("gen")(Ed25519.generate)
      sigs <- expectRight("bulk-sign")(
                ed.privateKey.signer.useEffIO(s => EffIO.traverse(List("a", "b", "c"))(m => s.sign(m.getBytes)))
              )
      _ <- check(sigs.size == 3, "three signatures through one handle")
      _ <- expectRight("bulk-verify")(
             ed.publicKey.verifier.useEffIO(v => EffIO.traverse_(sigs)(sig => v.verify("a".getBytes, sig)))
           )
    yield ()

  def pkcs8Flow: IO[Unit] =
    for
      imported <- IO.fromEither(PrivateKey.fromPkcs8(Array[Byte](1, 2, 3)))
      _ <- imported match
             case ImportedPrivateKey.Ec(_, key) => expectRight("ec-branch")(key.sign("m".getBytes, Sha256)).void
             case ImportedPrivateKey.Ed(key)    => expectRight("ed-branch")(key.sign("m".getBytes)).void
             case ImportedPrivateKey.X(_)       => IO.unit // agreement-only; signing is structurally absent
             case ImportedPrivateKey.Kem(_, _)  => IO.unit // decapsulation-only; likewise structural
             case ImportedPrivateKey.OfRsa(key) => expectRight("rsa-branch")(key.sign("m".getBytes, RsaPss(Sha256))).void
    yield ()

  def wrapOaepFlow: IO[Unit] =
    for
      kek <- expectRight("gen")(AesKw256.generate)
      cek <- expectRight("gen")(AesGcm256.generate)
      wrapped <- expectRight("wrap")(kek.wrap(cek))
      _ <- expectRight("unwrap")(kek.unwrap(Array.from(wrapped), as = AesGcm256))
      rsa <- expectRight("gen")(Rsa.generate(Rsa.bits(2048)))
      ct <- expectRight("oaep")(rsa.publicKey.encrypt(new Array[Byte](32), RsaOaep(Sha256)))
      _ <- expectRight("oaep-dec")(rsa.privateKey.decrypt(Array.from(ct), RsaOaep(Sha256)))
    yield ()
end coreFlows

class UniversalFlowsSuite extends munit.CatsEffectSuite:
  test("field encryption with persistence round-trip")(coreFlows.sealFlow)
  test("keyring rotation as a value (id-routing, legacy trial, duplicate rejection)")(coreFlows.keyringFlow)
  test("agree-over-wire -> extract -> expand-label -> target-typed key; PBKDF2 SCRAM shape")(coreFlows.agreeKdfFlow)
  test("sign/verify across families incl. PKCS#1 and PSS")(coreFlows.signFlows)
  test("signer/verifier handles via useEffIO")(coreFlows.signerHandleFlow)
  test("PKCS#8 GADT dispatch")(coreFlows.pkcs8Flow)
  test("wrap/unwrap and RSA-OAEP")(coreFlows.wrapOaepFlow)
