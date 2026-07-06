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

import boilerplate.Slice
import boilerplate.effect.EffIO
import cats.effect.IO

import kufuli.*
import kufuli.tests.support.check
import kufuli.unsafe as U

// Direct-gated per-record paths (absent from the browser artifact, which is the browser-subset
// claim): the record machine speaking one zero-copy vocabulary, Slice.
object directFlows:

  def tlsRecordFlow: IO[Unit] =
    val key = AesGcm256.key(new Array[Byte](32)).toOption.get
    val iv = new Array[Byte](12)
    val record = "application data record".getBytes
    key.cipher.use { c =>
      val nonceBuf = new Array[Byte](12)
      val nonce = Slice.of(nonceBuf)
      val out = Slice.of(new Array[Byte](record.length + 16))
      val plain = Slice.of(new Array[Byte](record.length))
      for
        _ <- IO(Nonce.xorInto(iv, sequence = 7, nonceBuf, 0))
        n <- IO.fromEither(c.encrypt(out, Slice.of(record), Slice.empty, nonce))
        _ <- check(n == record.length + 16, "ct||tag length")
        wire = out.take(n)
        m <- IO.fromEither(c.decrypt(plain, wire, Slice.empty, nonce))
        _ <- check(m == record.length && Arrays.equals(plain.toArray, record), "record round-trip")
        bridged <- EffIO.delay(c.encrypt(out, Slice.of(record), Slice.empty, nonce)).either
        _ <- check(bridged.exists(_ == record.length + 16), "EffIO.delay bridge")
      yield ()
    }
  end tlsRecordFlow

  def budgetFlow: IO[Unit] =
    val key = AesGcm256.key(new Array[Byte](32)).toOption.get
    key.cipher(AeadLimits(encryptions = 1, bytes = 1024, decryptFailures = 4)).use { c =>
      val nonce = Slice.of(new Array[Byte](12))
      val out = Slice.of(new Array[Byte](64))
      for
        first <- IO(c.encrypt(out, Slice.of("a".getBytes), Slice.empty, nonce))
        _ <- check(first.isRight, "first encryption within budget")
        _ <- check(c.budget.encryptionsRemaining == 0, "budget observable BEFORE exhaustion bites")
        second <- IO(c.encrypt(out, Slice.of("b".getBytes), Slice.empty, nonce))
        _ <- check(second.isLeft, "second encryption exhausts the budget")
      yield ()
    }
  end budgetFlow

  def transcriptFlow: IO[Unit] =
    Sha256.hasher.use { h =>
      for
        _ <- IO(h.update("ClientHello".getBytes))
        d1 <- IO(h.digestNow)
        _ <- IO(h.update(Slice.of("ServerHello".getBytes)))
        d2 <- IO(h.digestNow)
        _ <- check(d1.bytes.length == 32 && d2.bytes.length == 32, "transcript snapshots")
      yield ()
    }

  def quicHpFlow: IO[Unit] =
    val sample = Slice.of(Array.tabulate[Byte](16)(_.toByte))
    val mask = Slice.of(new Array[Byte](5))
    val block = Slice.of(new Array[Byte](16))
    for
      _ <- U.HeaderProtection.aes(new Array[Byte](16)).use(hp => IO(hp.mask(sample, mask)))
      _ <- check(mask.toArray(0) == 0, "aes hp mask (stub copies sample[0])")
      _ <- U.HeaderProtection.chacha(new Array[Byte](32)).use(hp => IO(hp.mask(sample, mask)))
      _ <- check(mask.toArray(0) == 0x42, "chacha hp mask (stub keystream)")
      _ <- U.AesBlock.of(new Array[Byte](16)).use(b => IO(b.encrypt(sample, block)))
      _ <- check(block.toArray(3) == sample.toArray(3), "raw block")
    yield ()
  end quicHpFlow
end directFlows

class DirectSuite extends munit.CatsEffectSuite:
  test("TLS/QUIC record path both directions through Slice, EffIO.delay bridge")(directFlows.tlsRecordFlow)
  test("AEAD budget enforced inside the handle and observable")(directFlows.budgetFlow)
  test("transcript snapshots (Sha256.hasher)")(directFlows.transcriptFlow)
  test("QUIC header-protection masks (kufuli.unsafe)")(directFlows.quicHpFlow)
