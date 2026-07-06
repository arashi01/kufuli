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

import cats.effect.IO

import kufuli.*
import kufuli.tests.support.check
import kufuli.tests.support.expectRight

// ML-KEM flows: included only where the backend attests Supports[MlKem*] (JVM >= 25, Native).
object kemFlows:
  def hybridHandshakeFlow: IO[Unit] =
    for
      xClient <- expectRight("gen")(X25519.generate)
      xServer <- expectRight("gen")(X25519.generate)
      xWire <- expectRight("export")(xServer.publicKey.raw)
      zX <- expectRight("agree")(xClient.privateKey.agree(PublicKey.fromRaw(X25519)(Array.from(xWire)).toOption.get))
      kemKp <- expectRight("gen")(MlKem768.generate)
      ekWire <- expectRight("export")(kemKp.publicKey.raw)
      serverSideEk <- IO.fromEither(PublicKey.fromRaw(MlKem768)(Array.from(ekWire)))
      enc <- expectRight("encapsulate")(serverSideEk.encapsulate) // server side: secret + ct
      ctWire = Array.from(enc.ciphertext.bytes) // ct travels server -> client
      parsedCt <- IO.fromEither(KemCiphertext.of(MlKem768)(ctWire))
      zK <- expectRight("decapsulate")(kemKp.privateKey.decapsulate(parsedCt)) // TOTAL: implicit rejection
      _ <- check(Arrays.equals(zK.bytes, enc.secret.bytes), "KEM shared secrets agree")
      hybridIkm = zX.bytes ++ zK.bytes // concatenation is the caller's protocol code
      prk <- expectRight("extract")(HKDF.extract(Sha256, Array.emptyByteArray, hybridIkm))
      _ <- expectRight("expand")(HKDF.expandLabelKey(Sha256, prk, "key", Array.emptyByteArray, AesGcm256))
      _ <- check(KemCiphertext.of(MlKem768)(new Array[Byte](7)).isLeft, "forged-length ct fails at PARSE")
    yield ()
end kemFlows

class KemSuite extends munit.CatsEffectSuite:
  test("hybrid X25519+ML-KEM handshake, both wire hops, forged ct rejected at parse")(kemFlows.hybridHandshakeFlow)
