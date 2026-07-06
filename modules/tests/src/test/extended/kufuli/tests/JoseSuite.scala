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

import cats.effect.IO

import kufuli.*
import kufuli.jose.*
import kufuli.tests.support.check
import kufuli.tests.support.expectRight

object joseFlows:
  def joseFlow: IO[Unit] =
    val claims = JWT.Claims(subject = Some("u-1"), audiences = Set("api", "internal")) // aud is a SET (RFC 7519)
    val policy = JWT.Policy(audience = "api", algorithms = Set(ES256, EdDSA))
    for
      kp <- expectRight("gen")(P256.generate)
      token <- expectRight("sign")(JWT.sign(claims, ES256)(kp.privateKey)) // key type fixed by alg
      verified <- expectRight("verify")(JWT.verify(token.compact, JWKS(Nil), policy))
      _ <- check(verified.audiences.contains("api"), "policy audience is a member of the token's aud set")
      coseKey <- IO.fromEither(COSEKey.parse(Array[Byte](0xa5.toByte, 1, 2))) // WebAuthn credential key
      assertion <- IO.fromEither(Signature.fromRaw(Ed25519)(new Array[Byte](64)))
      _ <- coseKey match
             case ImportedPublicKey.Ed(pub) =>
               expectRight("passkey-verify")(pub.verify("authenticatorData||clientDataHash".getBytes, assertion)).void
             case _ => IO.unit
      _ <- expectRight("verify-single-key")(JWT.verify(token.compact, ES256, kp.publicKey, policy))
      rsa <- expectRight("gen")(Rsa.generate(Rsa.bits(2048)))
      _ <- expectRight("rs256")(JWT.sign(claims, RS256)(rsa.privateKey)) // the most common JWT alg: PKCS#1
      tp <- expectRight("thumbprint")(kp.publicKey.thumbprint())
      _ <- check(tp.bytes.length == 32, "RFC 7638 thumbprint")
      jwe <- expectRight("jwe")(JWE.seal("secret".getBytes, kp.publicKey, JWE.Alg.EcdhEsA128Kw, JWE.Enc.A256Gcm))
      _ <- expectRight("jwe-open")(JWE.open(jwe.compact, kp.privateKey, Set(JWE.Enc.A256Gcm)))
    yield ()
    end for
  end joseFlow

  // placeholders + the dependent-pairing negative (jose-scoped; the 15 core negatives live universally)
  def someClaims: JWT.Claims = ???
  def edPriv: PrivateKey[Ed25519] = ???
  def negative(): Unit =
    assert(!typeChecks("JWT.sign(someClaims, ES256)(edPriv)"), "ES256 fixes the key type to PrivateKey[P256]")
end joseFlows

class JoseSuite extends munit.CatsEffectSuite:
  test("JWT multi-audience sign/verify, passkey COSE import, RS256, thumbprint, JWE")(joseFlows.joseFlow)
  test("dependent alg pairing: ES256 rejects an Ed25519 key")(IO(joseFlows.negative()))
