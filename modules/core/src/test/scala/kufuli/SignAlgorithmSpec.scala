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

class SignAlgorithmSpec extends FunSuite:

  test("fromJwsName resolves all non-EdDSA algorithms"):
    assertEquals(SignAlgorithm.fromJwsName("HS256"), Right(SignAlgorithm.HmacSha256))
    assertEquals(SignAlgorithm.fromJwsName("HS384"), Right(SignAlgorithm.HmacSha384))
    assertEquals(SignAlgorithm.fromJwsName("HS512"), Right(SignAlgorithm.HmacSha512))
    assertEquals(SignAlgorithm.fromJwsName("RS256"), Right(SignAlgorithm.RsaPkcs1Sha256))
    assertEquals(SignAlgorithm.fromJwsName("RS384"), Right(SignAlgorithm.RsaPkcs1Sha384))
    assertEquals(SignAlgorithm.fromJwsName("RS512"), Right(SignAlgorithm.RsaPkcs1Sha512))
    assertEquals(SignAlgorithm.fromJwsName("PS256"), Right(SignAlgorithm.RsaPssSha256))
    assertEquals(SignAlgorithm.fromJwsName("PS384"), Right(SignAlgorithm.RsaPssSha384))
    assertEquals(SignAlgorithm.fromJwsName("PS512"), Right(SignAlgorithm.RsaPssSha512))
    assertEquals(SignAlgorithm.fromJwsName("ES256"), Right(SignAlgorithm.EcdsaP256Sha256))
    assertEquals(SignAlgorithm.fromJwsName("ES384"), Right(SignAlgorithm.EcdsaP384Sha384))
    assertEquals(SignAlgorithm.fromJwsName("ES512"), Right(SignAlgorithm.EcdsaP521Sha512))

  test("fromJwsName rejects EdDSA without curve"):
    assert(SignAlgorithm.fromJwsName("EdDSA").isLeft)

  test("fromJwsName rejects unknown algorithm"):
    assert(SignAlgorithm.fromJwsName("XX999").isLeft)

  test("fromJwsName with OkpCurve resolves Ed25519"):
    assertEquals(SignAlgorithm.fromJwsName("EdDSA", OkpCurve.Ed25519), Right(SignAlgorithm.Ed25519))

  test("fromJwsName with OkpCurve resolves Ed448"):
    assertEquals(SignAlgorithm.fromJwsName("EdDSA", OkpCurve.Ed448), Right(SignAlgorithm.Ed448))

  test("fromJwsName with OkpCurve falls through for non-EdDSA"):
    assertEquals(SignAlgorithm.fromJwsName("ES256", OkpCurve.Ed25519), Right(SignAlgorithm.EcdsaP256Sha256))

  test("fromJwsName with OkpCurve rejects X25519 for EdDSA"):
    assert(SignAlgorithm.fromJwsName("EdDSA", OkpCurve.X25519).isLeft)

  test("jwsName round-trips with fromJwsName for all non-EdDSA algorithms"):
    assertEquals(SignAlgorithm.fromJwsName(SignAlgorithm.HmacSha256.jwsName), Right(SignAlgorithm.HmacSha256))
    assertEquals(SignAlgorithm.fromJwsName(SignAlgorithm.HmacSha384.jwsName), Right(SignAlgorithm.HmacSha384))
    assertEquals(SignAlgorithm.fromJwsName(SignAlgorithm.HmacSha512.jwsName), Right(SignAlgorithm.HmacSha512))
    assertEquals(SignAlgorithm.fromJwsName(SignAlgorithm.RsaPkcs1Sha256.jwsName), Right(SignAlgorithm.RsaPkcs1Sha256))
    assertEquals(SignAlgorithm.fromJwsName(SignAlgorithm.RsaPkcs1Sha384.jwsName), Right(SignAlgorithm.RsaPkcs1Sha384))
    assertEquals(SignAlgorithm.fromJwsName(SignAlgorithm.RsaPkcs1Sha512.jwsName), Right(SignAlgorithm.RsaPkcs1Sha512))
    assertEquals(SignAlgorithm.fromJwsName(SignAlgorithm.RsaPssSha256.jwsName), Right(SignAlgorithm.RsaPssSha256))
    assertEquals(SignAlgorithm.fromJwsName(SignAlgorithm.RsaPssSha384.jwsName), Right(SignAlgorithm.RsaPssSha384))
    assertEquals(SignAlgorithm.fromJwsName(SignAlgorithm.RsaPssSha512.jwsName), Right(SignAlgorithm.RsaPssSha512))
    assertEquals(SignAlgorithm.fromJwsName(SignAlgorithm.EcdsaP256Sha256.jwsName), Right(SignAlgorithm.EcdsaP256Sha256))
    assertEquals(SignAlgorithm.fromJwsName(SignAlgorithm.EcdsaP384Sha384.jwsName), Right(SignAlgorithm.EcdsaP384Sha384))
    assertEquals(SignAlgorithm.fromJwsName(SignAlgorithm.EcdsaP521Sha512.jwsName), Right(SignAlgorithm.EcdsaP521Sha512))

end SignAlgorithmSpec
