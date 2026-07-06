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

import cats.effect.IO

import kufuli.tests.support.check
import kufuli.tests.support.expectRight
import kufuli.x509 as X

object x509Flows:
  def x509Flow: IO[Unit] =
    for
      chain <- IO.fromEither(X.Certificate.chainFromPem("-----BEGIN CERTIFICATE-----...")) // fullchain.pem onboarding
      cert = chain.head
      host <- IO.fromEither(X.Hostname.of("example.com"))
      path <- expectRight("server-auth")(
                X.CertPath.verify(chain, X.TrustAnchors(List(cert)), at = 1751673600L, Some(host))
              )
      _ <- expectRight("mtls-client-auth")( // mTLS termination: same machinery, ClientAuth purpose
             X.CertPath.verify(chain, X.TrustAnchors(List(cert)), at = 1751673600L, None, X.PathPurpose.ClientAuth)
           )
      staple <- expectRight("ocsp-staple")(
                  X.OCSP.verifyStapled(Array[Byte](0x30, 1), path.leaf, cert, at = 1751673600L)
                )
      _ <- check(staple match
                   case X.OCSP.Status.Good => true;
                   case _                  => false
                 ,
                 "stapled status verified"
           )
    yield ()
end x509Flows

class X509Suite extends munit.CatsEffectSuite:
  test("chainFromPem onboarding, ServerAuth + mTLS ClientAuth, stapled OCSP")(x509Flows.x509Flow)
