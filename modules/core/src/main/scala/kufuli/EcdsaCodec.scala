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

import scala.util.boundary
import scala.util.boundary.break

/** ECDSA DER <-> R||S transcoding. Converts between ASN.1 DER-encoded ECDSA signatures and the
  * fixed-length R||S concatenation format used by JWS (RFC 7515).
  */
object EcdsaCodec:

  private val SequenceTag: Byte = 0x30.toByte
  private val IntegerTag: Byte = 0x02.toByte
  private val LongFormMarker: Byte = 0x81.toByte

  /** Transcodes a DER-encoded ECDSA signature to fixed-length R||S concatenation.
    *
    * @param der DER-encoded signature bytes
    * @param componentLength byte length of a single component (R or S), e.g. 32 for P-256
    * @return fixed-length R||S concatenation of `componentLength * 2` bytes
    */
  def derToConcat(der: Array[Byte], componentLength: Int): Either[KufuliError, Array[Byte]] =
    boundary:
      if der.length < 8 || der(0) != SequenceTag then break(Left(KufuliError.InvalidSignature))

      // Determine offset past the SEQUENCE length encoding
      val offset =
        if (der(1) & 0xff) < 0x80 then 2
        else if der(1) == LongFormMarker then 3
        else break(Left(KufuliError.InvalidSignature))

      // Validate SEQUENCE structure
      val seqLen = der(offset - 1) & 0xff
      if seqLen != der.length - offset then break(Left(KufuliError.InvalidSignature))
      if der(offset) != IntegerTag then break(Left(KufuliError.InvalidSignature))

      // Extract R
      val rLen = der(offset + 1) & 0xff
      if offset + 2 + rLen >= der.length then break(Left(KufuliError.InvalidSignature))
      if der(offset + 2 + rLen) != IntegerTag then break(Left(KufuliError.InvalidSignature))

      // Extract S
      val sLen = der(offset + 2 + rLen + 1) & 0xff
      if seqLen != 2 + rLen + 2 + sLen then break(Left(KufuliError.InvalidSignature))

      // Strip leading zero bytes from R
      // scalafix:off DisableSyntax.var, DisableSyntax.while; byte-level DER manipulation
      var rStart = offset + 2
      var rEffLen = rLen
      while rEffLen > 0 && der(rStart) == 0.toByte do
        rStart += 1
        rEffLen -= 1

      // Strip leading zero bytes from S
      var sStart = offset + 2 + rLen + 2
      var sEffLen = sLen
      while sEffLen > 0 && der(sStart) == 0.toByte do
        sStart += 1
        sEffLen -= 1
      // scalafix:on

      if rEffLen > componentLength || sEffLen > componentLength then break(Left(KufuliError.InvalidSignature))

      val outputLength = componentLength * 2
      val result = new Array[Byte](outputLength)
      System.arraycopy(der, rStart, result, componentLength - rEffLen, rEffLen)
      System.arraycopy(der, sStart, result, outputLength - sEffLen, sEffLen)
      Right(result)
  end derToConcat

  /** Transcodes a fixed-length R||S concatenated ECDSA signature to DER encoding.
    *
    * @param concat fixed-length R||S concatenation (must have even length)
    * @return DER-encoded signature bytes
    */
  def concatToDer(concat: Array[Byte]): Either[KufuliError, Array[Byte]] =
    boundary:
      if concat.length == 0 || concat.length % 2 != 0 then break(Left(KufuliError.InvalidSignature))

      val mid = concat.length / 2
      val rBytes = toSignedInteger(concat, 0, mid)
      val sBytes = toSignedInteger(concat, mid, concat.length)

      val contentLen = 2 + rBytes.length + 2 + sBytes.length
      if contentLen > 255 then break(Left(KufuliError.InvalidSignature))

      // Build DER SEQUENCE
      val useLongForm = contentLen >= 128
      val headerLen = if useLongForm then 3 else 2
      val result = new Array[Byte](headerLen + contentLen)

      // scalafix:off DisableSyntax.var; sequential index-based DER assembly
      var pos = 0

      // SEQUENCE tag + length
      result(pos) = SequenceTag; pos += 1
      if useLongForm then
        result(pos) = LongFormMarker; pos += 1
      result(pos) = contentLen.toByte; pos += 1

      // INTEGER R
      result(pos) = IntegerTag; pos += 1
      result(pos) = rBytes.length.toByte; pos += 1
      System.arraycopy(rBytes, 0, result, pos, rBytes.length); pos += rBytes.length

      // INTEGER S
      result(pos) = IntegerTag; pos += 1
      result(pos) = sBytes.length.toByte; pos += 1
      System.arraycopy(sBytes, 0, result, pos, sBytes.length)
      // scalafix:on

      Right(result)
  end concatToDer

  /** Extracts a component from a concatenated signature and prepares it for ASN.1 INTEGER encoding. */
  private def toSignedInteger(sig: Array[Byte], from: Int, to: Int): Array[Byte] =
    // scalafix:off DisableSyntax.var, DisableSyntax.while; byte-level leading-zero stripping
    // Strip leading zeros
    var start = from
    while start < to - 1 && sig(start) == 0.toByte do start += 1
    // scalafix:on

    val len = to - start
    if len == 0 then
      // All zeros - represent as single zero byte
      Array(0.toByte)
    else if (sig(start) & 0x80) != 0 then
      // High bit set - prepend 0x00 sign byte for positive ASN.1 INTEGER
      val out = new Array[Byte](len + 1)
      System.arraycopy(sig, start, out, 1, len)
      out
    else
      val out = new Array[Byte](len)
      System.arraycopy(sig, start, out, 0, len)
      out
    end if
  end toSignedInteger
end EcdsaCodec
