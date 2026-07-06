/*
 * Copyright (c) 2026 Ali Rashid.
 * MIT License - see LICENSE for details.
 *
 * Unified C header for kufuli cross-platform cryptographic operations.
 * Per-OS implementations in kufuli_crypto_openssl.c, kufuli_crypto_apple.c,
 * kufuli_crypto_win32.c.
 */
#ifndef KUFULI_CRYPTO_H
#define KUFULI_CRYPTO_H

#include <stddef.h>

/* --------------------------------------------------------------------------
 * Signing algorithm IDs (explicit integers, NOT Scala enum ordinals)
 * -------------------------------------------------------------------------- */
#define KUFULI_ALG_HMAC_SHA256       0
#define KUFULI_ALG_HMAC_SHA384       1
#define KUFULI_ALG_HMAC_SHA512       2
#define KUFULI_ALG_RSA_PKCS1_SHA256  3
#define KUFULI_ALG_RSA_PKCS1_SHA384  4
#define KUFULI_ALG_RSA_PKCS1_SHA512  5
#define KUFULI_ALG_RSA_PSS_SHA256    6
#define KUFULI_ALG_RSA_PSS_SHA384    7
#define KUFULI_ALG_RSA_PSS_SHA512    8
#define KUFULI_ALG_ECDSA_P256_SHA256 9
#define KUFULI_ALG_ECDSA_P384_SHA384 10
#define KUFULI_ALG_ECDSA_P521_SHA512 11
#define KUFULI_ALG_ED25519           12
#define KUFULI_ALG_ED448             13

/* --------------------------------------------------------------------------
 * Digest algorithm IDs (separate range from signing algorithms)
 * -------------------------------------------------------------------------- */
#define KUFULI_DIGEST_SHA1   100
#define KUFULI_DIGEST_SHA256 101
#define KUFULI_DIGEST_SHA384 102
#define KUFULI_DIGEST_SHA512 103

/* --------------------------------------------------------------------------
 * Error codes
 * -------------------------------------------------------------------------- */
#define KUFULI_OK                   0
#define KUFULI_ERR_UNSUPPORTED      1
#define KUFULI_ERR_INVALID_KEY      2
#define KUFULI_ERR_SIGN_FAILED      3
#define KUFULI_ERR_VERIFY_FAILED    4
#define KUFULI_ERR_DIGEST_FAILED    5
#define KUFULI_ERR_INVALID_SIGNATURE 6

/* --------------------------------------------------------------------------
 * Function signatures
 *
 * Key format:
 *   - HMAC algorithms: raw symmetric key bytes
 *   - kufuli_sign + asymmetric: PKCS#8 DER-encoded private key
 *   - kufuli_verify + asymmetric: SubjectPublicKeyInfo DER-encoded public key
 * -------------------------------------------------------------------------- */

/**
 * Sign data with the given algorithm and key.
 *
 * @param alg_id   Signing algorithm ID (KUFULI_ALG_*)
 * @param key      Key bytes (raw for HMAC, PKCS#8 DER for asymmetric)
 * @param key_len  Key byte length
 * @param data     Data to sign
 * @param data_len Data byte length
 * @param sig_out  Output buffer for signature
 * @param sig_len  On input: buffer capacity; on output: actual signature length
 * @return KUFULI_OK on success, error code on failure
 */
int kufuli_sign(int alg_id,
                const unsigned char* key, size_t key_len,
                const unsigned char* data, size_t data_len,
                unsigned char* sig_out, size_t* sig_len);

/**
 * Verify a signature against data with the given algorithm and key.
 *
 * @param alg_id   Signing algorithm ID (KUFULI_ALG_*)
 * @param key      Key bytes (raw for HMAC, SPKI DER for asymmetric)
 * @param key_len  Key byte length
 * @param data     Data that was signed
 * @param data_len Data byte length
 * @param sig      Signature to verify
 * @param sig_len  Signature byte length
 * @return KUFULI_OK if valid, KUFULI_ERR_INVALID_SIGNATURE if wrong,
 *         other error code on operational failure
 */
int kufuli_verify(int alg_id,
                  const unsigned char* key, size_t key_len,
                  const unsigned char* data, size_t data_len,
                  const unsigned char* sig, size_t sig_len);

/**
 * Compute a cryptographic digest (hash) of data.
 *
 * @param alg_id   Digest algorithm ID (KUFULI_DIGEST_*)
 * @param data     Data to hash
 * @param data_len Data byte length
 * @param out      Output buffer for digest
 * @param out_len  On input: buffer capacity; on output: actual digest length
 * @return KUFULI_OK on success, error code on failure
 */
int kufuli_digest(int alg_id,
                  const unsigned char* data, size_t data_len,
                  unsigned char* out, size_t* out_len);

#endif /* KUFULI_CRYPTO_H */
