/*
 * Copyright (c) 2026 Ali Rashid.
 * MIT License - see LICENSE for details.
 *
 * Linux OpenSSL EVP backend for kufuli cryptographic operations.
 * Uses EVP_DigestSign/EVP_DigestVerify for asymmetric operations,
 * HMAC() for symmetric MAC, and EVP_Digest for hashing.
 */
#include "kufuli_crypto.h"

#if defined(__linux__) || defined(KUFULI_USE_OPENSSL)

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <string.h>

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

static const EVP_MD* get_sign_digest(int alg_id) {
    switch (alg_id) {
        case KUFULI_ALG_HMAC_SHA256:
        case KUFULI_ALG_RSA_PKCS1_SHA256:
        case KUFULI_ALG_RSA_PSS_SHA256:
        case KUFULI_ALG_ECDSA_P256_SHA256:
            return EVP_sha256();
        case KUFULI_ALG_HMAC_SHA384:
        case KUFULI_ALG_RSA_PKCS1_SHA384:
        case KUFULI_ALG_RSA_PSS_SHA384:
        case KUFULI_ALG_ECDSA_P384_SHA384:
            return EVP_sha384();
        case KUFULI_ALG_HMAC_SHA512:
        case KUFULI_ALG_RSA_PKCS1_SHA512:
        case KUFULI_ALG_RSA_PSS_SHA512:
        case KUFULI_ALG_ECDSA_P521_SHA512:
            return EVP_sha512();
        default:
            return NULL;
    }
}

static const EVP_MD* get_hash_digest(int alg_id) {
    switch (alg_id) {
        case KUFULI_DIGEST_SHA1:   return EVP_sha1();
        case KUFULI_DIGEST_SHA256: return EVP_sha256();
        case KUFULI_DIGEST_SHA384: return EVP_sha384();
        case KUFULI_DIGEST_SHA512: return EVP_sha512();
        default:                   return NULL;
    }
}

static int is_hmac(int alg_id) {
    return alg_id >= KUFULI_ALG_HMAC_SHA256 && alg_id <= KUFULI_ALG_HMAC_SHA512;
}

static int is_pss(int alg_id) {
    return alg_id >= KUFULI_ALG_RSA_PSS_SHA256 && alg_id <= KUFULI_ALG_RSA_PSS_SHA512;
}

static int is_eddsa(int alg_id) {
    return alg_id == KUFULI_ALG_ED25519 || alg_id == KUFULI_ALG_ED448;
}

static int pss_salt_len(int alg_id) {
    switch (alg_id) {
        case KUFULI_ALG_RSA_PSS_SHA256: return 32;
        case KUFULI_ALG_RSA_PSS_SHA384: return 48;
        case KUFULI_ALG_RSA_PSS_SHA512: return 64;
        default: return 0;
    }
}

/* --------------------------------------------------------------------------
 * HMAC sign (compute MAC)
 * -------------------------------------------------------------------------- */

static int hmac_sign(int alg_id,
                     const unsigned char* key, size_t key_len,
                     const unsigned char* data, size_t data_len,
                     unsigned char* sig_out, size_t* sig_len) {
    const EVP_MD* md = get_sign_digest(alg_id);
    if (!md) return KUFULI_ERR_UNSUPPORTED;

    unsigned int hmac_len = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    unsigned char* result = HMAC(md, key, (int)key_len, data, data_len,
                                 sig_out, &hmac_len);
#pragma GCC diagnostic pop
    if (!result) return KUFULI_ERR_SIGN_FAILED;
    *sig_len = hmac_len;
    return KUFULI_OK;
}

/* --------------------------------------------------------------------------
 * HMAC verify (compute + constant-time compare)
 * -------------------------------------------------------------------------- */

static int hmac_verify(int alg_id,
                       const unsigned char* key, size_t key_len,
                       const unsigned char* data, size_t data_len,
                       const unsigned char* sig, size_t sig_len) {
    unsigned char computed[EVP_MAX_MD_SIZE];
    size_t computed_len = 0;

    int rc = hmac_sign(alg_id, key, key_len, data, data_len,
                       computed, &computed_len);
    if (rc != KUFULI_OK) return KUFULI_ERR_VERIFY_FAILED;
    if (computed_len != sig_len) return KUFULI_ERR_INVALID_SIGNATURE;
    if (CRYPTO_memcmp(computed, sig, sig_len) != 0)
        return KUFULI_ERR_INVALID_SIGNATURE;
    return KUFULI_OK;
}

/* --------------------------------------------------------------------------
 * Asymmetric sign (EVP_DigestSign*)
 * Key is PKCS#8 DER-encoded private key.
 * -------------------------------------------------------------------------- */

static int asym_sign(int alg_id,
                     const unsigned char* key, size_t key_len,
                     const unsigned char* data, size_t data_len,
                     unsigned char* sig_out, size_t* sig_len) {
    const unsigned char* p = key;
    EVP_PKEY* pkey = d2i_AutoPrivateKey(NULL, &p, (long)key_len);
    if (!pkey) return KUFULI_ERR_INVALID_KEY;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); return KUFULI_ERR_SIGN_FAILED; }

    int rc = KUFULI_ERR_SIGN_FAILED;

    if (is_eddsa(alg_id)) {
        /* EdDSA: single-shot, no separate digest */
        if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1) goto cleanup;
        size_t req = 0;
        if (EVP_DigestSign(ctx, NULL, &req, data, data_len) != 1) goto cleanup;
        if (req > *sig_len) goto cleanup;
        if (EVP_DigestSign(ctx, sig_out, &req, data, data_len) != 1) goto cleanup;
        *sig_len = req;
        rc = KUFULI_OK;
    } else {
        const EVP_MD* md = get_sign_digest(alg_id);
        if (!md) { rc = KUFULI_ERR_UNSUPPORTED; goto cleanup; }

        EVP_PKEY_CTX* pctx = NULL;
        if (EVP_DigestSignInit(ctx, &pctx, md, NULL, pkey) != 1) goto cleanup;

        if (is_pss(alg_id)) {
            if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
                goto cleanup;
            if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, pss_salt_len(alg_id)) <= 0)
                goto cleanup;
            if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) <= 0)
                goto cleanup;
        }

        if (EVP_DigestSignUpdate(ctx, data, data_len) != 1) goto cleanup;

        size_t req = 0;
        if (EVP_DigestSignFinal(ctx, NULL, &req) != 1) goto cleanup;
        if (req > *sig_len) goto cleanup;
        if (EVP_DigestSignFinal(ctx, sig_out, &req) != 1) goto cleanup;
        *sig_len = req;
        rc = KUFULI_OK;
    }

cleanup:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

/* --------------------------------------------------------------------------
 * Asymmetric verify (EVP_DigestVerify*)
 * Key is SubjectPublicKeyInfo DER-encoded public key.
 * -------------------------------------------------------------------------- */

static int asym_verify(int alg_id,
                       const unsigned char* key, size_t key_len,
                       const unsigned char* data, size_t data_len,
                       const unsigned char* sig, size_t sig_len) {
    const unsigned char* p = key;
    EVP_PKEY* pkey = d2i_PUBKEY(NULL, &p, (long)key_len);
    if (!pkey) return KUFULI_ERR_INVALID_KEY;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); return KUFULI_ERR_VERIFY_FAILED; }

    int rc = KUFULI_ERR_VERIFY_FAILED;

    if (is_eddsa(alg_id)) {
        /* EdDSA: single-shot */
        if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) != 1) goto cleanup;
        int vrc = EVP_DigestVerify(ctx, sig, sig_len, data, data_len);
        rc = (vrc == 1) ? KUFULI_OK : KUFULI_ERR_INVALID_SIGNATURE;
    } else {
        const EVP_MD* md = get_sign_digest(alg_id);
        if (!md) { rc = KUFULI_ERR_UNSUPPORTED; goto cleanup; }

        EVP_PKEY_CTX* pctx = NULL;
        if (EVP_DigestVerifyInit(ctx, &pctx, md, NULL, pkey) != 1) goto cleanup;

        if (is_pss(alg_id)) {
            if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
                goto cleanup;
            if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, pss_salt_len(alg_id)) <= 0)
                goto cleanup;
            if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) <= 0)
                goto cleanup;
        }

        if (EVP_DigestVerifyUpdate(ctx, data, data_len) != 1) goto cleanup;
        int vrc = EVP_DigestVerifyFinal(ctx, sig, sig_len);
        rc = (vrc == 1) ? KUFULI_OK : KUFULI_ERR_INVALID_SIGNATURE;
    }

cleanup:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

int kufuli_sign(int alg_id,
                const unsigned char* key, size_t key_len,
                const unsigned char* data, size_t data_len,
                unsigned char* sig_out, size_t* sig_len) {
    if (is_hmac(alg_id))
        return hmac_sign(alg_id, key, key_len, data, data_len, sig_out, sig_len);
    return asym_sign(alg_id, key, key_len, data, data_len, sig_out, sig_len);
}

int kufuli_verify(int alg_id,
                  const unsigned char* key, size_t key_len,
                  const unsigned char* data, size_t data_len,
                  const unsigned char* sig, size_t sig_len) {
    if (is_hmac(alg_id))
        return hmac_verify(alg_id, key, key_len, data, data_len, sig, sig_len);
    return asym_verify(alg_id, key, key_len, data, data_len, sig, sig_len);
}

int kufuli_digest(int alg_id,
                  const unsigned char* data, size_t data_len,
                  unsigned char* out, size_t* out_len) {
    const EVP_MD* md = get_hash_digest(alg_id);
    if (!md) return KUFULI_ERR_UNSUPPORTED;

    unsigned int digest_len = 0;
    if (EVP_Digest(data, data_len, out, &digest_len, md, NULL) != 1)
        return KUFULI_ERR_DIGEST_FAILED;
    *out_len = digest_len;
    return KUFULI_OK;
}

#endif /* __linux__ || KUFULI_USE_OPENSSL */
