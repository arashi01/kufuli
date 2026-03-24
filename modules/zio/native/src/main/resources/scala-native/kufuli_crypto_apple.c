/*
 * Copyright (c) 2026 Ali Rashid.
 * MIT License - see LICENSE for details.
 *
 * macOS Security.framework / CommonCrypto backend for kufuli cryptographic
 * operations. Uses SecKeyCreateSignature/SecKeyVerifySignature for asymmetric
 * operations, CCHmac for HMAC, and CC_SHA* for hashing.
 */
#include "kufuli_crypto.h"

#if defined(__APPLE__)

#include <Security/Security.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonDigest.h>
#include <string.h>

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

static int is_hmac(int alg_id) {
    return alg_id >= KUFULI_ALG_HMAC_SHA256 && alg_id <= KUFULI_ALG_HMAC_SHA512;
}

static int is_rsa(int alg_id) {
    return alg_id >= KUFULI_ALG_RSA_PKCS1_SHA256 && alg_id <= KUFULI_ALG_RSA_PSS_SHA512;
}

static int is_ecdsa(int alg_id) {
    return alg_id >= KUFULI_ALG_ECDSA_P256_SHA256 && alg_id <= KUFULI_ALG_ECDSA_P521_SHA512;
}

static int is_eddsa(int alg_id) {
    return alg_id == KUFULI_ALG_ED25519 || alg_id == KUFULI_ALG_ED448;
}

static CCHmacAlgorithm get_hmac_alg(int alg_id) {
    switch (alg_id) {
        case KUFULI_ALG_HMAC_SHA256: return kCCHmacAlgSHA256;
        case KUFULI_ALG_HMAC_SHA384: return kCCHmacAlgSHA384;
        case KUFULI_ALG_HMAC_SHA512: return kCCHmacAlgSHA512;
        default:                     return (CCHmacAlgorithm)-1;
    }
}

static size_t get_hmac_len(int alg_id) {
    switch (alg_id) {
        case KUFULI_ALG_HMAC_SHA256: return CC_SHA256_DIGEST_LENGTH;
        case KUFULI_ALG_HMAC_SHA384: return CC_SHA384_DIGEST_LENGTH;
        case KUFULI_ALG_HMAC_SHA512: return CC_SHA512_DIGEST_LENGTH;
        default:                     return 0;
    }
}

/* Map algorithm ID to SecKeyAlgorithm for signing (Message variants). */
static SecKeyAlgorithm get_sign_algorithm(int alg_id) {
    switch (alg_id) {
        /* RSA PKCS#1 v1.5 */
        case KUFULI_ALG_RSA_PKCS1_SHA256: return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
        case KUFULI_ALG_RSA_PKCS1_SHA384: return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384;
        case KUFULI_ALG_RSA_PKCS1_SHA512: return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512;
        /* RSA-PSS */
        case KUFULI_ALG_RSA_PSS_SHA256:   return kSecKeyAlgorithmRSASignatureMessagePSSSHA256;
        case KUFULI_ALG_RSA_PSS_SHA384:   return kSecKeyAlgorithmRSASignatureMessagePSSSHA384;
        case KUFULI_ALG_RSA_PSS_SHA512:   return kSecKeyAlgorithmRSASignatureMessagePSSSHA512;
        /* ECDSA (X9.62 = DER-encoded signatures) */
        case KUFULI_ALG_ECDSA_P256_SHA256: return kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
        case KUFULI_ALG_ECDSA_P384_SHA384: return kSecKeyAlgorithmECDSASignatureMessageX962SHA384;
        case KUFULI_ALG_ECDSA_P521_SHA512: return kSecKeyAlgorithmECDSASignatureMessageX962SHA512;
        default:                           return NULL;
    }
}

/* Determine key type for SecKeyCreateWithData attributes. */
static CFStringRef get_key_type(int alg_id) {
    if (is_rsa(alg_id))   return kSecAttrKeyTypeRSA;
    if (is_ecdsa(alg_id)) return kSecAttrKeyTypeECSECPrimeRandom;
    return NULL;
}

/* --------------------------------------------------------------------------
 * SecKey import helper
 *
 * Creates a SecKeyRef from DER-encoded key bytes.
 * Public keys: SubjectPublicKeyInfo DER.
 * Private keys: PKCS#8 PrivateKeyInfo DER.
 * -------------------------------------------------------------------------- */

static SecKeyRef import_key(int alg_id,
                            const unsigned char* key_bytes, size_t key_len,
                            CFStringRef key_class) {
    CFStringRef key_type = get_key_type(alg_id);
    if (!key_type) return NULL;

    CFDataRef key_data = CFDataCreate(kCFAllocatorDefault, key_bytes, (CFIndex)key_len);
    if (!key_data) return NULL;

    const void *attr_keys[] = { kSecAttrKeyType, kSecAttrKeyClass };
    const void *attr_values[] = { key_type, key_class };
    CFDictionaryRef attrs = CFDictionaryCreate(
        kCFAllocatorDefault,
        attr_keys, attr_values, 2,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
    if (!attrs) { CFRelease(key_data); return NULL; }

    CFErrorRef error = NULL;
    SecKeyRef sec_key = SecKeyCreateWithData(key_data, attrs, &error);

    if (error) CFRelease(error);
    CFRelease(attrs);
    CFRelease(key_data);
    return sec_key;
}

/* --------------------------------------------------------------------------
 * HMAC sign (compute MAC)
 * -------------------------------------------------------------------------- */

static int hmac_sign(int alg_id,
                     const unsigned char* key, size_t key_len,
                     const unsigned char* data, size_t data_len,
                     unsigned char* sig_out, size_t* sig_len) {
    CCHmacAlgorithm cc_alg = get_hmac_alg(alg_id);
    size_t mac_len = get_hmac_len(alg_id);
    if (mac_len == 0) return KUFULI_ERR_UNSUPPORTED;

    CCHmac(cc_alg, key, key_len, data, data_len, sig_out);
    *sig_len = mac_len;
    return KUFULI_OK;
}

/* --------------------------------------------------------------------------
 * HMAC verify (compute + constant-time compare)
 * -------------------------------------------------------------------------- */

static int hmac_verify(int alg_id,
                       const unsigned char* key, size_t key_len,
                       const unsigned char* data, size_t data_len,
                       const unsigned char* sig, size_t sig_len) {
    unsigned char computed[CC_SHA512_DIGEST_LENGTH]; /* large enough for any HMAC */
    size_t computed_len = 0;

    int rc = hmac_sign(alg_id, key, key_len, data, data_len,
                       computed, &computed_len);
    if (rc != KUFULI_OK) return KUFULI_ERR_VERIFY_FAILED;
    if (computed_len != sig_len) return KUFULI_ERR_INVALID_SIGNATURE;
    if (timingsafe_bcmp(computed, sig, sig_len) != 0)
        return KUFULI_ERR_INVALID_SIGNATURE;
    return KUFULI_OK;
}

/* --------------------------------------------------------------------------
 * Asymmetric sign (SecKeyCreateSignature)
 * Key is PKCS#8 DER-encoded private key.
 * -------------------------------------------------------------------------- */

static int asym_sign(int alg_id,
                     const unsigned char* key, size_t key_len,
                     const unsigned char* data, size_t data_len,
                     unsigned char* sig_out, size_t* sig_len) {
    SecKeyAlgorithm sec_alg = get_sign_algorithm(alg_id);
    if (!sec_alg) return KUFULI_ERR_UNSUPPORTED;

    SecKeyRef sec_key = import_key(alg_id, key, key_len, kSecAttrKeyClassPrivate);
    if (!sec_key) return KUFULI_ERR_INVALID_KEY;

    int rc = KUFULI_ERR_SIGN_FAILED;

    CFDataRef input = CFDataCreate(kCFAllocatorDefault, data, (CFIndex)data_len);
    if (!input) goto cleanup_key;

    CFErrorRef error = NULL;
    CFDataRef sig_data = SecKeyCreateSignature(sec_key, sec_alg, input, &error);
    if (!sig_data) goto cleanup_input;

    CFIndex actual_len = CFDataGetLength(sig_data);
    if ((size_t)actual_len > *sig_len) goto cleanup_sig;

    memcpy(sig_out, CFDataGetBytePtr(sig_data), (size_t)actual_len);
    *sig_len = (size_t)actual_len;
    rc = KUFULI_OK;

cleanup_sig:
    CFRelease(sig_data);
cleanup_input:
    if (error) CFRelease(error);
    CFRelease(input);
cleanup_key:
    CFRelease(sec_key);
    return rc;
}

/* --------------------------------------------------------------------------
 * Asymmetric verify (SecKeyVerifySignature)
 * Key is SubjectPublicKeyInfo DER-encoded public key.
 * -------------------------------------------------------------------------- */

static int asym_verify(int alg_id,
                       const unsigned char* key, size_t key_len,
                       const unsigned char* data, size_t data_len,
                       const unsigned char* sig, size_t sig_len) {
    SecKeyAlgorithm sec_alg = get_sign_algorithm(alg_id);
    if (!sec_alg) return KUFULI_ERR_UNSUPPORTED;

    SecKeyRef sec_key = import_key(alg_id, key, key_len, kSecAttrKeyClassPublic);
    if (!sec_key) return KUFULI_ERR_INVALID_KEY;

    int rc = KUFULI_ERR_VERIFY_FAILED;

    CFDataRef input = CFDataCreate(kCFAllocatorDefault, data, (CFIndex)data_len);
    if (!input) goto cleanup_key;

    CFDataRef sig_data = CFDataCreate(kCFAllocatorDefault, sig, (CFIndex)sig_len);
    if (!sig_data) goto cleanup_input;

    CFErrorRef error = NULL;
    Boolean valid = SecKeyVerifySignature(sec_key, sec_alg, input, sig_data, &error);
    rc = valid ? KUFULI_OK : KUFULI_ERR_INVALID_SIGNATURE;

    if (error) CFRelease(error);
    CFRelease(sig_data);
cleanup_input:
    CFRelease(input);
cleanup_key:
    CFRelease(sec_key);
    return rc;
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

int kufuli_sign(int alg_id,
                const unsigned char* key, size_t key_len,
                const unsigned char* data, size_t data_len,
                unsigned char* sig_out, size_t* sig_len) {
    if (is_eddsa(alg_id)) return KUFULI_ERR_UNSUPPORTED;
    if (is_hmac(alg_id))
        return hmac_sign(alg_id, key, key_len, data, data_len, sig_out, sig_len);
    return asym_sign(alg_id, key, key_len, data, data_len, sig_out, sig_len);
}

int kufuli_verify(int alg_id,
                  const unsigned char* key, size_t key_len,
                  const unsigned char* data, size_t data_len,
                  const unsigned char* sig, size_t sig_len) {
    if (is_eddsa(alg_id)) return KUFULI_ERR_UNSUPPORTED;
    if (is_hmac(alg_id))
        return hmac_verify(alg_id, key, key_len, data, data_len, sig, sig_len);
    return asym_verify(alg_id, key, key_len, data, data_len, sig, sig_len);
}

int kufuli_digest(int alg_id,
                  const unsigned char* data, size_t data_len,
                  unsigned char* out, size_t* out_len) {
    switch (alg_id) {
        case KUFULI_DIGEST_SHA1:
            if (CC_SHA1(data, (CC_LONG)data_len, out) == NULL)
                return KUFULI_ERR_DIGEST_FAILED;
            *out_len = CC_SHA1_DIGEST_LENGTH;
            return KUFULI_OK;
        case KUFULI_DIGEST_SHA256:
            if (CC_SHA256(data, (CC_LONG)data_len, out) == NULL)
                return KUFULI_ERR_DIGEST_FAILED;
            *out_len = CC_SHA256_DIGEST_LENGTH;
            return KUFULI_OK;
        case KUFULI_DIGEST_SHA384:
            if (CC_SHA384(data, (CC_LONG)data_len, out) == NULL)
                return KUFULI_ERR_DIGEST_FAILED;
            *out_len = CC_SHA384_DIGEST_LENGTH;
            return KUFULI_OK;
        case KUFULI_DIGEST_SHA512:
            if (CC_SHA512(data, (CC_LONG)data_len, out) == NULL)
                return KUFULI_ERR_DIGEST_FAILED;
            *out_len = CC_SHA512_DIGEST_LENGTH;
            return KUFULI_OK;
        default:
            return KUFULI_ERR_UNSUPPORTED;
    }
}

#endif /* __APPLE__ */
