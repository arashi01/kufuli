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
#include <stdlib.h>
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

/* Key size in bits for the algorithm. Required by SecKeyCreateWithData. */
static int get_key_size_bits(int alg_id) {
    switch (alg_id) {
        case KUFULI_ALG_ECDSA_P256_SHA256: return 256;
        case KUFULI_ALG_ECDSA_P384_SHA384: return 384;
        case KUFULI_ALG_ECDSA_P521_SHA512: return 521;
        /* RSA: size is embedded in the key data, pass 0 to let Security.framework infer */
        default: return 0;
    }
}

/* --------------------------------------------------------------------------
 * Minimal DER helpers for extracting inner key data from SPKI / PKCS#8.
 *
 * SecKeyCreateWithData expects platform-native formats:
 *   RSA public:  SubjectPublicKeyInfo (SPKI) DER
 *   RSA private: PKCS#1 RSAPrivateKey (inner key, NOT PKCS#8 wrapper)
 *   EC public:   X9.63 uncompressed point (04 || X || Y, NOT SPKI)
 *   EC private:  PKCS#8 PrivateKeyInfo DER
 *
 * Per Apple TN3137 "On Cryptographic Key Formats" (Quinn "The Eskimo").
 * -------------------------------------------------------------------------- */

/* Skip a DER tag + length, returning content start and length.
 * Returns 0 on success, -1 on error. Advances *pos past the entire TLV. */
static int der_skip_tl(const unsigned char *buf, size_t buf_len,
                       size_t *pos, const unsigned char **content, size_t *content_len) {
    if (*pos >= buf_len) return -1;
    (*pos)++; /* tag */
    if (*pos >= buf_len) return -1;
    unsigned char b = buf[(*pos)++];
    size_t len;
    if (b < 0x80) {
        len = b;
    } else if (b == 0x81) {
        if (*pos >= buf_len) return -1;
        len = buf[(*pos)++];
    } else if (b == 0x82) {
        if (*pos + 1 >= buf_len) return -1;
        len = ((size_t)buf[*pos] << 8) | buf[*pos + 1];
        *pos += 2;
    } else {
        return -1;
    }
    if (*pos + len > buf_len) return -1;
    *content = buf + *pos;
    *content_len = len;
    *pos += len;
    return 0;
}

/* Extract the BIT STRING payload from SPKI (skip AlgorithmIdentifier).
 * Returns pointer to the raw content after the unused-bits byte. */
static const unsigned char* spki_extract_bitstring(const unsigned char *spki, size_t spki_len,
                                                   size_t *out_len) {
    size_t pos = 0;
    const unsigned char *outer_content;
    size_t outer_len;
    /* Outer SEQUENCE */
    if (spki[0] != 0x30) return NULL;
    if (der_skip_tl(spki, spki_len, &pos, &outer_content, &outer_len) != 0) return NULL;

    size_t inner_pos = 0;
    const unsigned char *tmp;
    size_t tmp_len;
    /* Skip AlgorithmIdentifier SEQUENCE */
    if (outer_content[inner_pos] != 0x30) return NULL;
    if (der_skip_tl(outer_content, outer_len, &inner_pos, &tmp, &tmp_len) != 0) return NULL;

    /* BIT STRING */
    if (inner_pos >= outer_len || outer_content[inner_pos] != 0x03) return NULL;
    const unsigned char *bs_content;
    size_t bs_len;
    if (der_skip_tl(outer_content, outer_len, &inner_pos, &bs_content, &bs_len) != 0) return NULL;
    if (bs_len < 1 || bs_content[0] != 0x00) return NULL; /* unused bits must be 0 */

    *out_len = bs_len - 1;
    return bs_content + 1;
}

/* Extract the OCTET STRING payload from PKCS#8 (skip version + AlgorithmIdentifier).
 * Returns pointer to the inner key data (PKCS#1 for RSA, SEC1 for EC). */
static const unsigned char* pkcs8_extract_inner(const unsigned char *pkcs8, size_t pkcs8_len,
                                                size_t *out_len) {
    size_t pos = 0;
    const unsigned char *outer_content;
    size_t outer_len;
    /* Outer SEQUENCE */
    if (pkcs8[0] != 0x30) return NULL;
    if (der_skip_tl(pkcs8, pkcs8_len, &pos, &outer_content, &outer_len) != 0) return NULL;

    size_t inner_pos = 0;
    const unsigned char *tmp;
    size_t tmp_len;
    /* Skip version INTEGER */
    if (der_skip_tl(outer_content, outer_len, &inner_pos, &tmp, &tmp_len) != 0) return NULL;
    /* Skip AlgorithmIdentifier SEQUENCE */
    if (der_skip_tl(outer_content, outer_len, &inner_pos, &tmp, &tmp_len) != 0) return NULL;
    /* OCTET STRING containing inner key */
    if (inner_pos >= outer_len || outer_content[inner_pos] != 0x04) return NULL;
    const unsigned char *oct_content;
    size_t oct_len;
    if (der_skip_tl(outer_content, outer_len, &inner_pos, &oct_content, &oct_len) != 0) return NULL;

    *out_len = oct_len;
    return oct_content;
}

/* --------------------------------------------------------------------------
 * SecKey import helper
 *
 * Converts from kufuli's DER formats (SPKI for public, PKCS#8 for private)
 * to the formats expected by SecKeyCreateWithData.
 * -------------------------------------------------------------------------- */

static SecKeyRef import_key(int alg_id,
                            const unsigned char* key_bytes, size_t key_len,
                            CFStringRef key_class) {
    CFStringRef key_type = get_key_type(alg_id);
    if (!key_type) return NULL;

    const unsigned char *import_bytes = key_bytes;
    size_t import_len = key_len;

    /*
     * Convert to Apple-expected formats per TN3137:
     *   RSA public:  SPKI accepted directly
     *   RSA private: strip PKCS#8 -> PKCS#1 RSAPrivateKey
     *   EC public:   strip SPKI -> X9.63 point (04||X||Y)
     *   EC private:  strip PKCS#8 -> SEC1 ECPrivateKey -> extract X9.63 (04||X||Y||K)
     */
    if (is_rsa(alg_id) && key_class == kSecAttrKeyClassPrivate) {
        import_bytes = pkcs8_extract_inner(key_bytes, key_len, &import_len);
        if (!import_bytes) return NULL;
    } else if (is_ecdsa(alg_id) && key_class == kSecAttrKeyClassPublic) {
        import_bytes = spki_extract_bitstring(key_bytes, key_len, &import_len);
        if (!import_bytes) return NULL;
    } else if (is_ecdsa(alg_id) && key_class == kSecAttrKeyClassPrivate) {
        /* PKCS#8 -> SEC1 ECPrivateKey -> extract 04||X||Y from [1] BIT STRING, d from OCTET STRING
         * Then reassemble as X9.63: 04||X||Y||K */
        const unsigned char *sec1;
        size_t sec1_len;
        sec1 = pkcs8_extract_inner(key_bytes, key_len, &sec1_len);
        if (!sec1) return NULL;

        /* Parse SEC1 ECPrivateKey: SEQUENCE { INTEGER 1, OCTET STRING d, [1] { BIT STRING point } } */
        size_t s1_pos = 0;
        const unsigned char *seq_content;
        size_t seq_len;
        if (sec1[0] != 0x30) return NULL;
        if (der_skip_tl(sec1, sec1_len, &s1_pos, &seq_content, &seq_len) != 0) return NULL;

        size_t sp = 0;
        const unsigned char *tmp;
        size_t tmp_len;
        /* Skip version INTEGER 1 */
        if (der_skip_tl(seq_content, seq_len, &sp, &tmp, &tmp_len) != 0) return NULL;
        /* OCTET STRING d */
        if (sp >= seq_len || seq_content[sp] != 0x04) return NULL;
        const unsigned char *d_bytes;
        size_t d_len;
        if (der_skip_tl(seq_content, seq_len, &sp, &d_bytes, &d_len) != 0) return NULL;
        /* [1] EXPLICIT containing BIT STRING with point */
        if (sp >= seq_len || seq_content[sp] != 0xa1) return NULL;
        const unsigned char *ctx1;
        size_t ctx1_len;
        if (der_skip_tl(seq_content, seq_len, &sp, &ctx1, &ctx1_len) != 0) return NULL;
        /* BIT STRING inside [1] */
        size_t bp = 0;
        if (ctx1[0] != 0x03) return NULL;
        const unsigned char *bs;
        size_t bs_len;
        if (der_skip_tl(ctx1, ctx1_len, &bp, &bs, &bs_len) != 0) return NULL;
        if (bs_len < 2 || bs[0] != 0x00) return NULL;
        const unsigned char *point = bs + 1; /* 04||X||Y */
        size_t point_len = bs_len - 1;

        /* Build X9.63 private: 04||X||Y||K */
        size_t x963_len = point_len + d_len;
        unsigned char *x963 = (unsigned char *)malloc(x963_len);
        if (!x963) return NULL;
        memcpy(x963, point, point_len);
        memcpy(x963 + point_len, d_bytes, d_len);

        CFDataRef ec_data = CFDataCreate(kCFAllocatorDefault, x963, (CFIndex)x963_len);
        free(x963);
        if (!ec_data) return NULL;

        /* Build attributes and import */
        int ec_bits = get_key_size_bits(alg_id);
        CFNumberRef ec_size_ref = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &ec_bits);
        if (!ec_size_ref) { CFRelease(ec_data); return NULL; }

        const void *ec_attr_keys[] = { kSecAttrKeyType, kSecAttrKeyClass, kSecAttrKeySizeInBits };
        const void *ec_attr_vals[] = { key_type, key_class, ec_size_ref };
        CFDictionaryRef ec_attrs = CFDictionaryCreate(
            kCFAllocatorDefault, ec_attr_keys, ec_attr_vals, 3,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
        );
        CFRelease(ec_size_ref);
        if (!ec_attrs) { CFRelease(ec_data); return NULL; }

        CFErrorRef ec_error = NULL;
        SecKeyRef ec_key = SecKeyCreateWithData(ec_data, ec_attrs, &ec_error);
        if (ec_error) CFRelease(ec_error);
        CFRelease(ec_attrs);
        CFRelease(ec_data);
        return ec_key;
    }

    CFDataRef key_data = CFDataCreate(kCFAllocatorDefault, import_bytes, (CFIndex)import_len);
    if (!key_data) return NULL;

    int key_bits = get_key_size_bits(alg_id);
    CFNumberRef key_size_ref = NULL;
    const void *attr_keys[3];
    const void *attr_values[3];
    CFIndex attr_count = 2;

    attr_keys[0] = kSecAttrKeyType;    attr_values[0] = key_type;
    attr_keys[1] = kSecAttrKeyClass;   attr_values[1] = key_class;

    if (key_bits > 0) {
        key_size_ref = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &key_bits);
        if (!key_size_ref) { CFRelease(key_data); return NULL; }
        attr_keys[2] = kSecAttrKeySizeInBits;
        attr_values[2] = key_size_ref;
        attr_count = 3;
    }

    CFDictionaryRef attrs = CFDictionaryCreate(
        kCFAllocatorDefault,
        attr_keys, attr_values, attr_count,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
    if (!attrs) {
        if (key_size_ref) CFRelease(key_size_ref);
        CFRelease(key_data);
        return NULL;
    }

    CFErrorRef error = NULL;
    SecKeyRef sec_key = SecKeyCreateWithData(key_data, attrs, &error);

    if (error) CFRelease(error);
    CFRelease(attrs);
    if (key_size_ref) CFRelease(key_size_ref);
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
