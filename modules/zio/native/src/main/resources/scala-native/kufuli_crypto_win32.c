/*
 * Copyright (c) 2026 Ali Rashid.
 * MIT License - see LICENSE for details.
 *
 * Windows BCrypt backend for kufuli cryptographic operations.
 * Uses BCrypt for HMAC, digests, and asymmetric sign/verify.
 * Includes DER parsing to convert standard PKCS#8/SPKI keys
 * to BCrypt-specific blob formats.
 */
#include "kufuli_crypto.h"

#if defined(_WIN32)

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

static int is_hmac(int alg_id) {
    return alg_id >= KUFULI_ALG_HMAC_SHA256 && alg_id <= KUFULI_ALG_HMAC_SHA512;
}

static int is_rsa(int alg_id) {
    return alg_id >= KUFULI_ALG_RSA_PKCS1_SHA256 && alg_id <= KUFULI_ALG_RSA_PSS_SHA512;
}

static int is_pss(int alg_id) {
    return alg_id >= KUFULI_ALG_RSA_PSS_SHA256 && alg_id <= KUFULI_ALG_RSA_PSS_SHA512;
}

static int is_ecdsa(int alg_id) {
    return alg_id >= KUFULI_ALG_ECDSA_P256_SHA256 && alg_id <= KUFULI_ALG_ECDSA_P521_SHA512;
}

static int is_eddsa(int alg_id) {
    return alg_id == KUFULI_ALG_ED25519 || alg_id == KUFULI_ALG_ED448;
}

/* Hash algorithm identifier string for BCrypt. */
static LPCWSTR get_hash_alg_id(int alg_id) {
    switch (alg_id) {
        case KUFULI_ALG_HMAC_SHA256:
        case KUFULI_ALG_RSA_PKCS1_SHA256:
        case KUFULI_ALG_RSA_PSS_SHA256:
        case KUFULI_ALG_ECDSA_P256_SHA256:
        case KUFULI_DIGEST_SHA256:
            return BCRYPT_SHA256_ALGORITHM;
        case KUFULI_ALG_HMAC_SHA384:
        case KUFULI_ALG_RSA_PKCS1_SHA384:
        case KUFULI_ALG_RSA_PSS_SHA384:
        case KUFULI_ALG_ECDSA_P384_SHA384:
        case KUFULI_DIGEST_SHA384:
            return BCRYPT_SHA384_ALGORITHM;
        case KUFULI_ALG_HMAC_SHA512:
        case KUFULI_ALG_RSA_PKCS1_SHA512:
        case KUFULI_ALG_RSA_PSS_SHA512:
        case KUFULI_ALG_ECDSA_P521_SHA512:
        case KUFULI_DIGEST_SHA512:
            return BCRYPT_SHA512_ALGORITHM;
        case KUFULI_DIGEST_SHA1:
            return BCRYPT_SHA1_ALGORITHM;
        default:
            return NULL;
    }
}

/* Hash output length in bytes. */
static ULONG get_hash_len(int alg_id) {
    switch (alg_id) {
        case KUFULI_ALG_HMAC_SHA256:
        case KUFULI_ALG_RSA_PKCS1_SHA256:
        case KUFULI_ALG_RSA_PSS_SHA256:
        case KUFULI_ALG_ECDSA_P256_SHA256:
        case KUFULI_DIGEST_SHA256:
            return 32;
        case KUFULI_ALG_HMAC_SHA384:
        case KUFULI_ALG_RSA_PKCS1_SHA384:
        case KUFULI_ALG_RSA_PSS_SHA384:
        case KUFULI_ALG_ECDSA_P384_SHA384:
        case KUFULI_DIGEST_SHA384:
            return 48;
        case KUFULI_ALG_HMAC_SHA512:
        case KUFULI_ALG_RSA_PKCS1_SHA512:
        case KUFULI_ALG_RSA_PSS_SHA512:
        case KUFULI_ALG_ECDSA_P521_SHA512:
        case KUFULI_DIGEST_SHA512:
            return 64;
        case KUFULI_DIGEST_SHA1:
            return 20;
        default:
            return 0;
    }
}

/* ECDSA component byte length per curve. */
static ULONG ec_component_len(int alg_id) {
    switch (alg_id) {
        case KUFULI_ALG_ECDSA_P256_SHA256: return 32;
        case KUFULI_ALG_ECDSA_P384_SHA384: return 48;
        case KUFULI_ALG_ECDSA_P521_SHA512: return 66;
        default: return 0;
    }
}

/* Constant-time memory comparison. Returns 0 if equal, non-zero otherwise. */
static int ct_compare(const unsigned char *a, const unsigned char *b, size_t len) {
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return diff;
}

/* --------------------------------------------------------------------------
 * BCrypt hash helper - compute hash of data
 * -------------------------------------------------------------------------- */

static NTSTATUS compute_hash(LPCWSTR alg_id, const unsigned char *data,
                             size_t data_len, unsigned char *out, ULONG out_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, alg_id, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return status;

    BCRYPT_HASH_HANDLE hHash = NULL;
    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup_alg;

    status = BCryptHashData(hHash, (PUCHAR)data, (ULONG)data_len, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup_hash;

    status = BCryptFinishHash(hHash, out, out_len, 0);

cleanup_hash:
    BCryptDestroyHash(hHash);
cleanup_alg:
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status;
}

/* --------------------------------------------------------------------------
 * HMAC sign (compute MAC)
 * -------------------------------------------------------------------------- */

static int hmac_sign(int alg_id,
                     const unsigned char *key, size_t key_len,
                     const unsigned char *data, size_t data_len,
                     unsigned char *sig_out, size_t *sig_len) {
    LPCWSTR hash_alg = get_hash_alg_id(alg_id);
    ULONG mac_len = get_hash_len(alg_id);
    if (!hash_alg || mac_len == 0) return KUFULI_ERR_UNSUPPORTED;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg, hash_alg, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) return KUFULI_ERR_SIGN_FAILED;

    BCRYPT_HASH_HANDLE hHash = NULL;
    status = BCryptCreateHash(hAlg, &hHash, NULL, 0,
                              (PUCHAR)key, (ULONG)key_len, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup_alg;

    status = BCryptHashData(hHash, (PUCHAR)data, (ULONG)data_len, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup_hash;

    status = BCryptFinishHash(hHash, sig_out, mac_len, 0);
    if (BCRYPT_SUCCESS(status)) *sig_len = mac_len;

cleanup_hash:
    BCryptDestroyHash(hHash);
cleanup_alg:
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return BCRYPT_SUCCESS(status) ? KUFULI_OK : KUFULI_ERR_SIGN_FAILED;
}

/* --------------------------------------------------------------------------
 * HMAC verify (compute + constant-time compare)
 * -------------------------------------------------------------------------- */

static int hmac_verify(int alg_id,
                       const unsigned char *key, size_t key_len,
                       const unsigned char *data, size_t data_len,
                       const unsigned char *sig, size_t sig_len) {
    unsigned char computed[64]; /* large enough for SHA-512 */
    size_t computed_len = 0;

    int rc = hmac_sign(alg_id, key, key_len, data, data_len,
                       computed, &computed_len);
    if (rc != KUFULI_OK) return KUFULI_ERR_VERIFY_FAILED;
    if (computed_len != sig_len) return KUFULI_ERR_INVALID_SIGNATURE;
    if (ct_compare(computed, sig, sig_len) != 0)
        return KUFULI_ERR_INVALID_SIGNATURE;
    return KUFULI_OK;
}

/* ==========================================================================
 * Minimal DER parser for PKCS#8/SPKI key extraction
 * ========================================================================== */

/* Read DER length at position, advance pos. Returns 0 on success, -1 on error. */
static int der_read_len(const unsigned char *buf, size_t buf_len,
                        size_t *pos, size_t *out_len) {
    if (*pos >= buf_len) return -1;
    unsigned char b = buf[(*pos)++];
    if (b < 0x80) {
        *out_len = b;
    } else if (b == 0x81) {
        if (*pos >= buf_len) return -1;
        *out_len = buf[(*pos)++];
    } else if (b == 0x82) {
        if (*pos + 1 >= buf_len) return -1;
        *out_len = ((size_t)buf[*pos] << 8) | buf[*pos + 1];
        *pos += 2;
    } else if (b == 0x83) {
        if (*pos + 2 >= buf_len) return -1;
        *out_len = ((size_t)buf[*pos] << 16) | ((size_t)buf[*pos + 1] << 8) | buf[*pos + 2];
        *pos += 3;
    } else {
        return -1;
    }
    if (*pos + *out_len > buf_len) return -1;
    return 0;
}

/* Expect a specific tag, read its content. Returns pointer to content and length. */
static int der_expect(const unsigned char *buf, size_t buf_len,
                      size_t *pos, unsigned char tag,
                      const unsigned char **content, size_t *content_len) {
    if (*pos >= buf_len || buf[*pos] != tag) return -1;
    (*pos)++;
    if (der_read_len(buf, buf_len, pos, content_len) != 0) return -1;
    *content = buf + *pos;
    *pos += *content_len;
    return 0;
}

/* Skip one TLV element. */
static int der_skip(const unsigned char *buf, size_t buf_len, size_t *pos) {
    if (*pos >= buf_len) return -1;
    (*pos)++; /* tag */
    size_t len;
    if (der_read_len(buf, buf_len, pos, &len) != 0) return -1;
    *pos += len;
    return 0;
}

/* Read a DER INTEGER, stripping the leading sign byte if present.
 * Returns pointer to the unsigned value and its length. */
static int der_read_uint(const unsigned char *buf, size_t buf_len,
                         size_t *pos,
                         const unsigned char **val, size_t *val_len) {
    const unsigned char *content;
    size_t content_len;
    if (der_expect(buf, buf_len, pos, 0x02, &content, &content_len) != 0)
        return -1;
    /* Strip leading zero used for positive sign */
    if (content_len > 1 && content[0] == 0x00) {
        content++;
        content_len--;
    }
    *val = content;
    *val_len = content_len;
    return 0;
}

/* Copy a DER unsigned integer into a fixed-length output buffer (right-aligned,
 * zero-padded on the left). */
static int der_uint_to_fixed(const unsigned char *buf, size_t buf_len,
                             size_t *pos,
                             unsigned char *out, size_t out_len) {
    const unsigned char *val;
    size_t val_len;
    if (der_read_uint(buf, buf_len, pos, &val, &val_len) != 0) return -1;
    if (val_len > out_len) return -1; /* value too large */
    memset(out, 0, out_len);
    memcpy(out + (out_len - val_len), val, val_len);
    return 0;
}

/* Pre-encoded OIDs for algorithm identification */
static const unsigned char OID_RSA[] = {
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 /* 1.2.840.113549.1.1.1 */
};
static const unsigned char OID_EC[] = {
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 /* 1.2.840.10045.2.1 */
};
static const unsigned char OID_P256[] = {
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 /* 1.2.840.10045.3.1.7 */
};
static const unsigned char OID_P384[] = {
    0x2b, 0x81, 0x04, 0x00, 0x22 /* 1.3.132.0.34 */
};
static const unsigned char OID_P521[] = {
    0x2b, 0x81, 0x04, 0x00, 0x23 /* 1.3.132.0.35 */
};

/* Check if an OID content matches a known OID. */
static int oid_match(const unsigned char *content, size_t content_len,
                     const unsigned char *oid, size_t oid_len) {
    return content_len == oid_len && memcmp(content, oid, oid_len) == 0;
}

/* ==========================================================================
 * DER -> BCrypt RSA blob conversion
 * ========================================================================== */

/* Parse SubjectPublicKeyInfo DER for RSA, build BCRYPT_RSAPUBLIC_BLOB.
 * Returns allocated blob (caller must free) and sets blob_len. */
static unsigned char *rsa_spki_to_blob(const unsigned char *der, size_t der_len,
                                       size_t *blob_len) {
    size_t pos = 0;
    const unsigned char *seq_content;
    size_t seq_len;

    /* Outer SEQUENCE */
    if (der_expect(der, der_len, &pos, 0x30, &seq_content, &seq_len) != 0)
        return NULL;

    size_t inner_pos = 0;
    const unsigned char *inner = seq_content;
    size_t inner_len = seq_len;

    /* AlgorithmIdentifier SEQUENCE - skip it (we know it's RSA) */
    if (der_skip(inner, inner_len, &inner_pos) != 0) return NULL;

    /* BIT STRING containing RSAPublicKey */
    const unsigned char *bs_content;
    size_t bs_len;
    if (der_expect(inner, inner_len, &inner_pos, 0x03, &bs_content, &bs_len) != 0)
        return NULL;
    if (bs_len < 1 || bs_content[0] != 0x00) return NULL; /* unused bits must be 0 */
    const unsigned char *rsa_pub = bs_content + 1;
    size_t rsa_pub_len = bs_len - 1;

    /* RSAPublicKey SEQUENCE { INTEGER modulus, INTEGER exponent } */
    size_t rp_pos = 0;
    const unsigned char *rsa_seq;
    size_t rsa_seq_len;
    if (der_expect(rsa_pub, rsa_pub_len, &rp_pos, 0x30, &rsa_seq, &rsa_seq_len) != 0)
        return NULL;

    size_t rs_pos = 0;
    const unsigned char *mod_val, *exp_val;
    size_t mod_len, exp_len;
    if (der_read_uint(rsa_seq, rsa_seq_len, &rs_pos, &mod_val, &mod_len) != 0)
        return NULL;
    if (der_read_uint(rsa_seq, rsa_seq_len, &rs_pos, &exp_val, &exp_len) != 0)
        return NULL;

    /* Build BCRYPT_RSAPUBLIC_BLOB */
    size_t total = sizeof(BCRYPT_RSAKEY_BLOB) + exp_len + mod_len;
    unsigned char *blob = (unsigned char *)calloc(1, total);
    if (!blob) return NULL;

    BCRYPT_RSAKEY_BLOB *hdr = (BCRYPT_RSAKEY_BLOB *)blob;
    hdr->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    hdr->BitLength = (ULONG)(mod_len * 8);
    hdr->cbPublicExp = (ULONG)exp_len;
    hdr->cbModulus = (ULONG)mod_len;
    hdr->cbPrime1 = 0;
    hdr->cbPrime2 = 0;

    unsigned char *p = blob + sizeof(BCRYPT_RSAKEY_BLOB);
    memcpy(p, exp_val, exp_len); p += exp_len;
    memcpy(p, mod_val, mod_len);

    *blob_len = total;
    return blob;
}

/* Parse PKCS#8 PrivateKeyInfo DER for RSA, build BCRYPT_RSAFULLPRIVATE_BLOB.
 * Returns allocated blob (caller must free) and sets blob_len. */
static unsigned char *rsa_pkcs8_to_blob(const unsigned char *der, size_t der_len,
                                        size_t *blob_len) {
    size_t pos = 0;
    const unsigned char *outer_seq;
    size_t outer_seq_len;

    /* Outer SEQUENCE */
    if (der_expect(der, der_len, &pos, 0x30, &outer_seq, &outer_seq_len) != 0)
        return NULL;

    size_t o_pos = 0;
    /* version INTEGER 0 - skip */
    if (der_skip(outer_seq, outer_seq_len, &o_pos) != 0) return NULL;
    /* AlgorithmIdentifier SEQUENCE - skip */
    if (der_skip(outer_seq, outer_seq_len, &o_pos) != 0) return NULL;

    /* OCTET STRING containing RSAPrivateKey */
    const unsigned char *oct_content;
    size_t oct_len;
    if (der_expect(outer_seq, outer_seq_len, &o_pos, 0x04, &oct_content, &oct_len) != 0)
        return NULL;

    /* RSAPrivateKey SEQUENCE */
    size_t oc_pos = 0;
    const unsigned char *rsa_seq;
    size_t rsa_seq_len;
    if (der_expect(oct_content, oct_len, &oc_pos, 0x30, &rsa_seq, &rsa_seq_len) != 0)
        return NULL;

    /* Parse: version, n, e, d, p, q, dp, dq, qi */
    size_t rs_pos = 0;
    /* version INTEGER 0 - skip */
    if (der_skip(rsa_seq, rsa_seq_len, &rs_pos) != 0) return NULL;

    const unsigned char *n_val, *e_val, *d_val, *p_val, *q_val;
    const unsigned char *dp_val, *dq_val, *qi_val;
    size_t n_len, e_len, d_len, p_len, q_len, dp_len, dq_len, qi_len;

    if (der_read_uint(rsa_seq, rsa_seq_len, &rs_pos, &n_val, &n_len) != 0) return NULL;
    if (der_read_uint(rsa_seq, rsa_seq_len, &rs_pos, &e_val, &e_len) != 0) return NULL;
    if (der_read_uint(rsa_seq, rsa_seq_len, &rs_pos, &d_val, &d_len) != 0) return NULL;
    if (der_read_uint(rsa_seq, rsa_seq_len, &rs_pos, &p_val, &p_len) != 0) return NULL;
    if (der_read_uint(rsa_seq, rsa_seq_len, &rs_pos, &q_val, &q_len) != 0) return NULL;
    if (der_read_uint(rsa_seq, rsa_seq_len, &rs_pos, &dp_val, &dp_len) != 0) return NULL;
    if (der_read_uint(rsa_seq, rsa_seq_len, &rs_pos, &dq_val, &dq_len) != 0) return NULL;
    if (der_read_uint(rsa_seq, rsa_seq_len, &rs_pos, &qi_val, &qi_len) != 0) return NULL;

    /*
     * BCrypt full private blob layout:
     *   Header | e[cbPublicExp] | n[cbModulus] | p[cbPrime1] | q[cbPrime2]
     *          | dp[cbPrime1] | dq[cbPrime2] | qi[cbPrime1] | d[cbModulus]
     *
     * cbPrime1 and cbPrime2 must accommodate all fields indexed by them.
     * Use max(p_len, dp_len, qi_len) for cbPrime1, max(q_len, dq_len) for cbPrime2.
     */
    ULONG cbModulus = (ULONG)n_len;
    ULONG cbPublicExp = (ULONG)e_len;
    ULONG cbPrime1 = (ULONG)p_len;
    if (dp_len > cbPrime1) cbPrime1 = (ULONG)dp_len;
    if (qi_len > cbPrime1) cbPrime1 = (ULONG)qi_len;
    ULONG cbPrime2 = (ULONG)q_len;
    if (dq_len > cbPrime2) cbPrime2 = (ULONG)dq_len;

    /* d must fit in cbModulus bytes */
    ULONG cbPrivExp = cbModulus;
    if (d_len > cbPrivExp) return NULL;

    size_t total = sizeof(BCRYPT_RSAKEY_BLOB) + cbPublicExp + cbModulus
                   + cbPrime1 + cbPrime2
                   + cbPrime1 + cbPrime2 + cbPrime1
                   + cbPrivExp;
    unsigned char *blob = (unsigned char *)calloc(1, total);
    if (!blob) return NULL;

    BCRYPT_RSAKEY_BLOB *hdr = (BCRYPT_RSAKEY_BLOB *)blob;
    hdr->Magic = BCRYPT_RSAFULLPRIVATE_MAGIC;
    hdr->BitLength = cbModulus * 8;
    hdr->cbPublicExp = cbPublicExp;
    hdr->cbModulus = cbModulus;
    hdr->cbPrime1 = cbPrime1;
    hdr->cbPrime2 = cbPrime2;

    /* Write components right-aligned in their respective fields (calloc zeroed) */
    unsigned char *out = blob + sizeof(BCRYPT_RSAKEY_BLOB);

    memcpy(out + (cbPublicExp - e_len), e_val, e_len); out += cbPublicExp;
    memcpy(out + (cbModulus - n_len), n_val, n_len);    out += cbModulus;
    memcpy(out + (cbPrime1 - p_len), p_val, p_len);     out += cbPrime1;
    memcpy(out + (cbPrime2 - q_len), q_val, q_len);     out += cbPrime2;
    memcpy(out + (cbPrime1 - dp_len), dp_val, dp_len);  out += cbPrime1;
    memcpy(out + (cbPrime2 - dq_len), dq_val, dq_len);  out += cbPrime2;
    memcpy(out + (cbPrime1 - qi_len), qi_val, qi_len);   out += cbPrime1;
    memcpy(out + (cbPrivExp - d_len), d_val, d_len);

    *blob_len = total;
    return blob;
}

/* ==========================================================================
 * DER -> BCrypt ECC blob conversion
 * ========================================================================== */

/* Identify EC curve from the second OID in the AlgorithmIdentifier SEQUENCE.
 * Returns component byte length (32/48/66) or 0 on failure. */
static ULONG ec_identify_curve(const unsigned char *alg_id_seq, size_t alg_id_len,
                               int is_sign, int is_private,
                               ULONG *out_magic) {
    size_t pos = 0;
    /* Skip the first OID (ecPublicKey) */
    if (der_skip(alg_id_seq, alg_id_len, &pos) != 0) return 0;
    /* Read the curve OID */
    const unsigned char *curve_oid;
    size_t curve_oid_len;
    if (der_expect(alg_id_seq, alg_id_len, &pos, 0x06, &curve_oid, &curve_oid_len) != 0)
        return 0;

    if (oid_match(curve_oid, curve_oid_len, OID_P256, sizeof(OID_P256))) {
        *out_magic = is_private ? BCRYPT_ECDSA_PRIVATE_P256_MAGIC : BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        return 32;
    }
    if (oid_match(curve_oid, curve_oid_len, OID_P384, sizeof(OID_P384))) {
        *out_magic = is_private ? BCRYPT_ECDSA_PRIVATE_P384_MAGIC : BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
        return 48;
    }
    if (oid_match(curve_oid, curve_oid_len, OID_P521, sizeof(OID_P521))) {
        *out_magic = is_private ? BCRYPT_ECDSA_PRIVATE_P521_MAGIC : BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
        return 66;
    }
    return 0;
}

/* Parse SubjectPublicKeyInfo DER for ECDSA, build BCRYPT_ECCPUBLIC_BLOB.
 * Expects: SEQUENCE { AlgId SEQUENCE, BIT STRING { 04 || X || Y } } */
static unsigned char *ec_spki_to_blob(const unsigned char *der, size_t der_len,
                                      size_t *blob_len) {
    size_t pos = 0;
    const unsigned char *outer_seq;
    size_t outer_seq_len;
    if (der_expect(der, der_len, &pos, 0x30, &outer_seq, &outer_seq_len) != 0)
        return NULL;

    size_t o_pos = 0;
    /* AlgorithmIdentifier SEQUENCE */
    const unsigned char *alg_id_seq;
    size_t alg_id_len;
    if (der_expect(outer_seq, outer_seq_len, &o_pos, 0x30, &alg_id_seq, &alg_id_len) != 0)
        return NULL;

    ULONG magic = 0;
    ULONG comp_len = ec_identify_curve(alg_id_seq, alg_id_len, 1, 0, &magic);
    if (comp_len == 0) return NULL;

    /* BIT STRING containing uncompressed point */
    const unsigned char *bs_content;
    size_t bs_len;
    if (der_expect(outer_seq, outer_seq_len, &o_pos, 0x03, &bs_content, &bs_len) != 0)
        return NULL;
    if (bs_len < 2 || bs_content[0] != 0x00) return NULL; /* unused bits byte */
    const unsigned char *point = bs_content + 1;
    size_t point_len = bs_len - 1;

    /* Expect uncompressed: 04 || X[comp_len] || Y[comp_len] */
    if (point_len != 1 + 2 * comp_len || point[0] != 0x04) return NULL;

    /* Build BCRYPT_ECCPUBLIC_BLOB: header + X + Y */
    size_t total = sizeof(BCRYPT_ECCKEY_BLOB) + 2 * comp_len;
    unsigned char *blob = (unsigned char *)calloc(1, total);
    if (!blob) return NULL;

    BCRYPT_ECCKEY_BLOB *hdr = (BCRYPT_ECCKEY_BLOB *)blob;
    hdr->dwMagic = magic;
    hdr->cbKey = comp_len;

    memcpy(blob + sizeof(BCRYPT_ECCKEY_BLOB), point + 1, 2 * comp_len);

    *blob_len = total;
    return blob;
}

/* Parse PKCS#8 PrivateKeyInfo DER for ECDSA, build BCRYPT_ECCPRIVATE_BLOB.
 * PKCS#8 wraps RFC 5915 ECPrivateKey: SEQUENCE { 1, OCTET STRING d, [1] BIT STRING point } */
static unsigned char *ec_pkcs8_to_blob(const unsigned char *der, size_t der_len,
                                       size_t *blob_len) {
    size_t pos = 0;
    const unsigned char *outer_seq;
    size_t outer_seq_len;
    if (der_expect(der, der_len, &pos, 0x30, &outer_seq, &outer_seq_len) != 0)
        return NULL;

    size_t o_pos = 0;
    /* version INTEGER 0 - skip */
    if (der_skip(outer_seq, outer_seq_len, &o_pos) != 0) return NULL;

    /* AlgorithmIdentifier SEQUENCE (contains curve OID) */
    const unsigned char *alg_id_seq;
    size_t alg_id_len;
    if (der_expect(outer_seq, outer_seq_len, &o_pos, 0x30, &alg_id_seq, &alg_id_len) != 0)
        return NULL;

    ULONG magic = 0;
    ULONG comp_len = ec_identify_curve(alg_id_seq, alg_id_len, 1, 1, &magic);
    if (comp_len == 0) return NULL;

    /* OCTET STRING wrapping ECPrivateKey */
    const unsigned char *oct_content;
    size_t oct_len;
    if (der_expect(outer_seq, outer_seq_len, &o_pos, 0x04, &oct_content, &oct_len) != 0)
        return NULL;

    /* ECPrivateKey SEQUENCE */
    size_t ec_pos = 0;
    const unsigned char *ec_seq;
    size_t ec_seq_len;
    if (der_expect(oct_content, oct_len, &ec_pos, 0x30, &ec_seq, &ec_seq_len) != 0)
        return NULL;

    size_t es_pos = 0;
    /* version INTEGER 1 - skip */
    if (der_skip(ec_seq, ec_seq_len, &es_pos) != 0) return NULL;

    /* OCTET STRING d (private key scalar) */
    const unsigned char *d_content;
    size_t d_len;
    if (der_expect(ec_seq, ec_seq_len, &es_pos, 0x04, &d_content, &d_len) != 0)
        return NULL;

    /* [1] EXPLICIT containing BIT STRING with uncompressed point */
    const unsigned char *ctx1_content;
    size_t ctx1_len;
    if (der_expect(ec_seq, ec_seq_len, &es_pos, 0xa1, &ctx1_content, &ctx1_len) != 0)
        return NULL;

    size_t c1_pos = 0;
    const unsigned char *bs_content;
    size_t bs_len;
    if (der_expect(ctx1_content, ctx1_len, &c1_pos, 0x03, &bs_content, &bs_len) != 0)
        return NULL;
    if (bs_len < 2 || bs_content[0] != 0x00) return NULL;
    const unsigned char *point = bs_content + 1;
    size_t point_len = bs_len - 1;

    if (point_len != 1 + 2 * comp_len || point[0] != 0x04) return NULL;

    /* Build BCRYPT_ECCPRIVATE_BLOB: header + X + Y + d */
    size_t total = sizeof(BCRYPT_ECCKEY_BLOB) + 3 * comp_len;
    unsigned char *blob = (unsigned char *)calloc(1, total);
    if (!blob) return NULL;

    BCRYPT_ECCKEY_BLOB *hdr = (BCRYPT_ECCKEY_BLOB *)blob;
    hdr->dwMagic = magic;
    hdr->cbKey = comp_len;

    unsigned char *out = blob + sizeof(BCRYPT_ECCKEY_BLOB);
    memcpy(out, point + 1, 2 * comp_len); out += 2 * comp_len;
    /* d may be shorter than comp_len; right-align */
    if (d_len > comp_len) { free(blob); return NULL; }
    memset(out, 0, comp_len);
    memcpy(out + (comp_len - d_len), d_content, d_len);

    *blob_len = total;
    return blob;
}

/* ==========================================================================
 * ECDSA R||S <-> DER conversion
 *
 * BCrypt uses fixed-length R||S; the C API contract uses DER (matching OpenSSL).
 * ========================================================================== */

/* Convert fixed-length R||S to DER-encoded ECDSA signature.
 * out must be large enough (2*comp_len + 9 is always sufficient). */
static int ecdsa_rs_to_der(const unsigned char *rs, ULONG comp_len,
                           unsigned char *out, size_t *out_len) {
    const unsigned char *r = rs;
    const unsigned char *s = rs + comp_len;

    /* Strip leading zeros but keep at least 1 byte */
    size_t r_off = 0, s_off = 0;
    while (r_off < comp_len - 1 && r[r_off] == 0) r_off++;
    while (s_off < comp_len - 1 && s[s_off] == 0) s_off++;

    size_t r_len = comp_len - r_off;
    size_t s_len = comp_len - s_off;

    /* Add sign byte if high bit set */
    int r_pad = (r[r_off] & 0x80) ? 1 : 0;
    int s_pad = (s[s_off] & 0x80) ? 1 : 0;

    size_t r_total = r_len + r_pad;
    size_t s_total = s_len + s_pad;
    size_t seq_content_len = 2 + r_total + 2 + s_total; /* tag+len for each INTEGER */

    /* SEQUENCE header */
    size_t pos = 0;
    out[pos++] = 0x30; /* SEQUENCE tag */
    if (seq_content_len < 0x80) {
        out[pos++] = (unsigned char)seq_content_len;
    } else {
        out[pos++] = 0x81;
        out[pos++] = (unsigned char)seq_content_len;
    }

    /* INTEGER r */
    out[pos++] = 0x02;
    out[pos++] = (unsigned char)r_total;
    if (r_pad) out[pos++] = 0x00;
    memcpy(out + pos, r + r_off, r_len); pos += r_len;

    /* INTEGER s */
    out[pos++] = 0x02;
    out[pos++] = (unsigned char)s_total;
    if (s_pad) out[pos++] = 0x00;
    memcpy(out + pos, s + s_off, s_len); pos += s_len;

    *out_len = pos;
    return 0;
}

/* Convert DER-encoded ECDSA signature to fixed-length R||S.
 * out must be at least 2*comp_len bytes. */
static int ecdsa_der_to_rs(const unsigned char *der, size_t der_len,
                           ULONG comp_len,
                           unsigned char *out) {
    size_t pos = 0;
    const unsigned char *seq_content;
    size_t seq_len;
    if (der_expect(der, der_len, &pos, 0x30, &seq_content, &seq_len) != 0)
        return -1;

    size_t s_pos = 0;
    memset(out, 0, 2 * comp_len);

    /* Read R */
    if (der_uint_to_fixed(seq_content, seq_len, &s_pos, out, comp_len) != 0)
        return -1;
    /* Read S */
    if (der_uint_to_fixed(seq_content, seq_len, &s_pos, out + comp_len, comp_len) != 0)
        return -1;

    return 0;
}

/* ==========================================================================
 * Asymmetric sign/verify
 * ========================================================================== */

/* Import a BCrypt key from a blob. */
static NTSTATUS import_bcrypt_key(LPCWSTR alg_str, LPCWSTR blob_type,
                                  const unsigned char *blob, size_t blob_len,
                                  BCRYPT_KEY_HANDLE *hKey) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, alg_str, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return status;

    status = BCryptImportKeyPair(hAlg, NULL, blob_type, hKey,
                                 (PUCHAR)blob, (ULONG)blob_len, 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status;
}

/* Get BCrypt algorithm string for key import. */
static LPCWSTR get_asym_alg_str(int alg_id) {
    if (is_rsa(alg_id)) return BCRYPT_RSA_ALGORITHM;
    switch (alg_id) {
        case KUFULI_ALG_ECDSA_P256_SHA256: return BCRYPT_ECDSA_P256_ALGORITHM;
        case KUFULI_ALG_ECDSA_P384_SHA384: return BCRYPT_ECDSA_P384_ALGORITHM;
        case KUFULI_ALG_ECDSA_P521_SHA512: return BCRYPT_ECDSA_P521_ALGORITHM;
        default: return NULL;
    }
}

static int asym_sign(int alg_id,
                     const unsigned char *key, size_t key_len,
                     const unsigned char *data, size_t data_len,
                     unsigned char *sig_out, size_t *sig_len) {
    LPCWSTR alg_str = get_asym_alg_str(alg_id);
    LPCWSTR hash_alg_id = get_hash_alg_id(alg_id);
    ULONG hash_len = get_hash_len(alg_id);
    if (!alg_str || !hash_alg_id || hash_len == 0) return KUFULI_ERR_UNSUPPORTED;

    /* Parse DER key to BCrypt blob */
    size_t blob_len = 0;
    unsigned char *blob = NULL;
    LPCWSTR blob_type = NULL;

    if (is_rsa(alg_id)) {
        blob = rsa_pkcs8_to_blob(key, key_len, &blob_len);
        blob_type = BCRYPT_RSAFULLPRIVATE_BLOB;
    } else if (is_ecdsa(alg_id)) {
        blob = ec_pkcs8_to_blob(key, key_len, &blob_len);
        blob_type = BCRYPT_ECCPRIVATE_BLOB;
    }
    if (!blob) return KUFULI_ERR_INVALID_KEY;

    int rc = KUFULI_ERR_SIGN_FAILED;

    /* Import key */
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = import_bcrypt_key(alg_str, blob_type, blob, blob_len, &hKey);
    free(blob);
    if (!BCRYPT_SUCCESS(status)) return KUFULI_ERR_INVALID_KEY;

    /* Hash the data (BCryptSignHash requires pre-hashed input) */
    unsigned char hash[64];
    status = compute_hash(hash_alg_id, data, data_len, hash, hash_len);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    /* Sign */
    if (is_rsa(alg_id)) {
        if (is_pss(alg_id)) {
            BCRYPT_PSS_PADDING_INFO pss_info;
            pss_info.pszAlgId = hash_alg_id;
            pss_info.cbSalt = hash_len;
            ULONG result_len = 0;
            status = BCryptSignHash(hKey, &pss_info, hash, hash_len,
                                    sig_out, (ULONG)*sig_len, &result_len,
                                    BCRYPT_PAD_PSS);
            if (BCRYPT_SUCCESS(status)) { *sig_len = result_len; rc = KUFULI_OK; }
        } else {
            BCRYPT_PKCS1_PADDING_INFO pkcs1_info;
            pkcs1_info.pszAlgId = hash_alg_id;
            ULONG result_len = 0;
            status = BCryptSignHash(hKey, &pkcs1_info, hash, hash_len,
                                    sig_out, (ULONG)*sig_len, &result_len,
                                    BCRYPT_PAD_PKCS1);
            if (BCRYPT_SUCCESS(status)) { *sig_len = result_len; rc = KUFULI_OK; }
        }
    } else if (is_ecdsa(alg_id)) {
        /* BCryptSignHash returns raw R||S for ECDSA */
        ULONG comp = ec_component_len(alg_id);
        ULONG rs_len = 2 * comp;
        unsigned char *rs_buf = (unsigned char *)calloc(1, rs_len);
        if (!rs_buf) goto cleanup;

        ULONG result_len = 0;
        status = BCryptSignHash(hKey, NULL, hash, hash_len,
                                rs_buf, rs_len, &result_len, 0);
        if (BCRYPT_SUCCESS(status)) {
            /* Convert R||S to DER for the C API contract */
            if (ecdsa_rs_to_der(rs_buf, comp, sig_out, sig_len) == 0)
                rc = KUFULI_OK;
        }
        free(rs_buf);
    }

cleanup:
    BCryptDestroyKey(hKey);
    return rc;
}

static int asym_verify(int alg_id,
                       const unsigned char *key, size_t key_len,
                       const unsigned char *data, size_t data_len,
                       const unsigned char *sig, size_t sig_len) {
    LPCWSTR alg_str = get_asym_alg_str(alg_id);
    LPCWSTR hash_alg_id = get_hash_alg_id(alg_id);
    ULONG hash_len = get_hash_len(alg_id);
    if (!alg_str || !hash_alg_id || hash_len == 0) return KUFULI_ERR_UNSUPPORTED;

    /* Parse DER key to BCrypt blob */
    size_t blob_len = 0;
    unsigned char *blob = NULL;
    LPCWSTR blob_type = NULL;

    if (is_rsa(alg_id)) {
        blob = rsa_spki_to_blob(key, key_len, &blob_len);
        blob_type = BCRYPT_RSAPUBLIC_BLOB;
    } else if (is_ecdsa(alg_id)) {
        blob = ec_spki_to_blob(key, key_len, &blob_len);
        blob_type = BCRYPT_ECCPUBLIC_BLOB;
    }
    if (!blob) return KUFULI_ERR_INVALID_KEY;

    int rc = KUFULI_ERR_VERIFY_FAILED;

    /* Import key */
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = import_bcrypt_key(alg_str, blob_type, blob, blob_len, &hKey);
    free(blob);
    if (!BCRYPT_SUCCESS(status)) return KUFULI_ERR_INVALID_KEY;

    /* Hash the data */
    unsigned char hash[64];
    status = compute_hash(hash_alg_id, data, data_len, hash, hash_len);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    /* Verify */
    if (is_rsa(alg_id)) {
        if (is_pss(alg_id)) {
            BCRYPT_PSS_PADDING_INFO pss_info;
            pss_info.pszAlgId = hash_alg_id;
            pss_info.cbSalt = hash_len;
            status = BCryptVerifySignature(hKey, &pss_info, hash, hash_len,
                                           (PUCHAR)sig, (ULONG)sig_len,
                                           BCRYPT_PAD_PSS);
        } else {
            BCRYPT_PKCS1_PADDING_INFO pkcs1_info;
            pkcs1_info.pszAlgId = hash_alg_id;
            status = BCryptVerifySignature(hKey, &pkcs1_info, hash, hash_len,
                                           (PUCHAR)sig, (ULONG)sig_len,
                                           BCRYPT_PAD_PKCS1);
        }
        if (BCRYPT_SUCCESS(status)) rc = KUFULI_OK;
        else if (status == STATUS_INVALID_SIGNATURE) rc = KUFULI_ERR_INVALID_SIGNATURE;
    } else if (is_ecdsa(alg_id)) {
        /* Convert DER signature to R||S for BCrypt */
        ULONG comp = ec_component_len(alg_id);
        ULONG rs_len = 2 * comp;
        unsigned char *rs_buf = (unsigned char *)calloc(1, rs_len);
        if (!rs_buf) goto cleanup;

        if (ecdsa_der_to_rs(sig, sig_len, comp, rs_buf) != 0) {
            free(rs_buf);
            rc = KUFULI_ERR_INVALID_SIGNATURE;
            goto cleanup;
        }

        status = BCryptVerifySignature(hKey, NULL, hash, hash_len,
                                       rs_buf, rs_len, 0);
        free(rs_buf);
        if (BCRYPT_SUCCESS(status)) rc = KUFULI_OK;
        else if (status == STATUS_INVALID_SIGNATURE) rc = KUFULI_ERR_INVALID_SIGNATURE;
    }

cleanup:
    BCryptDestroyKey(hKey);
    return rc;
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

int kufuli_sign(int alg_id,
                const unsigned char *key, size_t key_len,
                const unsigned char *data, size_t data_len,
                unsigned char *sig_out, size_t *sig_len) {
    if (is_eddsa(alg_id)) return KUFULI_ERR_UNSUPPORTED;
    if (is_hmac(alg_id))
        return hmac_sign(alg_id, key, key_len, data, data_len, sig_out, sig_len);
    return asym_sign(alg_id, key, key_len, data, data_len, sig_out, sig_len);
}

int kufuli_verify(int alg_id,
                  const unsigned char *key, size_t key_len,
                  const unsigned char *data, size_t data_len,
                  const unsigned char *sig, size_t sig_len) {
    if (is_eddsa(alg_id)) return KUFULI_ERR_UNSUPPORTED;
    if (is_hmac(alg_id))
        return hmac_verify(alg_id, key, key_len, data, data_len, sig, sig_len);
    return asym_verify(alg_id, key, key_len, data, data_len, sig, sig_len);
}

int kufuli_digest(int alg_id,
                  const unsigned char *data, size_t data_len,
                  unsigned char *out, size_t *out_len) {
    LPCWSTR hash_alg = get_hash_alg_id(alg_id);
    ULONG hash_len = get_hash_len(alg_id);
    if (!hash_alg || hash_len == 0) return KUFULI_ERR_UNSUPPORTED;

    NTSTATUS status = compute_hash(hash_alg, data, data_len, out, hash_len);
    if (!BCRYPT_SUCCESS(status)) return KUFULI_ERR_DIGEST_FAILED;
    *out_len = hash_len;
    return KUFULI_OK;
}

#endif /* _WIN32 */
