/*
 * Copyright (c) 2026 Ali Rashid.
 * MIT License - see LICENSE for details.
 *
 * Windows BCrypt backend - stub.
 * Returns KUFULI_ERR_UNSUPPORTED for all operations until Batch 7b.
 */
#include "kufuli_crypto.h"

#if defined(_WIN32)

int kufuli_sign(int alg_id,
                const unsigned char* key, size_t key_len,
                const unsigned char* data, size_t data_len,
                unsigned char* sig_out, size_t* sig_len) {
    (void)alg_id; (void)key; (void)key_len;
    (void)data; (void)data_len;
    (void)sig_out; (void)sig_len;
    return KUFULI_ERR_UNSUPPORTED;
}

int kufuli_verify(int alg_id,
                  const unsigned char* key, size_t key_len,
                  const unsigned char* data, size_t data_len,
                  const unsigned char* sig, size_t sig_len) {
    (void)alg_id; (void)key; (void)key_len;
    (void)data; (void)data_len;
    (void)sig; (void)sig_len;
    return KUFULI_ERR_UNSUPPORTED;
}

int kufuli_digest(int alg_id,
                  const unsigned char* data, size_t data_len,
                  unsigned char* out, size_t* out_len) {
    (void)alg_id; (void)data; (void)data_len;
    (void)out; (void)out_len;
    return KUFULI_ERR_UNSUPPORTED;
}

#endif /* _WIN32 */
