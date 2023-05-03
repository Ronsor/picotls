/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WINDOWS
#include "wincompat.h"
#else
#include <unistd.h>
#endif
#include "sha2.h"
#include "uECC.h"
#include "uECC_vli.h"
#include "picotls.h"
#include "picotls/minicrypto.h"
#include "picotls/asn1.h"

#define TYPE_UNCOMPRESSED_PUBLIC_KEY 4

struct st_secp256r1_key_exhchange_t {
    ptls_key_exchange_context_t super;
    uint8_t priv[SECP256R1_PRIVATE_KEY_SIZE];
    uint8_t pub[SECP256R1_PUBLIC_KEY_SIZE];
};

static int secp256r1_on_exchange(ptls_key_exchange_context_t **_ctx, int release, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    struct st_secp256r1_key_exhchange_t *ctx = (struct st_secp256r1_key_exhchange_t *)*_ctx;
    uint8_t *secbytes = NULL;
    int ret;

    if (secret == NULL) {
        ret = 0;
        goto Exit;
    }

    if (peerkey.len != SECP256R1_PUBLIC_KEY_SIZE || peerkey.base[0] != TYPE_UNCOMPRESSED_PUBLIC_KEY) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    if ((secbytes = (uint8_t *)malloc(SECP256R1_SHARED_SECRET_SIZE)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (!uECC_shared_secret(peerkey.base + 1, ctx->priv, secbytes, uECC_secp256r1())) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    *secret = ptls_iovec_init(secbytes, SECP256R1_SHARED_SECRET_SIZE);
    ret = 0;

Exit:
    if (ret != 0)
        free(secbytes);
    if (release) {
        ptls_clear_memory(ctx->priv, sizeof(ctx->priv));
        free(ctx);
        *_ctx = NULL;
    }
    return ret;
}

static int secp256r1_create_key_exchange(ptls_key_exchange_algorithm_t *algo, ptls_key_exchange_context_t **_ctx)
{
    struct st_secp256r1_key_exhchange_t *ctx;

    if ((ctx = (struct st_secp256r1_key_exhchange_t *)malloc(sizeof(*ctx))) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    ctx->super = (ptls_key_exchange_context_t){algo, ptls_iovec_init(ctx->pub, sizeof(ctx->pub)), secp256r1_on_exchange};
    ctx->pub[0] = TYPE_UNCOMPRESSED_PUBLIC_KEY;

    /* RNG function must be set before calling uECC_make_key() */
    assert(uECC_get_rng() != NULL);
    uECC_make_key(ctx->pub + 1, ctx->priv, uECC_secp256r1());

    *_ctx = &ctx->super;
    return 0;
}

static int secp256r1_key_exchange(ptls_key_exchange_algorithm_t *algo, ptls_iovec_t *pubkey, ptls_iovec_t *secret,
                                  ptls_iovec_t peerkey)
{
    uint8_t priv[SECP256R1_PRIVATE_KEY_SIZE], *pub = NULL, *secbytes = NULL;
    int ret;

    if (peerkey.len != SECP256R1_PUBLIC_KEY_SIZE || peerkey.base[0] != TYPE_UNCOMPRESSED_PUBLIC_KEY) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    if ((pub = malloc(SECP256R1_PUBLIC_KEY_SIZE)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((secbytes = malloc(SECP256R1_SHARED_SECRET_SIZE)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    pub[0] = TYPE_UNCOMPRESSED_PUBLIC_KEY;
    uECC_make_key(pub + 1, priv, uECC_secp256r1());
    if (!uECC_shared_secret(peerkey.base + 1, priv, secbytes, uECC_secp256r1())) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    *pubkey = ptls_iovec_init(pub, SECP256R1_PUBLIC_KEY_SIZE);
    *secret = ptls_iovec_init(secbytes, SECP256R1_SHARED_SECRET_SIZE);
    ret = 0;

Exit:
    ptls_clear_memory(priv, sizeof(priv));
    if (ret != 0) {
        free(secbytes);
        free(pub);
    }
    return ret;
}

static int secp256r1sha256_sign(ptls_sign_certificate_t *_self, ptls_t *tls, ptls_async_job_t **async, uint16_t *selected_algorithm,
                                ptls_buffer_t *outbuf, ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms)
{
    ptls_minicrypto_secp256r1sha256_sign_certificate_t *self = (ptls_minicrypto_secp256r1sha256_sign_certificate_t *)_self;
    uint8_t hash[32], sig[64];
    size_t i;
    int ret;

    /* check algorithm */
    for (i = 0; i != num_algorithms; ++i)
        if (algorithms[i] == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256)
            break;
    if (i == num_algorithms)
        return PTLS_ALERT_HANDSHAKE_FAILURE;

    { /* calc hash */
        cf_sha256_context ctx;
        cf_sha256_init(&ctx);
        cf_sha256_update(&ctx, input.base, input.len);
        cf_sha256_digest_final(&ctx, hash);
        ptls_clear_memory(&ctx, sizeof(ctx));
    }

    /* sign */
    uECC_sign(self->key, hash, sizeof(hash), sig, uECC_secp256r1());

    /* encode using DER */
    ptls_buffer_push_asn1_sequence(outbuf, {
        if ((ret = ptls_buffer_push_asn1_ubigint(outbuf, sig, 32)) != 0)
            goto Exit;
        if ((ret = ptls_buffer_push_asn1_ubigint(outbuf, sig + 32, 32)) != 0)
            goto Exit;
    });

    *selected_algorithm = PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256;
    ret = 0;

Exit:
    ptls_clear_memory(hash, sizeof(hash));
    ptls_clear_memory(sig, sizeof(sig));
    return ret;
}

int ptls_minicrypto_init_secp256r1sha256_sign_certificate(ptls_minicrypto_secp256r1sha256_sign_certificate_t *self,
                                                          ptls_iovec_t key)
{
    if (key.len != sizeof(self->key))
        return PTLS_ERROR_INCOMPATIBLE_KEY;

    self->super.cb = secp256r1sha256_sign;
    memcpy(self->key, key.base, sizeof(self->key));

    return 0;
}

size_t ptls_minicrypto_asn1_decode_ecdsa_signature(ptls_iovec_t raw_sig, ptls_iovec_t encoded_sig,
                                                   int *decode_error, ptls_minicrypto_log_ctx_t *log_ctx)
{
    uint8_t *bytes = encoded_sig.base;
    size_t bytes_max = encoded_sig.len;
    uint32_t part_size = raw_sig.len >> 1;
    uint32_t seq_length;
    size_t last_byte;
    uint32_t r_length, s_length;
    size_t r_last, s_last;

    /* read the ASN1 messages */
    size_t byte_index = 0;

    /* start with sequence */
    byte_index = ptls_asn1_get_expected_type_and_length(bytes, bytes_max, byte_index, 0x30, &seq_length, NULL, &last_byte,
                                                        decode_error, log_ctx);

    if (*decode_error == 0 && bytes_max != last_byte) {
        byte_index = ptls_asn1_error_message("Length larger than message", bytes_max, byte_index, 0, log_ctx);
        *decode_error = PTLS_ERROR_BER_EXCESSIVE_LENGTH;
    }

    if (*decode_error == 0) {
        /* read r */
        byte_index = ptls_asn1_get_expected_type_and_length(bytes, last_byte, byte_index, 0x02, &r_length, NULL, &r_last,
                                                            decode_error, log_ctx);

        if (*decode_error == 0 && r_length > part_size + 1) {
            *decode_error = PTLS_ERROR_BER_EXCESSIVE_LENGTH;
        } else {
            uint32_t diff = r_length > part_size ? r_length - part_size : 0;
            uint32_t size = r_length > part_size ? part_size : r_length;
            memcpy(raw_sig.base, bytes + byte_index + diff, size);
        }
    }

    byte_index = r_last;

    if (*decode_error == 0) {
        /* read s */
        byte_index = ptls_asn1_get_expected_type_and_length(bytes, last_byte, byte_index, 0x02, &s_length, NULL, &s_last,
                                                            decode_error, log_ctx);

        if (*decode_error == 0 && s_length > part_size + 1) {
            *decode_error = PTLS_ERROR_BER_EXCESSIVE_LENGTH;
        } else {
            uint32_t diff = s_length > part_size ? s_length - part_size : 0;
            uint32_t size = s_length > part_size ? part_size : s_length;
            memcpy(raw_sig.base + part_size, bytes + byte_index + diff, size);
        }
    }

    return byte_index;
}

static int secp256r1sha256_verify_sign(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t signature) {
    uint8_t hash[32], raw_sig_data[64], *key = verify_ctx + 1;
    ptls_iovec_t raw_sig = {raw_sig_data, sizeof(raw_sig_data)};

    if (algo != PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256)
        return PTLS_ALERT_HANDSHAKE_FAILURE;

    int decode_error = 0;
    ptls_minicrypto_asn1_decode_ecdsa_signature(raw_sig, signature, &decode_error, NULL);
    if (decode_error != 0)
        return PTLS_ALERT_DECRYPT_ERROR;

    {
        cf_sha256_context ctx;
        cf_sha256_init(&ctx);
        cf_sha256_update(&ctx, data.base, data.len);
        cf_sha256_digest_final(&ctx, hash);
        ptls_clear_memory(&ctx, sizeof(ctx));
    }

    if (!uECC_verify(key, hash, sizeof(hash), raw_sig_data, uECC_secp256r1())) {
        return PTLS_ALERT_DECRYPT_ERROR;
    }

    return 0;
}

static int secp256r1sha256_verify(ptls_verify_certificate_t *_self, ptls_t *tls, const char *server_name,
                                  int (**verifier)(void *, uint16_t algo, ptls_iovec_t, ptls_iovec_t), void **verify_data,
                                  ptls_iovec_t *certs, size_t num_certs)
{
    ptls_minicrypto_secp256r1sha256_verify_certificate_t *self = (ptls_minicrypto_secp256r1sha256_verify_certificate_t *)_self;
    int ret = PTLS_ALERT_BAD_CERTIFICATE;
    ptls_iovec_t expected_pubkey = {self->key, sizeof(self->key)};

    assert(num_certs != 0);

    if (num_certs != 1)
        return ret;

/*    if (certs[0].len != expected_pubkey.len)
         return ret;*/

/*    if (!ptls_mem_equal(expected_pubkey.base, certs[0].base, certs[0].len))
         return ret;*/

    *verify_data = self->key;
    *verifier = secp256r1sha256_verify_sign;
    ret = 0;

    return ret;
}

int ptls_minicrypto_init_secp256r1sha256_verify_certificate(ptls_minicrypto_secp256r1sha256_verify_certificate_t* self,
                                                            ptls_iovec_t key)
{
    static const uint16_t signature_schemes[] = {PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256, UINT16_MAX};

    if (key.len != sizeof(self->key))
        return PTLS_ERROR_INCOMPATIBLE_KEY;

    self->super.cb = secp256r1sha256_verify;
    self->super.algos = signature_schemes;
    memcpy(self->key, key.base, sizeof(self->key));

    return 0;
}

ptls_key_exchange_algorithm_t ptls_minicrypto_secp256r1 = {.id = PTLS_GROUP_SECP256R1,
                                                           .name = PTLS_GROUP_NAME_SECP256R1,
                                                           .create = secp256r1_create_key_exchange,
                                                           .exchange = secp256r1_key_exchange};
ptls_key_exchange_algorithm_t *ptls_minicrypto_key_exchanges[] = {&ptls_minicrypto_secp256r1, NULL};
