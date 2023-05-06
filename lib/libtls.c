/*
 * Copyright (c) 2023 Ronsor Labs
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
#include <assert.h>
#include <stdlib.h>
#include "picotls.h"
#include "picotls/minicrypto.h"
#include "picotls/compat/tls_internal.h"
#ifndef PICOTLS_MINILIBC
#include <errno.h>
#define clear_errno() errno = 0
#else
#define clear_errno() (0)
#endif

#define set_tls_errno(x)  (ctx->tls_errno = (x))
#define clear_tls_errno() set_tls_errno(0)

int tls_init(void) {
    return 0;
}

const char* tls_error(struct tls* ctx) {
    if (!ctx->tls_errno) return NULL;
    return "Unknown error";
}

const char* tls_config_error(struct tls_config* config) {
    return config->err_str;
}

const char* tls_default_ca_cert_file(void) {
    return tls_default_ca_cert_file_();
}

/* Note: we have yet to support actual certificate verification.
   These simply wrap ptls_minicrypto_load_public_key_* for PUBLIC KEY
   verification only. Only PEM encoding is supported for now.

   Data is lazy-loaded on demand, not at the time these are called. */

int tls_config_set_ca_file(struct tls_config *config, const char *ca_file) {
    free(config->ca_cert_file); config->ca_cert_file = NULL;
    free(config->ca_cert_data); config->ca_cert_data = NULL;

    if (!ca_file) {
        config->err_str = "tls_config_set_ca_file: ca_file == NULL";
        return -1;
    }

    int len = strlen(ca_file) + 1;
    config->ca_cert_file = malloc(len);
    if (!config->ca_cert_file) {
        config->err_str = "tls_config_set_ca_file: out of memory";
        return -1;
    }
    memcpy(config->ca_cert_file, ca_file, len);

    config->err_str = NULL;
    return 0;
}

int tls_config_set_ca_mem(struct tls_config *config, const uint8_t* cert, size_t len) {
    free(config->ca_cert_file); config->ca_cert_file = NULL;
    free(config->ca_cert_data); config->ca_cert_data = NULL;

    if (!cert || !len) {
        config->err_str = "tls_config_set_ca_mem: cert == NULL || len == 0";
        return -1;
    }

    config->ca_cert_data = malloc(len + 1);
    if (!config->ca_cert_data) {
        config->err_str = "tls_config_set_ca_mem: out of memory";
        return -1;
    }

    memcpy(config->ca_cert_data, cert, len);
    config->ca_cert_data_len = len;
    config->ca_cert_data[len] = '\0';

    config->ca_cert_data_pem = 1;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = config->ca_cert_data[i];
        if (c > 0x7F) {
            config->ca_cert_data_pem = 0;
            break;
        }
    }

    config->err_str = NULL;
    return 0;
}

int tls_config_insecure_noverifycert(struct tls_config* config) { config->enable_verify = 0; return 0;  }
int tls_config_insecure_noverifyname(struct tls_config* config) { config->enable_verify = 0; return 0;  }
int tls_config_insecure_noverifytime(struct tls_config* config) { config->enable_verify = 0; return 0;  }
int tls_config_insecure_verifyifca(struct tls_config* config)   { config->enable_verify = -1; return 0; }
int tls_config_verify(struct tls_config* config) {
    if (!config->ca_cert_file && !config->ca_cert_data) {
        config->err_str = "tls_config_verify: no CA";
        return -1;
    }

    config->enable_verify = 1;
    return 0;
}

struct tls_config* tls_config_new(void) {
    struct tls_config* config = malloc(sizeof(struct tls_config));
    if (!config) return NULL;

    memset(config, '\0', sizeof(struct tls_config));

    /* Set defaults */
    config->ctx.random_bytes = ptls_minicrypto_random_bytes;
    config->ctx.get_time = &ptls_get_time;
    config->ctx.key_exchanges = ptls_minicrypto_key_exchanges;
    config->ctx.cipher_suites = ptls_minicrypto_cipher_suites;

    config->enable_verify = -1;

    return config;
}

void tls_config_free(struct tls_config* config) {
    free(config->ca_cert_file);
    free(config->ca_cert_data);
    free(config);
}

inline static void tls_ctx_init(struct tls* ctx) {
    memset(&ctx->config, '\0', sizeof(struct tls_config));
    ctx->tls = NULL;

    ctx->recvbuf_pos = 0;
    ptls_buffer_init(&ctx->recvbuf, "", 0);

    ctx->sendbuf_pos = 0;
    ptls_buffer_init(&ctx->sendbuf, "", 0);

    ctx->tls_errno = 0;

    ctx->last_buf = 0;
}

inline static void tls_ctx_deinit(struct tls* ctx) {
    if (ctx->tls) ptls_free(ctx->tls);
    if (ctx->config.ctx.verify_certificate)
        free(ctx->config.ctx.verify_certificate);

    ptls_buffer_dispose(&ctx->recvbuf);
    ptls_buffer_dispose(&ctx->sendbuf);
}

struct tls* tls_client(void) {
    struct tls* ctx = malloc(sizeof(struct tls));
    if (!ctx) return NULL;

    tls_ctx_init(ctx);

    return ctx;
}

int tls_configure(struct tls* ctx, struct tls_config* config) {
    clear_tls_errno();

    memcpy(&ctx->config, config, sizeof(struct tls_config));

    if (ctx->config.ca_cert_file) {
        int ret = ptls_minicrypto_load_public_key_file(&ctx->config.ctx, ctx->config.ca_cert_file);
        if (ret < 0) {
            set_tls_errno(PTLS_ERROR_INCOMPATIBLE_KEY);
            return -1;
        }
    } else if (ctx->config.ca_cert_data) {
        int ret = -1;
        if (ctx->config.ca_cert_data_pem) {
            ret = ptls_minicrypto_load_public_key_str(&ctx->config.ctx, (const char*)ctx->config.ca_cert_data);
        } else {
            ptls_iovec_t ca_cert = {ctx->config.ca_cert_data, ctx->config.ca_cert_data_len};
            ret = ptls_minicrypto_load_public_key_vec(&ctx->config.ctx, ca_cert);
        }
        if (ret < 0) {
            set_tls_errno(PTLS_ERROR_INCOMPATIBLE_KEY);
            return -1;
        }
    }

    if (ctx->config.enable_verify > 0 && !ctx->config.ctx.verify_certificate) {
        set_tls_errno(PTLS_ERROR_INCOMPATIBLE_KEY);
        return -1;
    }

    return 0;
}

void tls_reset(struct tls* ctx) {
    tls_ctx_deinit(ctx);
    tls_ctx_init(ctx);
}

void tls_free(struct tls* ctx) {
    tls_ctx_deinit(ctx);
    free(ctx);
}

int tls_connect_cbs(struct tls* ctx, tls_read_cb read_cb, tls_write_cb write_cb, void* cb_arg,
                    const char* servername) {
    ctx->tls = ptls_client_new(&ctx->config.ctx);
    if (!ctx->tls) return -1;

    ctx->read = read_cb;
    ctx->write = write_cb;
    ctx->cb_arg = cb_arg;

    if (servername != NULL)
        ptls_set_server_name(ctx->tls, servername, 0);

    int status = ptls_handshake(ctx->tls, &ctx->sendbuf, NULL, NULL, NULL);
    assert(status == PTLS_ERROR_IN_PROGRESS);

    return 0;
}

static int tls_flush_sendbuf(struct tls* ctx) {
    if (ctx->sendbuf.off != 0) {
        const void* buf = ctx->sendbuf.base + ctx->sendbuf_pos;
        size_t buflen = ctx->sendbuf.off - ctx->sendbuf_pos;
        ssize_t wret = ctx->write(ctx, buf, buflen, ctx->cb_arg);
        if (wret < 0)
            return wret;
        else if (wret == 0)
            return -1;
        else if (wret < buflen) {
            ctx->sendbuf_pos += wret;
            return TLS_WANT_POLLOUT;
        } else {
            ctx->sendbuf_pos = 0;
            ptls_buffer_dispose(&ctx->sendbuf);
            ptls_buffer_init(&ctx->sendbuf, "", 0);
        }
    }
    return 0;
}

int tls_handshake(struct tls* ctx) {
    clear_errno();
    clear_tls_errno();

    if (ptls_handshake_is_complete(ctx->tls)) return 0;

    int status = tls_flush_sendbuf(ctx);
    if (status != 0)
        return status;

    char buffer[8192];
    ssize_t rret, roff;
    int ret;
    do {
        rret = ctx->read(ctx, buffer, sizeof(buffer), ctx->cb_arg);
        if (rret < 0)
            return rret;
        else if (rret == 0)
            return -1;

        roff = 0;
        do {
            size_t consumed = rret - roff;
            ret = ptls_handshake(ctx->tls, &ctx->sendbuf, buffer + roff, &consumed, NULL);
            if (ret == 0 || ret == PTLS_ERROR_IN_PROGRESS) {
                tls_flush_sendbuf(ctx);
            } else if (ret != 0) {
                set_tls_errno(ret);
                return -1;
            }
            roff += consumed;
        } while (ret == PTLS_ERROR_IN_PROGRESS && rret != roff);

        status = tls_flush_sendbuf(ctx);
        if (status != 0)
            return status;
    } while (ret == PTLS_ERROR_IN_PROGRESS);

    if (rret - roff > 0) {
        do {
            size_t consumed = rret - roff;
            ret = ptls_receive(ctx->tls, &ctx->recvbuf, buffer + roff, &consumed);
            roff += consumed;
        } while (ret == 0 && roff < rret);

        if (ret != 0) {
            set_tls_errno(ret);
            return -1;
        }
    }

    return 0;
}

ssize_t tls_read(struct tls* ctx, void* buf, size_t buflen) {
    clear_errno();
    clear_tls_errno();

    ssize_t status = tls_handshake(ctx);
    if (status != 0)
        return status;

    int ret = 0;
    size_t reallen = buflen;
    ssize_t roff = 0, rret = 0;

    int buffer_is_allocated = 0;
    char stack_buffer[8192], *buffer = stack_buffer;
    size_t buffer_size = sizeof(stack_buffer);

    if (ctx->recvbuf.off - ctx->recvbuf_pos >= buflen) {
        goto copy;
    }

    if ((buflen * 2) > buffer_size) {
        buffer_size = buflen * 2;
        buffer_is_allocated = 1;
        buffer = malloc(buffer_size);
        if (!buffer)
            return -1;
    }

    rret = ctx->read(ctx, buffer, buffer_size, ctx->cb_arg);
    if (rret < 0) {
        status = rret;
        goto done;
    } else if (rret == 0) {
        status = -1;
        goto done;
    }

    do {
        size_t consumed = rret - roff;
        ret = ptls_receive(ctx->tls, &ctx->recvbuf, buffer + roff, &consumed);
        roff += consumed;
    } while (ret == 0 && roff < rret);

    if (ret != 0) {
        status = -1;
        set_tls_errno(ret);
        goto done;
    }

copy:
    if (reallen > ctx->recvbuf.off - ctx->recvbuf_pos) {
        reallen = ctx->recvbuf.off - ctx->recvbuf_pos;
    }

    memcpy(buf, ctx->recvbuf.base, reallen);
    ctx->recvbuf_pos += reallen;

    if (ctx->recvbuf_pos == ctx->recvbuf.off) {
        ptls_buffer_dispose(&ctx->recvbuf);
        ptls_buffer_init(&ctx->recvbuf, "", 0);
    }

    status = reallen;

done:
    if (buffer_is_allocated)
        free(buffer);

    return status;
}

ssize_t tls_write(struct tls* ctx, const void* buf, size_t buflen) {
    clear_errno();
    clear_tls_errno();

    int status = tls_handshake(ctx);
    if (status != 0)
        return status;

    if (buf == ctx->last_buf) {
        status = tls_flush_sendbuf(ctx);
        if (status == 0)
            ctx->last_buf = 0;
        return status;
    } else {
        ctx->last_buf = 0;
    }

    int ret = ptls_send(ctx->tls, &ctx->sendbuf, buf, buflen);
    if (ret != 0)
        return -1;

    status = tls_flush_sendbuf(ctx);
    if (status == TLS_WANT_POLLOUT) {
        ctx->last_buf = buf;
    }

    if (status < 0)
        return status;

    return buflen;
}

int tls_close(struct tls* ctx) {
    clear_errno();
    clear_tls_errno();

    if (ctx->last_buf == (void*)1) {
       return tls_flush_sendbuf(ctx);
    }

    ctx->last_buf = (void*)1;

    int ret = ptls_send_alert(ctx->tls, &ctx->sendbuf,
                              PTLS_ALERT_LEVEL_WARNING, PTLS_ALERT_CLOSE_NOTIFY);

    if (ret != 0) {
        set_tls_errno(ret);
        return -1;
    }

    return tls_flush_sendbuf(ctx);
}
