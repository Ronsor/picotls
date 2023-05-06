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

int tls_init() {
    return 0;
}

const char* tls_error(struct tls* ctx) {
    if (!ctx->tls_errno) return NULL;
    return "Unknown error";
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

    return config;
}

void tls_config_free(struct tls_config* config) {
    free(config);
}

struct tls* tls_client(void) {
    struct tls* ctx = malloc(sizeof(struct tls));
    if (!ctx) return NULL;

    memset(&ctx->config, '\0', sizeof(struct tls_config));
    ctx->tls = NULL;

    ctx->recvbuf_pos = 0;
    ptls_buffer_init(&ctx->recvbuf, "", 0);

    ctx->sendbuf_pos = 0;
    ptls_buffer_init(&ctx->sendbuf, "", 0);

    ctx->tls_errno = 0;

    ctx->last_buf = 0;

    return ctx;
}

int tls_configure(struct tls* ctx, struct tls_config* config) {
    memcpy(&ctx->config, config, sizeof(struct tls_config));

    return 0;
}

void tls_free(struct tls* ctx) {
    if (ctx->tls) ptls_free(ctx->tls);

    ptls_buffer_dispose(&ctx->recvbuf);
    ptls_buffer_dispose(&ctx->sendbuf);

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

    int status = tls_handshake(ctx);
    if (status != 0)
        return status;

    int ret = 0;
    size_t reallen = buflen;
    ssize_t roff = 0, rret = 0;

    int buffer_is_allocated = 0;
    char stack_buffer[8192], *buffer = stack_buffer;
    size_t buffer_size = sizeof(stack_buffer);

    if (ctx->recvbuf.off - ctx->recvbuf_pos >= buflen) {
        goto done;
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
    return status;
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
