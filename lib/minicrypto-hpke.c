/*
 * Copyright (c) 2023 Ronsor Labs, DeNA Co., Ltd., Kazuho Oku
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
#include <stddef.h>
#include "picotls/minicrypto.h"

ptls_hpke_kem_t ptls_minicrypto_hpke_kem_p256sha256 = {PTLS_HPKE_KEM_P256_SHA256, &ptls_minicrypto_secp256r1, &ptls_minicrypto_sha256};
ptls_hpke_kem_t *ptls_minicrypto_hpke_kems[] = {&ptls_minicrypto_hpke_kem_p256sha256, NULL};

ptls_hpke_cipher_suite_t ptls_minicrypto_hpke_aes128gcmsha256 = {
    .id = {.kdf = PTLS_HPKE_HKDF_SHA256, .aead = PTLS_HPKE_AEAD_AES_128_GCM},
    .name = "HKDF-SHA256/AES-128-GCM",
    .hash = &ptls_minicrypto_sha256,
    .aead = &ptls_minicrypto_aes128gcm};
ptls_hpke_cipher_suite_t ptls_minicrypto_hpke_aes128gcmsha512 = {
    .id = {.kdf = PTLS_HPKE_HKDF_SHA512, .aead = PTLS_HPKE_AEAD_AES_128_GCM},
    .name = "HKDF-SHA512/AES-128-GCM",
    .hash = &ptls_minicrypto_sha512,
    .aead = &ptls_minicrypto_aes128gcm};
ptls_hpke_cipher_suite_t ptls_minicrypto_hpke_aes256gcmsha384 = {
    .id = {.kdf = PTLS_HPKE_HKDF_SHA384, .aead = PTLS_HPKE_AEAD_AES_256_GCM},
    .name = "HKDF-SHA384/AES-256-GCM",
    .hash = &ptls_minicrypto_sha384,
    .aead = &ptls_minicrypto_aes256gcm};
ptls_hpke_cipher_suite_t ptls_minicrypto_hpke_chacha20poly1305sha256 = {
    .id = {.kdf = PTLS_HPKE_HKDF_SHA256, .aead = PTLS_HPKE_AEAD_CHACHA20POLY1305},
    .name = "HKDF-SHA256/ChaCha20Poly1305",
    .hash = &ptls_minicrypto_sha256,
    .aead = &ptls_minicrypto_chacha20poly1305};

ptls_hpke_cipher_suite_t *ptls_minicrypto_hpke_cipher_suites[] = {&ptls_minicrypto_hpke_aes128gcmsha256,
                                                               &ptls_minicrypto_hpke_aes256gcmsha384,
                                                               &ptls_minicrypto_hpke_chacha20poly1305sha256,
                                                               &ptls_minicrypto_hpke_aes128gcmsha512, /* likely only for tests */
                                                               NULL};
