/*
 * Single file PicoTLS library
 *
 * Copyright (c) 2023 Ronsor Labs, DeNA Co., Ltd., Kazuho Oku.
 */

#ifdef PICOTLS_MINILIBC
#include "minilibc.h"
#define FULL_FAT_ASSERT
#endif

#include "picotls.h"
#include "lib/chacha20poly1305.h"

#include "lib/pembase64.c"
#ifndef PICOTLS_NO_OPENSSL
#include "lib/openssl.c"
#else
#include "lib/asn1.c"
#include "deps/micro-ecc/uECC.c"
#include "deps/cifra/src/aes.c"
#include "deps/cifra/src/blockwise.c"
#include "deps/cifra/src/chacha20.c"
#include "deps/cifra/src/chash.c"
#define add add1
#include "deps/cifra/src/curve25519.c"
#undef add
#include "deps/cifra/src/drbg.c"
#include "deps/cifra/src/hmac.c"
#include "deps/cifra/src/gcm.c"
#include "deps/cifra/src/gf128.c"
#include "deps/cifra/src/modes.c"
#include "deps/cifra/src/poly1305.c"
#define add add2
#define K K1
#include "deps/cifra/src/sha256.c"
#undef K
#undef add
#undef SSIG0
#undef SSIG1
#undef BSIG0
#undef BSIG1
#define K K2
#include "deps/cifra/src/sha512.c"
#undef K
#undef SSIG0
#undef SSIG1
#undef BSIG0
#undef BSIG1
#include "lib/cifra.c"
#include "lib/cifra/x25519.c"
#include "lib/cifra/chacha20.c"
#include "lib/cifra/aes128.c"
#include "lib/cifra/aes256.c"
#include "lib/cifra/random.c"
#include "lib/minicrypto-pem.c"
#include "lib/minicrypto-hpke.c"
#include "lib/uecc.c"
#include "lib/ffx.c"
#endif
#ifdef PICOTLS_USE_FUSION
#include "lib/fusion.c"
#endif
#ifdef PICOTLS_USE_BROTLI
#include "lib/certificate_compression.c"
#endif
#include "lib/hpke.c"
#include "lib/picotls.c"
#ifdef PICOTLS_COMPAT_LIBTLS
#include "lib/libtls.c"
#endif
