/*
 * Single file PicoTLS library
 *
 * Copyright (c) 2023 Ronsor Labs, DeNA Co., Ltd., Kazuho Oku.
 */
#ifndef picotls_full_h
#define picotls_full_h

#pragma defines

#include "picotls.h"
#ifndef PICOTLS_NO_OPENSSL
#include "picotls/openssl.h"
#else
#include "picotls/minicrypto.h"
#endif
#ifdef PICOTLS_USE_BROTLI
#include "picotls/certificate_compression.h"
#endif
#include "picotls/asn1.h"
#include "picotls/ffx.h"
#ifdef PICOTLS_USE_FUSION
#include "picotls/fusion.h"
#endif
#include "picotls/pembase64.h"
#ifdef PICOTLS_COMPAT_LIBTLS
#include "picotls/compat/tls.h"
#endif

#endif
