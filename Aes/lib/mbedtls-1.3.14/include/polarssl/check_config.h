/**
 * \file check_config.h
 *
 * \brief Consistency checks for configuration options
 *
 *  Copyright (C) 2006-2014, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * It is recommended to include this file from your config.h
 * in order to catch dependency issues early.
 */

#ifndef POLARSSL_CHECK_CONFIG_H
#define POLARSSL_CHECK_CONFIG_H

#if defined(POLARSSL_DEPRECATED_WARNING) && \
    !defined(__GNUC__) && !defined(__clang__)
#error "POLARSSL_DEPRECATED_WARNING only works with GCC and Clang"
#endif

#if defined(POLARSSL_NET_C) && !defined(POLARSSL_HAVE_IPV6)
#if defined(POLARSSL_DEPRECATED_WARNING)
#warning "Using POLARSSL_NET_C without POLARSSL_HAVE_IPV6 is deprecated"
#endif
#if defined(POLARSSL_DEPRECATED_REMOVED)
#define POLARSSL_HAVE_IPV6
#endif
#endif /* POLARSSL_NET_C && !POLARSSL_HAVE_IPV6 */

#if defined(POLARSSL_ERROR_STRERROR_BC)
#if defined(POLARSSL_DEPRECATED_WARNING)
#warning "POLARSSL_ERROR_STRERROR_BC is deprecated"
#endif
#if defined(POLARSSL_DEPRECATED_REMOVED)
#error "POLARSSL_ERROR_STRERROR_BC is deprecated"
#endif
#endif /* POLARSSL_ERROR_STRERROR_BC */

#if defined(POLARSSL_MEMORY_C)
#if defined(POLARSSL_DEPRECATED_WARNING)
#warning "POLARSSL_MEMORY_C is deprecated"
#endif
#if defined(POLARSSL_DEPRECATED_REMOVED)
#error "POLARSSL_MEMORY_C is deprecated"
#endif
#endif /* POLARSSL_MEMORY_C */

#if defined(POLARSSL_PBKDF2_C)
#if defined(POLARSSL_DEPRECATED_WARNING)
#warning "POLARSSL_PBKDF2_C is deprecated"
#endif
#if defined(POLARSSL_DEPRECATED_REMOVED)
#error "POLARSSL_PBKDF2_C is deprecated"
#endif
#endif /* POLARSSL_PBKDF2_C */

#if defined(POLARSSL_HAVE_INT8)
#if defined(POLARSSL_DEPRECATED_WARNING)
#warning "POLARSSL_HAVE_INT8 is deprecated"
#endif
#if defined(POLARSSL_DEPRECATED_REMOVED)
#error "POLARSSL_HAVE_INT8 is deprecated"
#endif
#endif /* POLARSSL_HAVE_INT8 */

#if defined(POLARSSL_HAVE_INT16)
#if defined(POLARSSL_DEPRECATED_WARNING)
#warning "POLARSSL_HAVE_INT16 is deprecated"
#endif
#if defined(POLARSSL_DEPRECATED_REMOVED)
#error "POLARSSL_HAVE_INT16 is deprecated"
#endif
#endif /* POLARSSL_HAVE_INT16 */

#if defined(POLARSSL_AESNI_C) && !defined(POLARSSL_HAVE_ASM)
#error "POLARSSL_AESNI_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_CERTS_C) && !defined(POLARSSL_PEM_PARSE_C)
#error "POLARSSL_CERTS_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_CTR_DRBG_C) && !defined(POLARSSL_AES_C)
#error "POLARSSL_CTR_DRBG_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_DHM_C) && !defined(POLARSSL_BIGNUM_C)
#error "POLARSSL_DHM_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_ECDH_C) && !defined(POLARSSL_ECP_C)
#error "POLARSSL_ECDH_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_ECDSA_C) &&            \
    ( !defined(POLARSSL_ECP_C) ||           \
      !defined(POLARSSL_ASN1_PARSE_C) ||    \
      !defined(POLARSSL_ASN1_WRITE_C) )
#error "POLARSSL_ECDSA_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_ECDSA_DETERMINISTIC) && !defined(POLARSSL_HMAC_DRBG_C)
#error "POLARSSL_ECDSA_DETERMINISTIC defined, but not all prerequisites"
#endif

#if defined(POLARSSL_ECP_C) && ( !defined(POLARSSL_BIGNUM_C) || (   \
    !defined(POLARSSL_ECP_DP_SECP192R1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_SECP224R1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_SECP256R1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_SECP384R1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_SECP521R1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_BP256R1_ENABLED)   &&                  \
    !defined(POLARSSL_ECP_DP_BP384R1_ENABLED)   &&                  \
    !defined(POLARSSL_ECP_DP_BP512R1_ENABLED)   &&                  \
    !defined(POLARSSL_ECP_DP_SECP192K1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_SECP224K1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_SECP256K1_ENABLED) ) )
#error "POLARSSL_ECP_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_ENTROPY_C) && (!defined(POLARSSL_SHA512_C) &&      \
                                    !defined(POLARSSL_SHA256_C))
#error "POLARSSL_ENTROPY_C defined, but not all prerequisites"
#endif
#if defined(POLARSSL_ENTROPY_C) && defined(POLARSSL_SHA512_C) &&         \
    defined(CTR_DRBG_ENTROPY_LEN) && (CTR_DRBG_ENTROPY_LEN > 64)
#error "CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(POLARSSL_ENTROPY_C) &&                                            \
    ( !defined(POLARSSL_SHA512_C) || defined(POLARSSL_ENTROPY_FORCE_SHA256) ) \
    && defined(CTR_DRBG_ENTROPY_LEN) && (CTR_DRBG_ENTROPY_LEN > 32)
#error "CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(POLARSSL_ENTROPY_C) && \
    defined(POLARSSL_ENTROPY_FORCE_SHA256) && !defined(POLARSSL_SHA256_C)
#error "POLARSSL_ENTROPY_FORCE_SHA256 defined, but not all prerequisites"
#endif

#if defined(POLARSSL_GCM_C) && (                                        \
        !defined(POLARSSL_AES_C) && !defined(POLARSSL_CAMELLIA_C) )
#error "POLARSSL_GCM_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_HAVEGE_C) && !defined(POLARSSL_TIMING_C)
#error "POLARSSL_HAVEGE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_HMAC_DRBG) && !defined(POLARSSL_MD_C)
#error "POLARSSL_HMAC_DRBG_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_ECDH_ECDSA_ENABLED) &&                 \
    ( !defined(POLARSSL_ECDH_C) || !defined(POLARSSL_X509_CRT_PARSE_C) )
#error "POLARSSL_KEY_EXCHANGE_ECDH_ECDSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_ECDH_RSA_ENABLED) &&                 \
    ( !defined(POLARSSL_ECDH_C) || !defined(POLARSSL_X509_CRT_PARSE_C) )
#error "POLARSSL_KEY_EXCHANGE_ECDH_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_DHE_PSK_ENABLED) && !defined(POLARSSL_DHM_C)
#error "POLARSSL_KEY_EXCHANGE_DHE_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_ECDHE_PSK_ENABLED) &&                     \
    !defined(POLARSSL_ECDH_C)
#error "POLARSSL_KEY_EXCHANGE_ECDHE_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED) &&                   \
    ( !defined(POLARSSL_DHM_C) || !defined(POLARSSL_RSA_C) ||           \
      !defined(POLARSSL_X509_CRT_PARSE_C) || !defined(POLARSSL_PKCS1_V15) )
#error "POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED) &&                 \
    ( !defined(POLARSSL_ECDH_C) || !defined(POLARSSL_RSA_C) ||          \
      !defined(POLARSSL_X509_CRT_PARSE_C) || !defined(POLARSSL_PKCS1_V15) )
#error "POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) &&                 \
    ( !defined(POLARSSL_ECDH_C) || !defined(POLARSSL_ECDSA_C) ||          \
      !defined(POLARSSL_X509_CRT_PARSE_C) )
#error "POLARSSL_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_RSA_PSK_ENABLED) &&                   \
    ( !defined(POLARSSL_RSA_C) || !defined(POLARSSL_X509_CRT_PARSE_C) || \
      !defined(POLARSSL_PKCS1_V15) )
#error "POLARSSL_KEY_EXCHANGE_RSA_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_RSA_ENABLED) &&                       \
    ( !defined(POLARSSL_RSA_C) || !defined(POLARSSL_X509_CRT_PARSE_C) || \
      !defined(POLARSSL_PKCS1_V15) )
#error "POLARSSL_KEY_EXCHANGE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_MEMORY_C) && !defined(POLARSSL_PLATFORM_C)
#error "POLARSSL_MEMORY_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C) &&                          \
    ( !defined(POLARSSL_PLATFORM_C) || !defined(POLARSSL_PLATFORM_MEMORY) )
#error "POLARSSL_MEMORY_BUFFER_ALLOC_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PADLOCK_C) && !defined(POLARSSL_HAVE_ASM)
#error "POLARSSL_PADLOCK_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PBKDF2_C) && !defined(POLARSSL_MD_C)
#error "POLARSSL_PBKDF2_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PEM_PARSE_C) && !defined(POLARSSL_BASE64_C)
#error "POLARSSL_PEM_PARSE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PEM_WRITE_C) && !defined(POLARSSL_BASE64_C)
#error "POLARSSL_PEM_WRITE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PK_C) && \
    ( !defined(POLARSSL_RSA_C) && !defined(POLARSSL_ECP_C) )
#error "POLARSSL_PK_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PK_PARSE_C) && !defined(POLARSSL_PK_C)
#error "POLARSSL_PK_PARSE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PK_WRITE_C) && !defined(POLARSSL_PK_C)
#error "POLARSSL_PK_WRITE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PKCS11_C) && !defined(POLARSSL_PK_C)
#error "POLARSSL_PKCS11_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_EXIT_ALT) && !defined(POLARSSL_PLATFORM_C)
#error "POLARSSL_PLATFORM_EXIT_ALT defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_EXIT_MACRO) && !defined(POLARSSL_PLATFORM_C)
#error "POLARSSL_PLATFORM_EXIT_MACRO defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_EXIT_MACRO) &&\
    ( defined(POLARSSL_PLATFORM_STD_EXIT) ||\
        defined(POLARSSL_PLATFORM_EXIT_ALT) )
#error "POLARSSL_PLATFORM_EXIT_MACRO and POLARSSL_PLATFORM_STD_EXIT/POLARSSL_PLATFORM_EXIT_ALT cannot be defined simultaneously"
#endif

#if defined(POLARSSL_PLATFORM_FPRINTF_ALT) && !defined(POLARSSL_PLATFORM_C)
#error "POLARSSL_PLATFORM_FPRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_FPRINTF_MACRO) && !defined(POLARSSL_PLATFORM_C)
#error "POLARSSL_PLATFORM_FPRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_FPRINTF_MACRO) &&\
    ( defined(POLARSSL_PLATFORM_STD_FPRINTF) ||\
        defined(POLARSSL_PLATFORM_FPRINTF_ALT) )
#error "POLARSSL_PLATFORM_FPRINTF_MACRO and POLARSSL_PLATFORM_STD_FPRINTF/POLARSSL_PLATFORM_FPRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(POLARSSL_PLATFORM_FREE_MACRO) &&\
    ( !defined(POLARSSL_PLATFORM_C) || !defined(POLARSSL_PLATFORM_MEMORY) )
#error "POLARSSL_PLATFORM_FREE_MACRO defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_FREE_MACRO) &&\
    defined(POLARSSL_PLATFORM_STD_FREE)
#error "POLARSSL_PLATFORM_FREE_MACRO and POLARSSL_PLATFORM_STD_FREE cannot be defined simultaneously"
#endif

#if defined(POLARSSL_PLATFORM_FREE_MACRO) && !defined(POLARSSL_PLATFORM_MALLOC_MACRO)
#error "POLARSSL_PLATFORM_MALLOC_MACRO must be defined if POLARSSL_PLATFORM_FREE_MACRO is"
#endif

#if defined(POLARSSL_PLATFORM_MALLOC_MACRO) &&\
    ( !defined(POLARSSL_PLATFORM_C) || !defined(POLARSSL_PLATFORM_MEMORY) )
#error "POLARSSL_PLATFORM_MALLOC_MACRO defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_MALLOC_MACRO) &&\
    defined(POLARSSL_PLATFORM_STD_MALLOC)
#error "POLARSSL_PLATFORM_MALLOC_MACRO and POLARSSL_PLATFORM_STD_MALLOC cannot be defined simultaneously"
#endif

#if defined(POLARSSL_PLATFORM_MALLOC_MACRO) && !defined(POLARSSL_PLATFORM_FREE_MACRO)
#error "POLARSSL_PLATFORM_FREE_MACRO must be defined if POLARSSL_PLATFORM_MALLOC_MACRO is"
#endif

#if defined(POLARSSL_PLATFORM_MEMORY) && !defined(POLARSSL_PLATFORM_C)
#error "POLARSSL_PLATFORM_MEMORY defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_PRINTF_ALT) && !defined(POLARSSL_PLATFORM_C)
#error "POLARSSL_PLATFORM_PRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_PRINTF_MACRO) && !defined(POLARSSL_PLATFORM_C)
#error "POLARSSL_PLATFORM_PRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_PRINTF_MACRO) &&\
    ( defined(POLARSSL_PLATFORM_STD_PRINTF) ||\
        defined(POLARSSL_PLATFORM_PRINTF_ALT) )
#error "POLARSSL_PLATFORM_PRINTF_MACRO and POLARSSL_PLATFORM_STD_PRINTF/POLARSSL_PLATFORM_PRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(POLARSSL_PLATFORM_SNPRINTF_ALT) && !defined(POLARSSL_PLATFORM_C)
#error "POLARSSL_PLATFORM_SNPRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_SNPRINTF_ALT) && ( defined(_WIN32)\
    && !defined(EFIX64) && !defined(EFI32) )
#error "POLARSSL_PLATFORM_SNPRINTF_ALT defined but not available on Windows"
#endif

#if defined(POLARSSL_PLATFORM_SNPRINTF_MACRO) && !defined(POLARSSL_PLATFORM_C)
#error "POLARSSL_PLATFORM_SNPRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_SNPRINTF_MACRO) &&\
    ( defined(POLARSSL_PLATFORM_STD_SNPRINTF) ||\
        defined(POLARSSL_PLATFORM_SNPRINTF_ALT) )
#error "POLARSSL_PLATFORM_SNPRINTF_MACRO and POLARSSL_PLATFORM_STD_SNPRINTF/POLARSSL_PLATFORM_SNPRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(POLARSSL_PLATFORM_STD_MEM_HDR) &&\
    !defined(POLARSSL_PLATFORM_NO_STD_FUNCTIONS)
#error "POLARSSL_PLATFORM_STD_MEM_HDR defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_STD_MALLOC) && !defined(POLARSSL_PLATFORM_MEMORY)
#error "POLARSSL_PLATFORM_STD_MALLOC defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_STD_MALLOC) && !defined(POLARSSL_PLATFORM_MEMORY)
#error "POLARSSL_PLATFORM_STD_MALLOC defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_STD_FREE) && !defined(POLARSSL_PLATFORM_MEMORY)
#error "POLARSSL_PLATFORM_STD_FREE defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_STD_EXIT) &&\
    !defined(POLARSSL_PLATFORM_EXIT_ALT)
#error "POLARSSL_PLATFORM_STD_EXIT defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_STD_FPRINTF) &&\
    !defined(POLARSSL_PLATFORM_FPRINTF_ALT)
#error "POLARSSL_PLATFORM_STD_FPRINTF defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_STD_PRINTF) &&\
    !defined(POLARSSL_PLATFORM_PRINTF_ALT)
#error "POLARSSL_PLATFORM_STD_PRINTF defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PLATFORM_STD_SNPRINTF) &&\
    !defined(POLARSSL_PLATFORM_SNPRINTF_ALT)
#error "POLARSSL_PLATFORM_STD_SNPRINTF defined, but not all prerequisites"
#endif

#if defined(POLARSSL_RSA_C) && ( !defined(POLARSSL_BIGNUM_C) ||         \
    !defined(POLARSSL_OID_C) )
#error "POLARSSL_RSA_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_RSASSA_PSS_SUPPORT) &&                        \
    ( !defined(POLARSSL_RSA_C) || !defined(POLARSSL_PKCS1_V21) )
#error "POLARSSL_X509_RSASSA_PSS_SUPPORT defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_PROTO_SSL3) && ( !defined(POLARSSL_MD5_C) ||     \
    !defined(POLARSSL_SHA1_C) )
#error "POLARSSL_SSL_PROTO_SSL3 defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_PROTO_TLS1) && ( !defined(POLARSSL_MD5_C) ||     \
    !defined(POLARSSL_SHA1_C) )
#error "POLARSSL_SSL_PROTO_TLS1 defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_PROTO_TLS1_1) && ( !defined(POLARSSL_MD5_C) ||     \
    !defined(POLARSSL_SHA1_C) )
#error "POLARSSL_SSL_PROTO_TLS1_1 defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_PROTO_TLS1_2) && ( !defined(POLARSSL_SHA1_C) &&     \
    !defined(POLARSSL_SHA256_C) && !defined(POLARSSL_SHA512_C) )
#error "POLARSSL_SSL_PROTO_TLS1_2 defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_CLI_C) && !defined(POLARSSL_SSL_TLS_C)
#error "POLARSSL_SSL_CLI_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_TLS_C) && ( !defined(POLARSSL_CIPHER_C) ||     \
    !defined(POLARSSL_MD_C) )
#error "POLARSSL_SSL_TLS_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_SRV_C) && !defined(POLARSSL_SSL_TLS_C)
#error "POLARSSL_SSL_SRV_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_TLS_C) && (!defined(POLARSSL_SSL_PROTO_SSL3) && \
    !defined(POLARSSL_SSL_PROTO_TLS1) && !defined(POLARSSL_SSL_PROTO_TLS1_1) && \
    !defined(POLARSSL_SSL_PROTO_TLS1_2))
#error "POLARSSL_SSL_TLS_C defined, but no protocols are active"
#endif

#if defined(POLARSSL_SSL_TLS_C) && (defined(POLARSSL_SSL_PROTO_SSL3) && \
    defined(POLARSSL_SSL_PROTO_TLS1_1) && !defined(POLARSSL_SSL_PROTO_TLS1))
#error "Illegal protocol selection"
#endif

#if defined(POLARSSL_SSL_TLS_C) && (defined(POLARSSL_SSL_PROTO_TLS1) && \
    defined(POLARSSL_SSL_PROTO_TLS1_2) && !defined(POLARSSL_SSL_PROTO_TLS1_1))
#error "Illegal protocol selection"
#endif

#if defined(POLARSSL_SSL_TLS_C) && (defined(POLARSSL_SSL_PROTO_SSL3) && \
    defined(POLARSSL_SSL_PROTO_TLS1_2) && (!defined(POLARSSL_SSL_PROTO_TLS1) || \
    !defined(POLARSSL_SSL_PROTO_TLS1_1)))
#error "Illegal protocol selection"
#endif

#if defined(POLARSSL_SSL_ENCRYPT_THEN_MAC) &&   \
    !defined(POLARSSL_SSL_PROTO_TLS1)   &&      \
    !defined(POLARSSL_SSL_PROTO_TLS1_1) &&      \
    !defined(POLARSSL_SSL_PROTO_TLS1_2)
#error "POLARSSL_SSL_ENCRYPT_THEN_MAC defined, but not all prerequsites"
#endif

#if defined(POLARSSL_SSL_EXTENDED_MASTER_SECRET) && \
    !defined(POLARSSL_SSL_PROTO_TLS1)   &&          \
    !defined(POLARSSL_SSL_PROTO_TLS1_1) &&          \
    !defined(POLARSSL_SSL_PROTO_TLS1_2)
#error "POLARSSL_SSL_EXTENDED_MASTER_SECRET defined, but not all prerequsites"
#endif

#if defined(POLARSSL_SSL_SESSION_TICKETS) && defined(POLARSSL_SSL_TLS_C) && \
    ( !defined(POLARSSL_AES_C) || !defined(POLARSSL_SHA256_C) ||            \
      !defined(POLARSSL_CIPHER_MODE_CBC) )
#error "POLARSSL_SSL_SESSION_TICKETS_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_CBC_RECORD_SPLITTING) && \
    !defined(POLARSSL_SSL_PROTO_SSL3) && !defined(POLARSSL_SSL_PROTO_TLS1)
#error "POLARSSL_SSL_CBC_RECORD_SPLITTING defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_SERVER_NAME_INDICATION) && \
        !defined(POLARSSL_X509_CRT_PARSE_C)
#error "POLARSSL_SSL_SERVER_NAME_INDICATION defined, but not all prerequisites"
#endif

#if defined(POLARSSL_THREADING_PTHREAD)
#if !defined(POLARSSL_THREADING_C) || defined(POLARSSL_THREADING_IMPL)
#error "POLARSSL_THREADING_PTHREAD defined, but not all prerequisites"
#endif
#define POLARSSL_THREADING_IMPL
#endif

#if defined(POLARSSL_THREADING_ALT)
#if !defined(POLARSSL_THREADING_C) || defined(POLARSSL_THREADING_IMPL)
#error "POLARSSL_THREADING_ALT defined, but not all prerequisites"
#endif
#define POLARSSL_THREADING_IMPL
#endif

#if defined(POLARSSL_THREADING_C) && !defined(POLARSSL_THREADING_IMPL)
#error "POLARSSL_THREADING_C defined, single threading implementation required"
#endif
#undef POLARSSL_THREADING_IMPL

#if defined(POLARSSL_VERSION_FEATURES) && !defined(POLARSSL_VERSION_C)
#error "POLARSSL_VERSION_FEATURES defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_USE_C) && ( !defined(POLARSSL_BIGNUM_C) ||  \
    !defined(POLARSSL_OID_C) || !defined(POLARSSL_ASN1_PARSE_C) ||      \
    !defined(POLARSSL_PK_PARSE_C) )
#error "POLARSSL_X509_USE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CREATE_C) && ( !defined(POLARSSL_BIGNUM_C) ||  \
    !defined(POLARSSL_OID_C) || !defined(POLARSSL_ASN1_WRITE_C) ||       \
    !defined(POLARSSL_PK_WRITE_C) )
#error "POLARSSL_X509_CREATE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CRT_PARSE_C) && ( !defined(POLARSSL_X509_USE_C) )
#error "POLARSSL_X509_CRT_PARSE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CRL_PARSE_C) && ( !defined(POLARSSL_X509_USE_C) )
#error "POLARSSL_X509_CRL_PARSE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CSR_PARSE_C) && ( !defined(POLARSSL_X509_USE_C) )
#error "POLARSSL_X509_CSR_PARSE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CRT_WRITE_C) && ( !defined(POLARSSL_X509_CREATE_C) )
#error "POLARSSL_X509_CRT_WRITE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CSR_WRITE_C) && ( !defined(POLARSSL_X509_CREATE_C) )
#error "POLARSSL_X509_CSR_WRITE_C defined, but not all prerequisites"
#endif

#endif /* POLARSSL_CHECK_CONFIG_H */
