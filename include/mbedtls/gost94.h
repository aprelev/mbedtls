/**
 * \file gost94.h
 *
 * \brief GOST R 34.11-94 cryptographic hash function
 */

#ifndef MBEDTLS_GOST94_H
#define MBEDTLS_GOST94_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#if !defined(MBEDTLS_GOST94_ALT) && defined(MBEDTLS_GOST89_C)
// Regular implementation
//

#include "gost89.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          GOST94 context structure
 */
typedef struct
{
    mbedtls_gost89_sbox_id_t sbox_id; /*!< S-Box identifier           */
    uint32_t total[2];                /*!< number of bytes processed  */
    unsigned char h[32];              /*!< intermediate digest state  */
    unsigned char sum[32];            /*!< intermediate digest state  */
    unsigned char buffer[32];         /*!< data block being processed */
}
mbedtls_gost94_context;

/**
 * \brief          Initialize GOST94 context
 *
 * \param ctx      GOST94 context to be initialized
 * \param sbox_id  S-Box identifier
 */
void mbedtls_gost94_init( mbedtls_gost94_context *ctx,
                          mbedtls_gost89_sbox_id_t sbox_id );

/**
 * \brief          Clear GOST94 context
 *
 * \param ctx      GOST94 context to be cleared
 */
void mbedtls_gost94_free( mbedtls_gost94_context *ctx );

/**
 * \brief          Clone (the state of) a GOST94 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void mbedtls_gost94_clone( mbedtls_gost94_context *dst,
                           const mbedtls_gost94_context *src );

/**
 * \brief          GOST94 context setup
 *
 * \param ctx      context to be initialized
 * \param iv       hash initial value
 */
void mbedtls_gost94_starts( mbedtls_gost94_context *ctx );

/**
 * \brief          GOST94 process buffer
 *
 * \param ctx      GOST94 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void mbedtls_gost94_update( mbedtls_gost94_context *ctx, const unsigned char *input,
                            size_t ilen );

/**
 * \brief          GOST94 final digest
 *
 * \param ctx      GOST94 context
 * \param output   GOST94 checksum result
 */
void mbedtls_gost94_finish( mbedtls_gost94_context *ctx, unsigned char output[32] );

/* Internal use */
void mbedtls_gost94_process( mbedtls_gost94_context *ctx, const unsigned char data[32] );

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_GOST94_ALT */
#include "gost94_alt.h"
#endif /* MBEDTLS_GOST94_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Output = GOST94( input buffer )
 *
 * \param sbox_id  S-Box identifier
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   GOST94 checksum result
 */
void mbedtls_gost94( mbedtls_gost89_sbox_id_t sbox_id,
                     const unsigned char *input, size_t ilen,
                     unsigned char output[32] );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_gost94_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_gost94.h */
