/**
 * \file gost12.h
 *
 * \brief GOST R 34.11-2012 (256 and 512 bit) cryptographic hash function
 */

#ifndef MBEDTLS_GOST12_H
#define MBEDTLS_GOST12_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#if !defined(MBEDTLS_GOST12_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          GOST12 context structure
 */
typedef struct
{
    uint64_t total[2];        /*!< number of bytes processed  */
    uint64_t N;               /*!< intermediate digest state  */
    unsigned char h[64];      /*!< intermediate digest state  */
    unsigned char sum[64];    /*!< intermediate digest state  */
    unsigned char buffer[64]; /*!< data block being processed */
    int is256;                /*!< 0 => GOST12-512, else GOST12-256 */
}
mbedtls_gost12_context;

/**
 * \brief          Initialize GOST12 context
 *
 * \param ctx      GOST12 context to be initialized
 */
void mbedtls_gost12_init( mbedtls_gost12_context *ctx );

/**
 * \brief          Clear GOST12 context
 *
 * \param ctx      GOST12 context to be cleared
 */
void mbedtls_gost12_free( mbedtls_gost12_context *ctx );

/**
 * \brief          Clone (the state of) a GOST12 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void mbedtls_gost12_clone( mbedtls_gost12_context *dst,
                           const mbedtls_gost12_context *src );

/**
 * \brief          GOST12 context setup
 *
 * \param ctx      context to be initialized
 * \param is224    0 = use GOST12-512, 1 = use GOST12-256
 */
void mbedtls_gost12_starts( mbedtls_gost12_context *ctx, int is256 );

/**
 * \brief          GOST12 process buffer
 *
 * \param ctx      GOST12 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void mbedtls_gost12_update( mbedtls_gost12_context *ctx, const unsigned char *input,
                    size_t ilen );

/**
 * \brief          GOST12 final digest
 *
 * \param ctx      GOST12 context
 * \param output   GOST12-256/512 checksum result
 */
void mbedtls_gost12_finish( mbedtls_gost12_context *ctx, unsigned char output[64] );

/* Internal use */
void mbedtls_gost12_process( mbedtls_gost12_context *ctx, const unsigned char data[64] );


#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_GOST12_ALT */
#include "gost12_alt.h"
#endif /* MBEDTLS_GOST12_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Output = GOST12( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   GOST12-256/512 checksum result
 * \param is256    0 = use GOST12-512, 1 = use GOST12-256
 */
void mbedtls_gost12( const unsigned char *input, size_t ilen,
           unsigned char output[64], int is256 );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_gost12_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* gost12.h */
