/*
 *  GOST 28147-89 implementation
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_GOST89_C)

#include <string.h>

#include "mbedtls/gost89.h"

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#if !defined(MBEDTLS_GOST89_ALT)

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/*
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ]       )             \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 2] << 16 )             \
        | ( (uint32_t) (b)[(i) + 3] << 24 );            \
}
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n,b,i)                                    \
{                                                               \
    (b)[(i)    ] = (unsigned char) ( ( (n)       ) & 0xFF );    \
    (b)[(i) + 1] = (unsigned char) ( ( (n) >>  8 ) & 0xFF );    \
    (b)[(i) + 2] = (unsigned char) ( ( (n) >> 16 ) & 0xFF );    \
    (b)[(i) + 3] = (unsigned char) ( ( (n) >> 24 ) & 0xFF );    \
}
#endif

/*
 * GOST 28147-89 S-Box
 */
typedef struct
{
    unsigned char data[8][16];
} mbedtls_gost89_sbox_t;

/*
 * Test S-Box (id-Gost28147-89-TestParamSet, 1.2.643.2.2.31.0)
 */
static const mbedtls_gost89_sbox_t TestSb =
{
    {
        {  4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3 },
        { 14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9 },
        {  5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11 },
        {  7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3 },
        {  6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2 },
        {  4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14 },
        { 13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12 },
        {  1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12 }
    }
};

/*
 * S-Box A (id-Gost28147-89-CryptoPro-A-ParamSet, 1.2.643.2.2.31.1)
 */
static const mbedtls_gost89_sbox_t SbA =
{
    {
        { 10,  4,  5,  6,  8,  1,  3,  7, 13, 12, 14,  0,  9,  2, 11, 15 },
        {  5, 15,  4,  0,  2, 13, 11,  9,  1,  7,  6,  3, 12, 14, 10,  8 },
        {  7, 15, 12, 14,  9,  4,  1,  0,  3, 11,  5,  2,  6, 10,  8, 13 },
        {  4, 10,  7, 12,  0, 15,  2,  8, 14,  1,  6,  5, 13, 11,  9,  3 },
        {  7,  6,  4, 11,  9, 12,  2, 10,  1,  8,  0, 14, 15, 13,  3,  5 },
        {  7,  6,  2,  4, 13,  9, 15,  0, 10,  1,  5, 11,  8, 14, 12,  3 },
        { 13, 14,  4,  1,  7,  0,  5, 10,  3, 12,  8, 15,  6,  2,  9, 11 },
        {  1,  3, 10,  9,  5, 11,  4, 15,  8,  6,  7, 14, 13,  0,  2, 12 }
    }
};

/*
 * S-Box Z (id-tc26-gost-28147-param-Z, 1.2.643.7.1.2.5.1.1)
*/
static const mbedtls_gost89_sbox_t SbZ =
{
    {
        { 12,  4,  6,  2, 10,  5, 11,  9, 14,  8, 13,  7,  0,  3, 15,  1 },
        {  6,  8,  2,  3,  9, 10,  5, 12,  1, 14,  4,  7, 11, 13,  0, 15 },
        { 11,  3,  5,  8,  2, 15, 10, 13, 14,  1,  7,  4, 12,  9,  6,  0 },
        { 12,  8,  2,  1, 13,  4, 15,  6,  7,  0, 10,  5,  3, 14,  9, 11 },
        {  7, 15,  5, 10,  8,  1,  6, 13,  0,  9,  3, 14, 11,  4,  2, 12 },
        {  5, 13, 15,  6,  9,  2, 12, 10, 11,  7,  8,  1,  4,  3, 14,  0 },
        {  8, 14,  2,  5,  6,  9,  1, 12, 15,  4, 11,  0, 13, 10,  3,  7 },
        {  1,  7, 14, 13,  0,  5,  8,  3,  4, 15, 10,  6,  9, 12, 11,  2 }
    }
};

/*
 * CryptoPro Key Meshing algorithm constant from RFC 4357:
 *
 * https://tools.ietf.org/html/rfc4357
 */
static const unsigned char MeshC[32] =
{
    0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23,
    0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4,
    0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12,
    0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B
};

#define GOST89_ROUND(N1,N2,S,RK,Sb)                                 \
    S = ( N1 + *RK ) & 0xFFFFFFFF;                                  \
    S = ( (uint32_t) Sb->data[ 0 ][ ( S       ) & 0x0F ]       )    \
      | ( (uint32_t) Sb->data[ 1 ][ ( S >>  4 ) & 0x0F ] <<  4 )    \
      | ( (uint32_t) Sb->data[ 2 ][ ( S >>  8 ) & 0x0F ] <<  8 )    \
      | ( (uint32_t) Sb->data[ 3 ][ ( S >> 12 ) & 0x0F ] << 12 )    \
      | ( (uint32_t) Sb->data[ 4 ][ ( S >> 16 ) & 0x0F ] << 16 )    \
      | ( (uint32_t) Sb->data[ 5 ][ ( S >> 20 ) & 0x0F ] << 20 )    \
      | ( (uint32_t) Sb->data[ 6 ][ ( S >> 24 ) & 0x0F ] << 24 )    \
      | ( (uint32_t) Sb->data[ 7 ][ ( S >> 28 ) & 0x0F ] << 28 );   \
    S = ( ( S << 11 ) & 0xFFFFFFFF ) | ( S >> 21 );                 \
    S ^= N2;                                                        \
    N2 = N1;                                                        \
    N1 = S;                                                         \

void mbedtls_gost89_init( mbedtls_gost89_context *ctx,
                          mbedtls_gost89_sbox_id_t sbox_id )
{
    memset( ctx, 0, sizeof( mbedtls_gost89_context ) );
    ctx->sbox_id = sbox_id;
}

void mbedtls_gost89_free( mbedtls_gost89_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_zeroize( ctx, sizeof( mbedtls_gost89_context ) );
}

int mbedtls_gost89_setkey( mbedtls_gost89_context *ctx,
                           const unsigned char key[MBEDTLS_GOST89_KEY_SIZE] )
{
    int i;

    for( i = 0; i < 8; i++ )
    {
        GET_UINT32_LE( ctx->rk[i], key, i << 2 );
    }

    return( 0 );
}

static const mbedtls_gost89_sbox_t *mbedtls_gost89_sbox_from_id( mbedtls_gost89_sbox_id_t sbox_id )
{
    switch( sbox_id )
    {
        case MBEDTLS_GOST89_SBOX_TEST:
            return &TestSb;
        case MBEDTLS_GOST89_SBOX_A:
            return &SbA;
        case MBEDTLS_GOST89_SBOX_Z:
            return &SbZ;
        default:
            return &SbA;
    }
}

/*
 * Copy round keys from one GOST89 context to another
 */
static const void mbedtls_gost89_key_copy( mbedtls_gost89_context *dst,
                                           mbedtls_gost89_context *src )
{
    int i;

    for( i = 0; i < 8; i++ )
    {
        dst->rk[i] = src->rk[i];
    }
}

/*
 * CryptoPro Key Meshing algorithm from RFC 4357:
 *
 * https://tools.ietf.org/html/rfc4357
 */
static const void mbedtls_gost89_key_meshing( mbedtls_gost89_context *ctx,
                                              unsigned char *iv )
{
    int i;
    unsigned char output[MBEDTLS_GOST89_BLOCKSIZE];
    mbedtls_gost89_context mesh;
    mbedtls_gost89_init( &mesh, ctx->sbox_id );

    /*
     * Key Meshing
     */
    mbedtls_gost89_key_copy( &mesh, ctx );
    for( i = 0; i < 4; i++ )
    {
        mbedtls_gost89_crypt_ecb( &mesh, MBEDTLS_GOST89_DECRYPT, &MeshC[i * MBEDTLS_GOST89_BLOCKSIZE], output );
        GET_UINT32_LE( ctx->rk[ i << 1 ], output, 0 );
        GET_UINT32_LE( ctx->rk[ ( i << 1 ) + 1 ], output, 4 );
    }

    /*
     * IV Meshing
     */
    if( iv != NULL )
    {
        mbedtls_gost89_key_copy( &mesh, ctx );
        mbedtls_gost89_crypt_ecb( &mesh, MBEDTLS_GOST89_ENCRYPT, iv, iv );
    }

    mbedtls_gost89_free( &mesh );
}

/*
 * GOST89-ECB block encryption
 */
#if !defined(MBEDTLS_GOST89_ENCRYPT_ALT)
void mbedtls_gost89_encrypt( mbedtls_gost89_context *ctx,
                             const unsigned char input[MBEDTLS_GOST89_BLOCKSIZE],
                             unsigned char output[MBEDTLS_GOST89_BLOCKSIZE] )
{
    int i, j;
    uint32_t N1, N2, S, *RK;
    const mbedtls_gost89_sbox_t *Sb = mbedtls_gost89_sbox_from_id( ctx->sbox_id );

    GET_UINT32_LE( N1, input, 0 );
    GET_UINT32_LE( N2, input, 4 );

    for( i = 0; i < 3; i++ )
    {
        RK = ctx->rk;
        for( j = 0; j < 8; j++ )
        {
            GOST89_ROUND( N1, N2, S, RK, Sb ); RK++;
        }
    }

    RK = &ctx->rk[7];
    for( j = 0; j < 8; j++ )
    {
        GOST89_ROUND( N1, N2, S, RK, Sb ); RK--;
    }

    PUT_UINT32_LE( N2, output, 0 );
    PUT_UINT32_LE( N1, output, 4 );
}
#endif /* !MBEDTLS_GOST89_ENCRYPT_ALT */

/*
 * GOST89-ECB block decryption
 */
#if !defined(MBEDTLS_GOST89_DECRYPT_ALT)
void mbedtls_gost89_decrypt( mbedtls_gost89_context *ctx,
                             const unsigned char input[MBEDTLS_GOST89_BLOCKSIZE],
                             unsigned char output[MBEDTLS_GOST89_BLOCKSIZE] )
{
    int i, j;
    uint32_t N1, N2, S, *RK;
    const mbedtls_gost89_sbox_t *Sb = mbedtls_gost89_sbox_from_id( ctx->sbox_id );

    GET_UINT32_LE( N1, input, 0 );
    GET_UINT32_LE( N2, input, 4 );

    RK = ctx->rk;
    for( j = 0; j < 8; j++ )
    {
        GOST89_ROUND( N1, N2, S, RK, Sb ); RK++;
    }

    for( i = 0; i < 3; i++ )
    {
        RK = &ctx->rk[7];
        for( j = 0; j < 8; j++ )
        {
            GOST89_ROUND( N1, N2, S, RK, Sb ); RK--;
        }
    }

    PUT_UINT32_LE( N2, output, 0 );
    PUT_UINT32_LE( N1, output, 4 );
}
#endif /* !MBEDTLS_GOST89_DECRYPT_ALT */

/*
 * GOST89-ECB block encryption/decryption
 */
int mbedtls_gost89_crypt_ecb( mbedtls_gost89_context *ctx,
                              int mode,
                              const unsigned char input[MBEDTLS_GOST89_BLOCKSIZE],
                              unsigned char output[MBEDTLS_GOST89_BLOCKSIZE] )
{
    if( ctx->processed_len == 1024 )
    {
        mbedtls_gost89_key_meshing( ctx, NULL );
    }

    if( mode == MBEDTLS_GOST89_ENCRYPT )
        mbedtls_gost89_encrypt( ctx, input, output );
    else
        mbedtls_gost89_decrypt( ctx, input, output );

    ctx->processed_len += MBEDTLS_GOST89_BLOCKSIZE;

    return( 0 );
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/*
 * GOST89-CBC buffer encryption/decryption
 */
int mbedtls_gost89_crypt_cbc( mbedtls_gost89_context *ctx,
                              int mode,
                              size_t length,
                              unsigned char iv[MBEDTLS_GOST89_BLOCKSIZE],
                              const unsigned char *input,
                              unsigned char *output )
{
    int i;
    unsigned char temp[MBEDTLS_GOST89_BLOCKSIZE];

    if( length % MBEDTLS_GOST89_BLOCKSIZE )
        return( MBEDTLS_ERR_GOST89_INVALID_INPUT_LENGTH );

    if( mode == MBEDTLS_GOST89_DECRYPT )
    {
        while( length > 0 )
        {
            if( ctx->processed_len == 1024 )
            {
                mbedtls_gost89_key_meshing( ctx, iv );
            }

            memcpy( temp, input, MBEDTLS_GOST89_BLOCKSIZE );
            mbedtls_gost89_crypt_ecb( ctx, mode, input, output );

            for( i = 0; i < MBEDTLS_GOST89_BLOCKSIZE; i++ )
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, MBEDTLS_GOST89_BLOCKSIZE );

            input  += MBEDTLS_GOST89_BLOCKSIZE;
            output += MBEDTLS_GOST89_BLOCKSIZE;
            length -= MBEDTLS_GOST89_BLOCKSIZE;

            ctx->processed_len += MBEDTLS_GOST89_BLOCKSIZE;
        }
    }
    else
    {
        while( length > 0 )
        {
            if( ctx->processed_len == 1024 )
            {
                mbedtls_gost89_key_meshing( ctx, iv );
            }

            for( i = 0; i < MBEDTLS_GOST89_BLOCKSIZE; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

            mbedtls_gost89_crypt_ecb( ctx, mode, output, output );
            memcpy( iv, output, MBEDTLS_GOST89_BLOCKSIZE );

            input  += MBEDTLS_GOST89_BLOCKSIZE;
            output += MBEDTLS_GOST89_BLOCKSIZE;
            length -= MBEDTLS_GOST89_BLOCKSIZE;

            ctx->processed_len += MBEDTLS_GOST89_BLOCKSIZE;
        }
    }

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#endif /* !MBEDTLS_GOST89_ALT */

#if defined(MBEDTLS_SELF_TEST)
/*
 * GOST 28147-89 test vector from:
 *
 * http://tc26.ru/standard/gost/GOST_R_3412-2015.pdf
 */
static const unsigned char gost89_test3412_key[MBEDTLS_GOST89_KEY_SIZE] =
{
    0xcc, 0xdd, 0xee, 0xff, 0x88, 0x99, 0xaa, 0xbb,
    0x44, 0x55, 0x66, 0x77, 0x00, 0x11, 0x22, 0x33,
    0xf3, 0xf2, 0xf1, 0xf0, 0xf7, 0xf6, 0xf5, 0xf4,
    0xfb, 0xfa, 0xf9, 0xf8, 0xff, 0xfe, 0xfd, 0xfc
};

static const unsigned char gost89_test3412_pt[MBEDTLS_GOST89_BLOCKSIZE] =
{
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe
};

static const unsigned char gost89_test3412_ecb_ct[MBEDTLS_GOST89_BLOCKSIZE] =
{
    0x3d, 0xca, 0xd8, 0xc2, 0xe5, 0x01, 0xe9, 0x4e,
};

/*
 * GOST 28147-89 test vector from:
 *
 * http://tc26.ru/standard/gost/GOST_R_3413-2015.pdf
 */
static const unsigned char gost89_test3413_key[MBEDTLS_GOST89_KEY_SIZE] =
{
    0xcc, 0xdd, 0xee, 0xff, 0x88, 0x99, 0xaa, 0xbb,
    0x44, 0x55, 0x66, 0x77, 0x00, 0x11, 0x22, 0x33,
    0xf3, 0xf2, 0xf1, 0xf0, 0xf7, 0xf6, 0xf5, 0xf4,
    0xfb, 0xfa, 0xf9, 0xf8, 0xff, 0xfe, 0xfd, 0xfc
};

static const unsigned char gost89_test3413_pt[4 * MBEDTLS_GOST89_BLOCKSIZE] =
{
    0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92,
    0x20, 0x9d, 0x18, 0xf8, 0x04, 0xc7, 0x54, 0xdb,
    0x4c, 0x02, 0xa8, 0x67, 0x2e, 0xfb, 0x98, 0x4a,
    0x41, 0x7e, 0xb5, 0x17, 0x9b, 0x40, 0x12, 0x89
};

static const unsigned char gost89_test3413_ecb_ct[4 * MBEDTLS_GOST89_BLOCKSIZE] =
{
    0xa0, 0x72, 0xf3, 0x94, 0x04, 0x3f, 0x07, 0x2b,
    0x48, 0x6e, 0x55, 0xd3, 0x15, 0xe7, 0x70, 0xde,
    0x1e, 0xbc, 0xcf, 0xea, 0xe9, 0xd9, 0xd8, 0x11,
    0xfb, 0x7e, 0xc6, 0x96, 0x09, 0x26, 0x68, 0x7c
};

/*
 * GOST 28147-89 test vector from:
 *
 * http://tc26.ru/methods/recommendation/%D0%A2%D0%9A26%D0%A3%D0%97.pdf
 */
static const unsigned char gost89_testz_key[MBEDTLS_GOST89_KEY_SIZE] =
{
    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
    0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x80,
    0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
    0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xd0
};

static const unsigned char gost89_testz_pt[2 * MBEDTLS_GOST89_BLOCKSIZE] =
{
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8
};

static const unsigned char gost89_testz_ecb_ct[2 * MBEDTLS_GOST89_BLOCKSIZE] =
{
    0xce, 0x5a, 0x5e, 0xd7, 0xe0, 0x57, 0x7a, 0x5f,
    0xd0, 0xcc, 0x85, 0xce, 0x31, 0x63, 0x5b, 0x8b
};

/*
 * Checkup routine
 */
int mbedtls_gost89_self_test( int verbose )
{
    int ret = 0, i;
    unsigned char buf[4 * MBEDTLS_GOST89_BLOCKSIZE];
    mbedtls_gost89_context ctx;

    /*
     * ECB mode
     */
    if( verbose != 0 )
        mbedtls_printf( "  GOST89-Z-ECB 34.12 (enc): ");
    mbedtls_gost89_init( &ctx, MBEDTLS_GOST89_SBOX_Z );
    mbedtls_gost89_setkey( &ctx, gost89_test3412_key );
    memset( buf, 0, sizeof( buf ) );
    mbedtls_gost89_crypt_ecb( &ctx, MBEDTLS_GOST89_ENCRYPT, gost89_test3412_pt, buf );
    if( memcmp( gost89_test3412_ecb_ct, buf, MBEDTLS_GOST89_BLOCKSIZE ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto exit;
    }
    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    if( verbose != 0 )
        mbedtls_printf( "  GOST89-Z-ECB 34.12 (dec): ");
    mbedtls_gost89_init( &ctx, MBEDTLS_GOST89_SBOX_Z );
    mbedtls_gost89_setkey( &ctx, gost89_test3412_key );
    memset( buf, 0, sizeof( buf ) );
    mbedtls_gost89_crypt_ecb( &ctx, MBEDTLS_GOST89_DECRYPT, gost89_test3412_ecb_ct, buf );
    if( memcmp( gost89_test3412_pt, buf, MBEDTLS_GOST89_BLOCKSIZE ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto exit;
    }
    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    if( verbose != 0 )
        mbedtls_printf( "  GOST89-Z-ECB 34.13 (enc): ");
    mbedtls_gost89_init( &ctx, MBEDTLS_GOST89_SBOX_Z );
    mbedtls_gost89_setkey( &ctx, gost89_test3413_key );
    for( i = 0; i < 4; i++ )
    {
        memset( buf, 0, sizeof( buf ) );
        mbedtls_gost89_crypt_ecb( &ctx, MBEDTLS_GOST89_ENCRYPT, &gost89_test3413_pt[i * MBEDTLS_GOST89_BLOCKSIZE], buf );

        if( memcmp( &gost89_test3413_ecb_ct[i * MBEDTLS_GOST89_BLOCKSIZE], buf, MBEDTLS_GOST89_BLOCKSIZE ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            ret = 1;
            goto exit;
        }
    }
    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    if( verbose != 0 )
        mbedtls_printf( "  GOST89-Z-ECB 34.13 (dec): ");
    mbedtls_gost89_init( &ctx, MBEDTLS_GOST89_SBOX_Z );
    mbedtls_gost89_setkey( &ctx, gost89_test3413_key );
    for( i = 0; i < 4; i++ )
    {
        memset( buf, 0, sizeof( buf ) );
        mbedtls_gost89_crypt_ecb( &ctx, MBEDTLS_GOST89_DECRYPT, &gost89_test3413_ecb_ct[i * MBEDTLS_GOST89_BLOCKSIZE], buf );

        if( memcmp( &gost89_test3413_pt[i * MBEDTLS_GOST89_BLOCKSIZE], buf, MBEDTLS_GOST89_BLOCKSIZE ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            ret = 1;
            goto exit;
        }
    }
    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    if( verbose != 0 )
        mbedtls_printf( "  GOST89-Z-ECB Z (enc): ");
    mbedtls_gost89_init( &ctx, MBEDTLS_GOST89_SBOX_Z );
    mbedtls_gost89_setkey( &ctx, gost89_testz_key );
    for( i = 0; i < 2; i++ )
    {
        memset( buf, 0, sizeof( buf ) );
        mbedtls_gost89_crypt_ecb( &ctx, MBEDTLS_GOST89_ENCRYPT, &gost89_testz_pt[i * MBEDTLS_GOST89_BLOCKSIZE], buf );

        if( memcmp( &gost89_testz_ecb_ct[i * MBEDTLS_GOST89_BLOCKSIZE], buf, MBEDTLS_GOST89_BLOCKSIZE ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            ret = 1;
            goto exit;
        }
    }
    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    if( verbose != 0 )
        mbedtls_printf( "  GOST89-Z-ECB Z (dec): ");
    mbedtls_gost89_init( &ctx, MBEDTLS_GOST89_SBOX_Z );
    mbedtls_gost89_setkey( &ctx, gost89_testz_key );
    for( i = 0; i < 2; i++ )
    {
        memset( buf, 0, sizeof( buf ) );
        mbedtls_gost89_crypt_ecb( &ctx, MBEDTLS_GOST89_DECRYPT, &gost89_testz_ecb_ct[i * MBEDTLS_GOST89_BLOCKSIZE], buf );

        if( memcmp( &gost89_testz_pt[i * MBEDTLS_GOST89_BLOCKSIZE], buf, MBEDTLS_GOST89_BLOCKSIZE ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            ret = 1;
            goto exit;
        }
    }
    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    if( verbose != 0 )
        mbedtls_printf( "\n" );

exit:
    mbedtls_gost89_free( &ctx );

    return( ret );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_GOST89_C */
