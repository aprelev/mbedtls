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
        { 0x4, 0x2, 0xF, 0x5, 0x9, 0x1, 0x0, 0x8, 0xE, 0x3, 0xB, 0xC, 0xD, 0x7, 0xA, 0x6 },
        { 0xC, 0x9, 0xF, 0xE, 0x8, 0x1, 0x3, 0xA, 0x2, 0x7, 0x4, 0xD, 0x6, 0x0, 0xB, 0x5 },
        { 0xD, 0x8, 0xE, 0xC, 0x7, 0x3, 0x9, 0xA, 0x1, 0x5, 0x2, 0x4, 0x6, 0xF, 0x0, 0xB },
        { 0xE, 0x9, 0xB, 0x2, 0x5, 0xF, 0x7, 0x1, 0x0, 0xD, 0xC, 0x6, 0xA, 0x4, 0x3, 0x8 },
        { 0x3, 0xE, 0x5, 0x9, 0x6, 0x8, 0x0, 0xD, 0xA, 0xB, 0x7, 0xC, 0x2, 0x1, 0xF, 0x4 },
        { 0x8, 0xF, 0x6, 0xB, 0x1, 0x9, 0xC, 0x5, 0xD, 0x3, 0x7, 0xA, 0x0, 0xE, 0x2, 0x4 },
        { 0x9, 0xB, 0xC, 0x0, 0x3, 0x6, 0x7, 0x5, 0x4, 0x8, 0xE, 0xF, 0x1, 0xA, 0x2, 0xD },
        { 0xC, 0x6, 0x5, 0x2, 0xB, 0x0, 0x9, 0xD, 0x3, 0xE, 0x7, 0xA, 0xF, 0x4, 0x1, 0x8 }
    }
};

/*
 * S-Box A (id-Gost28147-89-CryptoPro-A-ParamSet, 1.2.643.2.2.31.1)
 */
static const mbedtls_gost89_sbox_t SbA =
{
    {
        { 0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0, 0xD, 0x5 },
        { 0x3, 0x7, 0xE, 0x9, 0x8, 0xA, 0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4, 0xD, 0x1 },
        { 0xE, 0x4, 0x6, 0x2, 0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA, 0x0, 0x7, 0x1, 0x9 },
        { 0xE, 0x7, 0xA, 0xC, 0xD, 0x1, 0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8, 0x5, 0x6 },
        { 0xB, 0x5, 0x1, 0x9, 0x8, 0xD, 0xF, 0x0, 0xE, 0x4, 0x2, 0x3, 0xC, 0x7, 0xA, 0x6 },
        { 0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB, 0x7, 0x5, 0x9, 0x4, 0x8, 0xF, 0xE, 0x6 },
        { 0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5, 0xF, 0x3, 0xB, 0xE },
        { 0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7, 0xD, 0x4 }
    }
};

/*
 * S-Box Z (id-tc26-gost-28147-param-Z, 1.2.643.7.1.2.5.1.1)
*/
static const mbedtls_gost89_sbox_t SbZ =
{
    {
        { 0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1 },
        { 0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF },
        { 0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0 },
        { 0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB },
        { 0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC },
        { 0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0 },
        { 0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7 },
        { 0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2 }
    }
};

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
 * CryptoPro Key Meshing algorithm from RFC 4357:
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

static void mbedtls_gost89_key_meshing( mbedtls_gost89_context *ctx,
                                        unsigned char *iv )
{
    int i;
    unsigned char output[MBEDTLS_GOST89_BLOCKSIZE];
    mbedtls_gost89_context mesh;
    mbedtls_gost89_init( &mesh, ctx->sbox_id );

    /*
     * Key Meshing
     */
    for( i = 0; i < 8; i++ )
    {
        mesh.rk[i] = ctx->rk[i];
    }
    for( i = 0; i < 4; i++ )
    {
        mbedtls_gost89_crypt_ecb( &mesh, MBEDTLS_GOST89_DECRYPT,
                                  &MeshC[i * MBEDTLS_GOST89_BLOCKSIZE], output );
        GET_UINT32_LE( ctx->rk[ i << 1 ], output, 0 );
        GET_UINT32_LE( ctx->rk[ ( i << 1 ) + 1 ], output, 4 );
    }

    /*
     * IV Meshing
     */
    if( iv != NULL )
    {
        for( i = 0; i < 8; i++ )
        {
            mesh.rk[i] = ctx->rk[i];
        }
        mbedtls_gost89_crypt_ecb( &mesh, MBEDTLS_GOST89_ENCRYPT, iv, iv );
    }

    mbedtls_gost89_free( &mesh );
}

static inline int mbedtls_gost89_is_meshing_needed( const mbedtls_gost89_context *ctx )
{
    return ( ctx->processed_len == 1024 );
}

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
    if( mbedtls_gost89_is_meshing_needed( ctx ) )
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
            if( mbedtls_gost89_is_meshing_needed( ctx ) )
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
            if( mbedtls_gost89_is_meshing_needed( ctx ) )
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
    mbedtls_gost89_crypt_ecb( &ctx, MBEDTLS_GOST89_ENCRYPT, gost89_test3412_pt,
                              buf );
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
    mbedtls_gost89_crypt_ecb( &ctx, MBEDTLS_GOST89_DECRYPT, gost89_test3412_ecb_ct,
                              buf );
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
        mbedtls_gost89_crypt_ecb( &ctx, MBEDTLS_GOST89_ENCRYPT,
                                  &gost89_test3413_pt[i * MBEDTLS_GOST89_BLOCKSIZE],
                                  buf );

        if( memcmp( &gost89_test3413_ecb_ct[i * MBEDTLS_GOST89_BLOCKSIZE],
                    buf, MBEDTLS_GOST89_BLOCKSIZE ) != 0 )
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
        mbedtls_gost89_crypt_ecb( &ctx, MBEDTLS_GOST89_DECRYPT,
                                  &gost89_test3413_ecb_ct[i * MBEDTLS_GOST89_BLOCKSIZE],
                                  buf );

        if( memcmp( &gost89_test3413_pt[i * MBEDTLS_GOST89_BLOCKSIZE],
                    buf, MBEDTLS_GOST89_BLOCKSIZE ) != 0 )
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
        mbedtls_gost89_crypt_ecb( &ctx, MBEDTLS_GOST89_ENCRYPT,
                                  &gost89_testz_pt[i * MBEDTLS_GOST89_BLOCKSIZE],
                                  buf );

        if( memcmp( &gost89_testz_ecb_ct[i * MBEDTLS_GOST89_BLOCKSIZE],
                    buf, MBEDTLS_GOST89_BLOCKSIZE ) != 0 )
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
        mbedtls_gost89_crypt_ecb( &ctx, MBEDTLS_GOST89_DECRYPT,
                                  &gost89_testz_ecb_ct[i * MBEDTLS_GOST89_BLOCKSIZE],
                                  buf );

        if( memcmp( &gost89_testz_pt[i * MBEDTLS_GOST89_BLOCKSIZE],
                    buf, MBEDTLS_GOST89_BLOCKSIZE ) != 0 )
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
