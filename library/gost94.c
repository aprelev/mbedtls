/*
 *  The GOST R 34.11-94 hash function implementation
 *
 *  https://tools.ietf.org/html/rfc5831
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_GOST94_C)

#include "mbedtls/gost94.h"

#include <string.h>

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#if !defined(MBEDTLS_GOST94_ALT)

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = (unsigned char*)v; while( n-- ) *p++ = 0;
}

/*
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n,b,i)                         \
{                                                    \
    (n) = ( (uint32_t) (b)[(i)    ]       )          \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )          \
        | ( (uint32_t) (b)[(i) + 2] << 16 )          \
        | ( (uint32_t) (b)[(i) + 3] << 24 );         \
}
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n,b,i)                         \
{                                                    \
    (b)[(i)    ] = (unsigned char) ( (n)       );    \
    (b)[(i) + 1] = (unsigned char) ( (n) >>  8 );    \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 16 );    \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 24 );    \
}
#endif

void mbedtls_gost94_init( mbedtls_gost94_context *ctx,
                          mbedtls_gost89_sbox_id_t sbox_id )
{
    memset( ctx, 0, sizeof( mbedtls_gost94_context ) );
    ctx->sbox_id = sbox_id;
}

void mbedtls_gost94_free( mbedtls_gost94_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_zeroize( ctx, sizeof( mbedtls_gost94_context ) );
}

void mbedtls_gost94_clone( mbedtls_gost94_context *dst,
                           const mbedtls_gost94_context *src )
{
    *dst = *src;
}

/*
 * GOST94 context setup
 */
void mbedtls_gost94_starts( mbedtls_gost94_context *ctx )
{
    int i;

    ctx->total[0] = 0;
    ctx->total[1] = 0;

    for( i = 0; i < 32; i++ )
    {
        ctx->h[i] = 0;
        ctx->sum[i] = 0;
    }
}

#if !defined(MBEDTLS_GOST94_PROCESS_ALT)
static const uint32_t C3[8] =
{
    0xff00ff00,
    0xff00ff00,
    0x00ff00ff,
    0x00ff00ff,
    0x00ffff00,
    0xff0000ff,
    0x000000ff,
    0xff00ffff
};

#define XOR(w,u,v)         \
{                          \
    w[0] = u[0] ^ v[0];    \
    w[1] = u[1] ^ v[1];    \
    w[2] = u[2] ^ v[2];    \
    w[3] = u[3] ^ v[3];    \
    w[4] = u[4] ^ v[4];    \
    w[5] = u[5] ^ v[5];    \
    w[6] = u[6] ^ v[6];    \
    w[7] = u[7] ^ v[7];    \
}

#define A(y,tmp1,tmp2)       \
{                            \
    tmp1 = y[6];             \
    tmp2 = y[7];             \
      y[6] = y[0] ^ y[2];    \
      y[7] = y[1] ^ y[3];    \
      y[0] = y[2];           \
      y[1] = y[3];           \
      y[2] = y[4];           \
      y[3] = y[5];           \
      y[4] = tmp1;           \
      y[5] = tmp2;           \
}

#define P(k,w)                                                                                                                               \
{                                                                                                                                            \
    k[0] = ( (w[0] & 0x000000ff)       ) | ( (w[2] & 0x000000ff) <<  8 ) | ( (w[4] & 0x000000ff) << 16 ) | ( (w[6] & 0x000000ff) << 24 );    \
    k[1] = ( (w[0] & 0x0000ff00) >> 8  ) | ( (w[2] & 0x0000ff00)       ) | ( (w[4] & 0x0000ff00) <<  8 ) | ( (w[6] & 0x0000ff00) << 16 );    \
    k[2] = ( (w[0] & 0x00ff0000) >> 16 ) | ( (w[2] & 0x00ff0000) >>  8 ) | ( (w[4] & 0x00ff0000)       ) | ( (w[6] & 0x00ff0000) <<  8 );    \
    k[3] = ( (w[0] & 0xff000000) >> 24 ) | ( (w[2] & 0xff000000) >> 16 ) | ( (w[4] & 0xff000000) >>  8 ) | ( (w[6] & 0xff000000)       );    \
    k[4] = ( (w[1] & 0x000000ff)       ) | ( (w[3] & 0x000000ff) <<  8 ) | ( (w[5] & 0x000000ff) << 16 ) | ( (w[7] & 0x000000ff) << 24 );    \
    k[5] = ( (w[1] & 0x0000ff00) >> 8  ) | ( (w[3] & 0x0000ff00)       ) | ( (w[5] & 0x0000ff00) <<  8 ) | ( (w[7] & 0x0000ff00) << 16 );    \
    k[6] = ( (w[1] & 0x00ff0000) >> 16 ) | ( (w[3] & 0x00ff0000) >>  8 ) | ( (w[5] & 0x00ff0000)       ) | ( (w[7] & 0x00ff0000) <<  8 );    \
    k[7] = ( (w[1] & 0xff000000) >> 24 ) | ( (w[3] & 0xff000000) >> 16 ) | ( (w[5] & 0xff000000) >>  8 ) | ( (w[7] & 0xff000000)       );    \
}

#define Psi(s,tmp)                                        \
{                                                         \
    tmp = ( (uint32_t) s[31] << 8 ) | s[30];              \
    s[30] = s[0] ^ s[2] ^ s[4] ^ s[6] ^ s[24] ^ s[30];    \
    s[31] = s[1] ^ s[3] ^ s[5] ^ s[7] ^ s[25] ^ s[31];    \
    s[0] = s[2];                                          \
    s[1] = s[3];                                          \
    s[2] = s[4];                                          \
    s[3] = s[5];                                          \
    s[4] = s[6];                                          \
    s[5] = s[7];                                          \
    s[6] = s[8];                                          \
    s[7] = s[9];                                          \
    s[8] = s[10];                                         \
    s[9] = s[11];                                         \
    s[10] = s[12];                                        \
    s[11] = s[13];                                        \
    s[12] = s[14];                                        \
    s[13] = s[15];                                        \
    s[14] = s[16];                                        \
    s[15] = s[17];                                        \
    s[16] = s[18];                                        \
    s[17] = s[19];                                        \
    s[18] = s[20];                                        \
    s[19] = s[21];                                        \
    s[20] = s[22];                                        \
    s[21] = s[23];                                        \
    s[22] = s[24];                                        \
    s[23] = s[25];                                        \
    s[24] = s[26];                                        \
    s[25] = s[27];                                        \
    s[26] = s[28];                                        \
    s[27] = s[29];                                        \
    s[28] = (unsigned char) tmp;                          \
    s[29] = (unsigned char) ( tmp >> 8 );                 \
}

void mbedtls_gost94_process( mbedtls_gost94_context *ctx, const unsigned char data[32] )
{
    int i;
    uint32_t u[8], v[8], w[8], tmp1, tmp2;
    unsigned char s[32], c;
    mbedtls_gost89_context gost89;

    mbedtls_gost89_init( &gost89, ctx->sbox_id, MBEDTLS_GOST89_KEY_MESHING_NONE );

    /*
     * Step 1
     */
    GET_UINT32_LE( u[0], ctx->h, 0 );
    GET_UINT32_LE( u[1], ctx->h, 4 );
    GET_UINT32_LE( u[2], ctx->h, 8 );
    GET_UINT32_LE( u[3], ctx->h, 12 );
    GET_UINT32_LE( u[4], ctx->h, 16 );
    GET_UINT32_LE( u[5], ctx->h, 20 );
    GET_UINT32_LE( u[6], ctx->h, 24 );
    GET_UINT32_LE( u[7], ctx->h, 28 );

    GET_UINT32_LE( v[0], data, 0 );
    GET_UINT32_LE( v[1], data, 4 );
    GET_UINT32_LE( v[2], data, 8 );
    GET_UINT32_LE( v[3], data, 12 );
    GET_UINT32_LE( v[4], data, 16 );
    GET_UINT32_LE( v[5], data, 20 );
    GET_UINT32_LE( v[6], data, 24 );
    GET_UINT32_LE( v[7], data, 28 );

    XOR( w, u, v );

    P( gost89.rk, w );

    mbedtls_gost89_encrypt( &gost89, ctx->h, s );

    /*
     * Steps 2, 3, 4
     */
    for( i = 1; i < 4; i++ )
    {
        A( u, tmp1, tmp2 );
        if( i == 2 )
            XOR( u, u, C3 );

        A( v, tmp1, tmp2 );
        A( v, tmp1, tmp2 );

        XOR( w, u, v );

        P( gost89.rk, w );

        mbedtls_gost89_encrypt( &gost89, &ctx->h[i << 3], &s[i << 3] );
    }

    /*
     * Final step
     */
    for( i = 0; i < 12; i++ )
        Psi( s, tmp1 );

    for( i = 0; i < 32; i++ )
        s[i] ^= data[i];
    Psi( s, tmp1 );

    for( i = 0; i < 32; i++ )
        ctx->h[i] ^= s[i];
    for( i = 0; i < 61; i++ )
        Psi( ctx->h, tmp1 );

    /*
     * Update control sum
     */
    c = 0;
    for( i = 0; i < 32; i++ )
    {
        ctx->sum[i] += c;
        c = (unsigned char) ( ctx->sum[i] < c );
        ctx->sum[i] += data[i];
        c += (unsigned char) ( ctx->sum[i] < data[i] );
    }

    mbedtls_gost89_free( &gost89 );
}
#endif /* !MBEDTLS_GOST94_PROCESS_ALT */

/*
 * GOST94 process buffer
 */
void mbedtls_gost94_update( mbedtls_gost94_context *ctx, const unsigned char *input,
                            size_t ilen )
{
    size_t fill;
    uint32_t left;

    if( ilen == 0 )
        return;

    left = ctx->total[0] & 0x1F;
    fill = 32 - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (uint32_t) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left), input, fill );
        mbedtls_gost94_process( ctx, ctx->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 32 )
    {
        mbedtls_gost94_process( ctx, input );
        input += 32;
        ilen  -= 32;
    }

    if( ilen > 0 )
        memcpy( (void *) (ctx->buffer + left), input, ilen );
}

static const unsigned char gost94_padding[32] =
{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * GOST94 final digest
 */
void mbedtls_gost94_finish( mbedtls_gost94_context *ctx, unsigned char output[32] )
{
    uint32_t last, padn;
    uint32_t high, low;
    unsigned char msglen[32], sum[32];

    memset( msglen, 0, 32 );

    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_UINT32_LE( low, msglen, 0 );
    PUT_UINT32_LE( high, msglen, 4 );

    last = ctx->total[0] & 0x1F;
    padn = ( last != 0 ) ? ( 32 - last ) : ( 0 );

    mbedtls_gost94_update( ctx, gost94_padding, padn );
    memcpy( sum, ctx->sum, 32 );
    mbedtls_gost94_process( ctx, msglen );
    mbedtls_gost94_process( ctx, sum );

    memcpy( output, ctx->h, 32 );
}

#endif /* !MBEDTLS_GOST94_ALT */

/*
 * output = GOST94( input buffer )
 */
void mbedtls_gost94( mbedtls_gost89_sbox_id_t sbox_id,
                     const unsigned char *input, size_t ilen,
                     unsigned char output[32] )
{
    mbedtls_gost94_context ctx;

    mbedtls_gost94_init( &ctx, sbox_id );
    mbedtls_gost94_starts( &ctx );
    mbedtls_gost94_update( &ctx, input, ilen );
    mbedtls_gost94_finish( &ctx, output );
    mbedtls_gost94_free( &ctx );
}

#if defined(MBEDTLS_SELF_TEST)
/*
 * GOST R 34.11-94 test vectors from:
 *
 * http://gosthash.chat.ru
 */
static const unsigned char gost94_testbuf[10][81] =
{
    { "" },
    { "a" },
    { "abc" },
    { "message digest" },
    { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" },
    { "12345678901234567890123456789012345678901234567890123456789012345678901234567890" },
    { "This is message, length=32 bytes" },
    { "Suppose the original message has length = 50 bytes" },
    { "The quick brown fox jumps over the lazy dog" },
    { "The quick brown fox jumps over the lazy cog" }
};

static const int gost94_test_buflen[10] =
{
    0, 1, 3, 14, 62, 80, 32, 50, 43, 43
};

static const unsigned char gost94_test_test_sum[10][32] =
{
    /*
     * id-GostR3411-94-TestParamSet test vectors
     */
    { 0xce, 0x85, 0xb9, 0x9c, 0xc4, 0x67, 0x52, 0xff,
      0xfe, 0xe3, 0x5c, 0xab, 0x9a, 0x7b, 0x02, 0x78,
      0xab, 0xb4, 0xc2, 0xd2, 0x05, 0x5c, 0xff, 0x68,
      0x5a, 0xf4, 0x91, 0x2c, 0x49, 0x49, 0x0f, 0x8d },
    { 0xd4, 0x2c, 0x53, 0x9e, 0x36, 0x7c, 0x66, 0xe9,
      0xc8, 0x8a, 0x80, 0x1f, 0x66, 0x49, 0x34, 0x9c,
      0x21, 0x87, 0x1b, 0x43, 0x44, 0xc6, 0xa5, 0x73,
      0xf8, 0x49, 0xfd, 0xce, 0x62, 0xf3, 0x14, 0xdd },
    { 0xf3, 0x13, 0x43, 0x48, 0xc4, 0x4f, 0xb1, 0xb2,
      0xa2, 0x77, 0x72, 0x9e, 0x22, 0x85, 0xeb, 0xb5,
      0xcb, 0x5e, 0x0f, 0x29, 0xc9, 0x75, 0xbc, 0x75,
      0x3b, 0x70, 0x49, 0x7c, 0x06, 0xa4, 0xd5, 0x1d },
    { 0xad, 0x44, 0x34, 0xec, 0xb1, 0x8f, 0x2c, 0x99,
      0xb6, 0x0c, 0xbe, 0x59, 0xec, 0x3d, 0x24, 0x69,
      0x58, 0x2b, 0x65, 0x27, 0x3f, 0x48, 0xde, 0x72,
      0xdb, 0x2f, 0xde, 0x16, 0xa4, 0x88, 0x9a, 0x4d },
    { 0x95, 0xc1, 0xaf, 0x62, 0x7c, 0x35, 0x64, 0x96,
      0xd8, 0x02, 0x74, 0x33, 0x0b, 0x2c, 0xff, 0x6a,
      0x10, 0xc6, 0x7b, 0x5f, 0x59, 0x70, 0x87, 0x20,
      0x2f, 0x94, 0xd0, 0x6d, 0x23, 0x38, 0xcf, 0x8e },
    { 0xcc, 0x17, 0x8d, 0xca, 0xd4, 0xdf, 0x61, 0x9d,
      0xca, 0xa0, 0x0a, 0xac, 0x79, 0xca, 0x35, 0x5c,
      0x00, 0x14, 0x4e, 0x4a, 0xda, 0x27, 0x93, 0xd7,
      0xbd, 0x9b, 0x35, 0x18, 0xea, 0xd3, 0xcc, 0xd3 },
    { 0xb1, 0xc4, 0x66, 0xd3, 0x75, 0x19, 0xb8, 0x2e,
      0x83, 0x19, 0x81, 0x9f, 0xf3, 0x25, 0x95, 0xe0,
      0x47, 0xa2, 0x8c, 0xb6, 0xf8, 0x3e, 0xff, 0x1c,
      0x69, 0x16, 0xa8, 0x15, 0xa6, 0x37, 0xff, 0xfa },
    { 0x47, 0x1a, 0xba, 0x57, 0xa6, 0x0a, 0x77, 0x0d,
      0x3a, 0x76, 0x13, 0x06, 0x35, 0xc1, 0xfb, 0xea,
      0x4e, 0xf1, 0x4d, 0xe5, 0x1f, 0x78, 0xb4, 0xae,
      0x57, 0xdd, 0x89, 0x3b, 0x62, 0xf5, 0x52, 0x08 },
    { 0x77, 0xb7, 0xfa, 0x41, 0x0c, 0x9a, 0xc5, 0x8a,
      0x25, 0xf4, 0x9b, 0xca, 0x7d, 0x04, 0x68, 0xc9,
      0x29, 0x65, 0x29, 0x31, 0x5e, 0xac, 0xa7, 0x6b,
      0xd1, 0xa1, 0x0f, 0x37, 0x6d, 0x1f, 0x42, 0x94 },
    { 0xa3, 0xeb, 0xc4, 0xda, 0xaa, 0xb7, 0x8b, 0x0b,
      0xe1, 0x31, 0xda, 0xb5, 0x73, 0x7a, 0x7f, 0x67,
      0xe6, 0x02, 0x67, 0x0d, 0x54, 0x35, 0x21, 0x31,
      0x91, 0x50, 0xd2, 0xe1, 0x4e, 0xee, 0xc4, 0x45 }
};

static const unsigned char gost94_cryptopro_test_sum[9][32] =
{
    /*
     * id-GostR3411-94-CryptoProParamSet test vectors
     */
    { 0x98, 0x1e, 0x5f, 0x3c, 0xa3, 0x0c, 0x84, 0x14,
      0x87, 0x83, 0x0f, 0x84, 0xfb, 0x43, 0x3e, 0x13,
      0xac, 0x11, 0x01, 0x56, 0x9b, 0x9c, 0x13, 0x58,
      0x4a, 0xc4, 0x83, 0x23, 0x4c, 0xd6, 0x56, 0xc0 },
    { 0xe7, 0x4c, 0x52, 0xdd, 0x28, 0x21, 0x83, 0xbf,
      0x37, 0xaf, 0x00, 0x79, 0xc9, 0xf7, 0x80, 0x55,
      0x71, 0x5a, 0x10, 0x3f, 0x17, 0xe3, 0x13, 0x3c,
      0xef, 0xf1, 0xaa, 0xcf, 0x2f, 0x40, 0x30, 0x11 },
    { 0xb2, 0x85, 0x05, 0x6d, 0xbf, 0x18, 0xd7, 0x39,
      0x2d, 0x76, 0x77, 0x36, 0x95, 0x24, 0xdd, 0x14,
      0x74, 0x74, 0x59, 0xed, 0x81, 0x43, 0x99, 0x7e,
      0x16, 0x3b, 0x29, 0x86, 0xf9, 0x2f, 0xd4, 0x2c },
    { 0xbc, 0x60, 0x41, 0xdd, 0x2a, 0xa4, 0x01, 0xeb,
      0xfa, 0x6e, 0x98, 0x86, 0x73, 0x41, 0x74, 0xfe,
      0xbd, 0xb4, 0x72, 0x9a, 0xa9, 0x72, 0xd6, 0x0f,
      0x54, 0x9a, 0xc3, 0x9b, 0x29, 0x72, 0x1b, 0xa0 },
    { 0x73, 0xb7, 0x0a, 0x39, 0x49, 0x7d, 0xe5, 0x3a,
      0x6e, 0x08, 0xc6, 0x7b, 0x6d, 0x4d, 0xb8, 0x53,
      0x54, 0x0f, 0x03, 0xe9, 0x38, 0x92, 0x99, 0xd9,
      0xb0, 0x15, 0x6e, 0xf7, 0xe8, 0x5d, 0x0f, 0x61 },
    { 0x6b, 0xc7, 0xb3, 0x89, 0x89, 0xb2, 0x8c, 0xf9,
      0x3a, 0xe8, 0x84, 0x2b, 0xf9, 0xd7, 0x52, 0x90,
      0x59, 0x10, 0xa7, 0x52, 0x8a, 0x61, 0xe5, 0xbc,
      0xe0, 0x78, 0x2d, 0xe4, 0x3e, 0x61, 0x0c, 0x90 },
    { 0x2c, 0xef, 0xc2, 0xf7, 0xb7, 0xbd, 0xc5, 0x14,
      0xe1, 0x8e, 0xa5, 0x7f, 0xa7, 0x4f, 0xf3, 0x57,
      0xe7, 0xfa, 0x17, 0xd6, 0x52, 0xc7, 0x5f, 0x69,
      0xcb, 0x1b, 0xe7, 0x89, 0x3e, 0xde, 0x48, 0xeb },
    { 0xc3, 0x73, 0x0c, 0x5c, 0xbc, 0xca, 0xcf, 0x91,
      0x5a, 0xc2, 0x92, 0x67, 0x6f, 0x21, 0xe8, 0xbd,
      0x4e, 0xf7, 0x53, 0x31, 0xd9, 0x40, 0x5e, 0x5f,
      0x1a, 0x61, 0xdc, 0x31, 0x30, 0xa6, 0x50, 0x11 },
    { 0x90, 0x04, 0x29, 0x4a, 0x36, 0x1a, 0x50, 0x8c,
      0x58, 0x6f, 0xe5, 0x3d, 0x1f, 0x1b, 0x02, 0x74,
      0x67, 0x65, 0xe7, 0x1b, 0x76, 0x54, 0x72, 0x78,
      0x6e, 0x47, 0x70, 0xd5, 0x65, 0x83, 0x0a, 0x76 }
};

static const unsigned char gost94_special_testbuf[2][1] =
{
    { "U" },
    { "a" },
};

static const int gost94_special_buflen[2] =
{
    128, 1000000
};

static const unsigned char gost94_test_special_test_sum[2][32] =
{
    { 0x53, 0xa3, 0xa3, 0xed, 0x25, 0x18, 0x0c, 0xef,
      0x0c, 0x1d, 0x85, 0xa0, 0x74, 0x27, 0x3e, 0x55,
      0x1c, 0x25, 0x66, 0x0a, 0x87, 0x06, 0x2a, 0x52,
      0xd9, 0x26, 0xa9, 0xe8, 0xfe, 0x57, 0x33, 0xa4 },
    { 0x5c, 0x00, 0xcc, 0xc2, 0x73, 0x4c, 0xdd, 0x33,
      0x32, 0xd3, 0xd4, 0x74, 0x95, 0x76, 0xe3, 0xc1,
      0xa7, 0xdb, 0xaf, 0x0e, 0x7e, 0xa7, 0x4e, 0x9f,
      0xa6, 0x02, 0x41, 0x3c, 0x90, 0xa1, 0x29, 0xfa }
};

static const unsigned char gost94_cryptopro_special_test_sum[2][32] =
{
    { 0x1c, 0x4a, 0xc7, 0x61, 0x46, 0x91, 0xbb, 0xf4,
      0x27, 0xfa, 0x23, 0x16, 0x21, 0x6b, 0xe8, 0xf1,
      0x0d, 0x92, 0xed, 0xfd, 0x37, 0xcd, 0x10, 0x27,
      0x51, 0x4c, 0x10, 0x08, 0xf6, 0x49, 0xc4, 0xe8 },
    { 0x86, 0x93, 0x28, 0x7a, 0xa6, 0x2f, 0x94, 0x78,
      0xf7, 0xcb, 0x31, 0x2e, 0xc0, 0x86, 0x6b, 0x6c,
      0x4e, 0x4a, 0x0f, 0x11, 0x16, 0x04, 0x41, 0xe8,
      0xf4, 0xff, 0xcd, 0x27, 0x15, 0xdd, 0x55, 0x4f }
}
;
/*
 * Checkup routine
 */
int mbedtls_gost94_self_test( int verbose )
{
    int i, j, ret = 0;
    unsigned char gost94sum[32];
    mbedtls_gost94_context ctx;

    mbedtls_gost94_init( &ctx, MBEDTLS_GOST94_SBOX_TEST );
    for( i = 0; i < 10; i++ )
    {
        if( verbose != 0 )
            mbedtls_printf( "  GOST94-TEST test #%d: ", i + 1 );

        mbedtls_gost94_starts( &ctx );

        mbedtls_gost94_update( &ctx, gost94_testbuf[i],
                               gost94_test_buflen[i] );

        mbedtls_gost94_finish( &ctx, gost94sum );

        if( memcmp( gost94sum, gost94_test_test_sum[i], 32 ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    mbedtls_gost94_init( &ctx, MBEDTLS_GOST94_SBOX_CRYPTOPRO );
    for( i = 0; i < 9; i++ )
    {
        if( verbose != 0 )
            mbedtls_printf( "  GOST94-CRYPTOPRO test #%d: ", i + 1 );

        mbedtls_gost94_starts( &ctx );

        mbedtls_gost94_update( &ctx, gost94_testbuf[i],
                               gost94_test_buflen[i] );

        mbedtls_gost94_finish( &ctx, gost94sum );

        if( memcmp( gost94sum, gost94_cryptopro_test_sum[i], 32 ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    mbedtls_gost94_init( &ctx, MBEDTLS_GOST94_SBOX_TEST );
    for( i = 0; i < 2; i++ )
    {
        if( verbose != 0 )
            mbedtls_printf( "  GOST94-TEST special test #%d: ", i + 1 );

        mbedtls_gost94_starts( &ctx );

        for( j = 0; j < gost94_special_buflen[i]; j++ )
            mbedtls_gost94_update( &ctx, gost94_special_testbuf[i], 1 );

        mbedtls_gost94_finish( &ctx, gost94sum );

        if( memcmp( gost94sum, gost94_test_special_test_sum[i], 32 ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    mbedtls_gost94_init( &ctx, MBEDTLS_GOST94_SBOX_CRYPTOPRO );
    for( i = 0; i < 2; i++ )
    {
        if( verbose != 0 )
            mbedtls_printf( "  GOST94-CRYPTOPRO special test #%d: ", i + 1 );

        mbedtls_gost94_starts( &ctx );

        for( j = 0; j < gost94_special_buflen[i]; j++ )
            mbedtls_gost94_update( &ctx, gost94_special_testbuf[i], 1 );

        mbedtls_gost94_finish( &ctx, gost94sum );

        if( memcmp( gost94sum, gost94_cryptopro_special_test_sum[i], 32 ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

exit:
    mbedtls_gost94_free( &ctx );

    if( verbose != 0 )
        mbedtls_printf( "\n" );

    return( ret );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_GOST94_C */
