/*
 *  Example ECGOST program
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif

#if defined(MBEDTLS_ECGOST_C) && \
    defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/gost12.h"
#include "mbedtls/ecgost.h"

#include <string.h>
#endif

/*
 * Uncomment to show key and signature details
 */
#define VERBOSE

/*
 * Uncomment to force use of a specific curve
 */
#define ECPARAMS    MBEDTLS_ECP_DP_GOST256TEST

#if !defined(MBEDTLS_ECGOST_C) || !defined(MBEDTLS_GOST12_C) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_ECGOST_C and/or MBEDTLS_GOST12_C and/or "
           "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C not defined\n");
    return( 0 );
}
#else
#if defined(VERBOSE)
static void dump_buf( const char *title, unsigned char *buf, size_t len )
{
    size_t i;

    mbedtls_printf( "%s", title );
    for( i = 0; i < len; i++ )
        mbedtls_printf("%c%c", "0123456789ABCDEF" [buf[i] / 16],
                       "0123456789ABCDEF" [buf[i] % 16] );
    mbedtls_printf( "\n" );
}

static void dump_pubkey( const char *title, mbedtls_ecgost_context *key )
{
    unsigned char buf[300];
    size_t len;

    if( mbedtls_ecp_point_write_binary( &key->grp, &key->Q,
                MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf ) != 0 )
    {
        mbedtls_printf("internal error\n");
        return;
    }

    dump_buf( title, buf, len );
}
#else
#define dump_buf( a, b, c )
#define dump_pubkey( a, b )
#endif

int main( int argc, char *argv[] )
{
    int ret;
    mbedtls_ecgost_context ctx_sign, ctx_verify;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char msg[] = "This should be the hash of a message.";
    unsigned char hash[32], sig[512];
    size_t sig_len;
    const char *pers = "ecgost";
    ((void) argv);

    mbedtls_gost12( msg, sizeof( msg ), hash, 1 );

    mbedtls_ecgost_init( &ctx_sign );
    mbedtls_ecgost_init( &ctx_verify );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    memset(sig, 0, sizeof( sig ) );
    ret = 1;

    if( argc != 1 )
    {
        mbedtls_printf( "usage: ecgost\n" );

#if defined(_WIN32)
        mbedtls_printf( "\n" );
#endif

        goto exit;
    }

    /*
     * Generate a key pair for signing
     */
    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n  . Generating key pair..." );
    fflush( stdout );

    if( ( ret = mbedtls_ecgost_genkey( &ctx_sign, ECPARAMS,
                              mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecgost_genkey returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok (key size: %d bits)\n", (int) ctx_sign.grp.pbits );

    dump_pubkey( "  + Public key: ", &ctx_sign );

    /*
     * Sign some message hash
     */
    mbedtls_printf( "  . Signing message..." );
    fflush( stdout );

    if( ( ret = mbedtls_ecgost_write_signature( &ctx_sign,
                                       hash, sizeof( hash ),
                                       sig, &sig_len,
                                       mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecgost_genkey returned %d\n", ret );
        goto exit;
    }
    mbedtls_printf( " ok (signature length = %u)\n", (unsigned int) sig_len );

    dump_buf( "  + Hash: ", hash, sizeof hash );
    dump_buf( "  + Signature: ", sig, sig_len );

    /*
     * Transfer public information to verifying context
     *
     * We could use the same context for verification and signatures, but we
     * chose to use a new one in order to make it clear that the verifying
     * context only needs the public key (Q), and not the private key (d).
     */
    mbedtls_printf( "  . Preparing verification context..." );
    fflush( stdout );

    if( ( ret = mbedtls_ecp_group_copy( &ctx_verify.grp, &ctx_sign.grp ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_group_copy returned %d\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ecp_copy( &ctx_verify.Q, &ctx_sign.Q ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_copy returned %d\n", ret );
        goto exit;
    }

    ret = 0;

    /*
     * Verify signature
     */
    mbedtls_printf( " ok\n  . Verifying signature..." );
    fflush( stdout );

    if( ( ret = mbedtls_ecgost_read_signature( &ctx_verify,
                                      hash, sizeof( hash ),
                                      sig, sig_len ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecgost_read_signature returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

exit:

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    mbedtls_ecgost_free( &ctx_verify );
    mbedtls_ecgost_free( &ctx_sign );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return( ret );
}
#endif /* MBEDTLS_ECGOST_C && MBEDTLS_GOST12_C && MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C &&
          ECPARAMS */
