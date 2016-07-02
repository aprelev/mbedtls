/*
 *  Elliptic curve GOST Diffie-Hellman
 *
 *  https://tools.ietf.org/html/rfc4357#page-7:
 *      VKO GOST R 34.10-2001 algorithm
 *
 *  http://tc26.ru/methods/recommendation/%D0%A2%D0%9A26%D0%90%D0%9B%D0%93.pdf page 9:
 *      VKO_GOSTR3410_2012_256 and VKO_GOSTR3410_2012_512 algorithms
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECDH_GOST_C)

#include "mbedtls/ecdh_gost.h"

#include <string.h>

/*
 * Generate public key: simple wrapper around mbedtls_ecp_gen_keypair
 */
int mbedtls_ecdh_gost_gen_public( mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    return mbedtls_ecp_gen_keypair( grp, d, Q, f_rng, p_rng );
}

/*
 * Compute shared secret
 */
int mbedtls_ecdh_gost_compute_shared( mbedtls_ecp_group *grp, mbedtls_ecp_point *P,
                         const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                         const mbedtls_mpi *ukm,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng )
{
    int ret;

    /*
     * Make sure Q is a valid pubkey before using it
     */
    MBEDTLS_MPI_CHK( mbedtls_ecp_check_pubkey( grp, Q ) );

    MBEDTLS_MPI_CHK( mbedtls_ecp_mul( grp, P, d, Q, f_rng, p_rng ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mul( grp, P, ukm, P, f_rng, p_rng ) );

    if( mbedtls_ecp_is_zero( P ) )
    {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

cleanup:
    return( ret );
}

/*
 * Initialize context
 */
void mbedtls_ecdh_gost_init( mbedtls_ecdh_gost_context *ctx,
                             mbedtls_md_type_t md_alg )
{
    if( ctx == NULL )
        return;

    mbedtls_ecp_group_init( &ctx->grp );
    mbedtls_ecp_point_init( &ctx->Q   );
    mbedtls_ecp_point_init( &ctx->Qp  );
    mbedtls_ecp_point_init( &ctx->P   );
    mbedtls_mpi_init( &ctx->d );

    ctx->md_alg = md_alg;
}

/*
 * Free context
 */
void mbedtls_ecdh_gost_free( mbedtls_ecdh_gost_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_ecp_group_free( &ctx->grp );
    mbedtls_ecp_point_free( &ctx->Q   );
    mbedtls_ecp_point_free( &ctx->Qp  );
    mbedtls_ecp_point_free( &ctx->P   );
    mbedtls_mpi_free( &ctx->d );
}

/*
 * Derive and export the shared secret
 */
int mbedtls_ecdh_gost_calc_secret( mbedtls_ecdh_gost_context *ctx,
                      unsigned char ukm[8], size_t *olen,
                      unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng )
{
    int ret;
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;
    size_t n_size, hash_len;
    unsigned char coord[MBEDTLS_ECP_MAX_BYTES];
    mbedtls_mpi ukm_mpi;

    if( ctx == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    n_size = ( ctx->grp.nbits + 7 ) / 8;

    if( ( md_info = mbedtls_md_info_from_type( ctx->md_alg ) ) == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    hash_len = mbedtls_md_get_size( md_info );

    if( hash_len > blen )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    mbedtls_mpi_init( &ukm_mpi );
    mbedtls_mpi_read_binary_le( &ukm_mpi, ukm, 8 );

    if( ( ret = mbedtls_ecdh_gost_compute_shared( &ctx->grp, &ctx->P, &ctx->Qp,
                                     &ctx->d, &ukm_mpi,
                                     f_rng, p_rng ) ) != 0 )
    {
        return( ret );
    }

    mbedtls_md_init( &md_ctx );
    if( ( ret = mbedtls_md_setup( &md_ctx, md_info, 0 ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_md_starts( &md_ctx ) ) != 0 )
        return( ret );

    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary_le( &ctx->P.X, coord, n_size ) );
    if( ( ret = mbedtls_md_update( &md_ctx, coord, n_size ) ) != 0 )
        return( ret );


    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary_le( &ctx->P.Y, coord, n_size ) );
    if( ( ret = mbedtls_md_update( &md_ctx, coord, n_size ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_md_finish( &md_ctx, buf ) ) != 0 )
        return( ret );

    *olen = hash_len;

cleanup:
    mbedtls_md_free( &md_ctx );
    mbedtls_mpi_free( &ukm_mpi );

    return( ret );
}

#endif /* MBEDTLS_ECDH_GOST_C */
