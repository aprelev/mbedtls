/*
 *  Elliptic curve GOST algorithms
 *
 *  https://tools.ietf.org/html/rfc7091
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECGOST_C)

#include "mbedtls/ecgost.h"
#include "mbedtls/asn1write.h"

#include <string.h>

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/*
 * Derive a suitable integer for group grp from a buffer of length len
 */
static int derive_mpi( const mbedtls_ecp_group *grp, mbedtls_mpi *x,
                       const unsigned char *buf, size_t blen )
{
    int ret;
    size_t n_size = ( grp->nbits + 7 ) / 8;

    /* GOST algorithm can only sign fixed size hash */
    if( blen != n_size )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    /* GOST hash is MPI in little-endian format */
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary_le( x, buf, blen ) );

    /* While at it, reduce modulo N */
    if( mbedtls_mpi_cmp_mpi( x, &grp->N ) >= 0 )
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( x, x, &grp->N ) );

cleanup:
    return( ret );
}

static inline int is_gost_ecp_group( mbedtls_ecp_group_id gid )
{
    return( ( gid == MBEDTLS_ECP_DP_GOST256TEST ) ||
            ( gid == MBEDTLS_ECP_DP_GOST256A )    ||
            ( gid == MBEDTLS_ECP_DP_GOST256B )    ||
            ( gid == MBEDTLS_ECP_DP_GOST256C )    ||
            ( gid == MBEDTLS_ECP_DP_GOST512TEST ) ||
            ( gid == MBEDTLS_ECP_DP_GOST512A )    ||
            ( gid == MBEDTLS_ECP_DP_GOST512B ) );
}

/*
 * Compute GOST signature of a hashed message
 */
int mbedtls_ecgost_sign( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret, key_tries, sign_tries;
    mbedtls_ecp_point C;
    mbedtls_mpi k, e;

    /* GOST algorithm can only work with GOST ECP groups */
    if( !is_gost_ecp_group( grp->id ) )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    mbedtls_ecp_point_init( &C );
    mbedtls_mpi_init( &k ); mbedtls_mpi_init( &e );

    /*
     * Step 1: derive MPI from hashed message
     */
    MBEDTLS_MPI_CHK( derive_mpi( grp, &e, buf, blen ) );

    sign_tries = 0;
    do
    {
        /*
         * Steps 2-3: generate a suitable ephemeral keypair
         * and set r = xC mod n
         */
        key_tries = 0;
        do
        {
            MBEDTLS_MPI_CHK( mbedtls_ecp_gen_keypair( grp, &k, &C, f_rng, p_rng ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( r, &C.X, &grp->N ) );

            if( key_tries++ > 10 )
            {
                ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
                goto cleanup;
            }
        }
        while( mbedtls_mpi_cmp_int( r, 0 ) == 0 );

        /*
         * Step 4: compute s = (r * d + k * e) mod n
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( s, r, d ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &k, &k, &e ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( s, s, &k ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( s, s, &grp->N ) );

        if( sign_tries++ > 10 )
        {
            ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }
    }
    while( mbedtls_mpi_cmp_int( s, 0 ) == 0 );

cleanup:
    mbedtls_ecp_point_free( &C );
    mbedtls_mpi_free( &k ); mbedtls_mpi_free( &e );

    return( ret );
}

/*
 * Verify GOST signature of hashed message
 */
int mbedtls_ecgost_verify( mbedtls_ecp_group *grp,
                  const unsigned char *buf, size_t blen,
                  const mbedtls_ecp_point *Q, const mbedtls_mpi *r, const mbedtls_mpi *s)
{
    int ret;
    mbedtls_mpi e, e_inv, z1, z2;
    mbedtls_ecp_point R;

    /* GOST algorithm can only work with GOST ECP groups */
    if( !is_gost_ecp_group( grp->id ) )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    mbedtls_ecp_point_init( &R );
    mbedtls_mpi_init( &e ); mbedtls_mpi_init( &e_inv ); mbedtls_mpi_init( &z1 ); mbedtls_mpi_init( &z2 );

    /*
     * Step 1: make sure r and s are in range 1..n-1
     */
    if( mbedtls_mpi_cmp_int( r, 1 ) < 0 || mbedtls_mpi_cmp_mpi( r, &grp->N ) >= 0 ||
        mbedtls_mpi_cmp_int( s, 1 ) < 0 || mbedtls_mpi_cmp_mpi( s, &grp->N ) >= 0 )
    {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Additional precaution: make sure Q is valid
     */
    MBEDTLS_MPI_CHK( mbedtls_ecp_check_pubkey( grp, Q ) );

    /*
     * Step 3: derive MPI from hashed message
     */
    MBEDTLS_MPI_CHK( derive_mpi( grp, &e, buf, blen ) );

    /*
     * Step 4: z1 = s / e mod n, z2 = -r / e mod n
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &e_inv, &e, &grp->N ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &z1, s, &e_inv ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &z1, &z1, &grp->N ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &z2, r, &e_inv ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &z2, &z2, &grp->N ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &z2, &grp->N, &z2 ) );

    /*
     * Step 5: R = z1 G + z2 Q
     *
     * Since we're not using any secret data, no need to pass a RNG to
     * mbedtls_ecp_mul() for countermesures.
     */
    MBEDTLS_MPI_CHK( mbedtls_ecp_muladd( grp, &R, &z1, &grp->G, &z2, Q ) );

    if( mbedtls_ecp_is_zero( &R ) )
    {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Step 6: convert xR to an integer (no-op)
     * Step 7: reduce xR mod n
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &R.X, &R.X, &grp->N ) );

    /*
     * Step 8: check if xR is equal to r
     */
    if( mbedtls_mpi_cmp_mpi( &R.X, r ) != 0 )
    {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_point_free( &R );
    mbedtls_mpi_free( &e ); mbedtls_mpi_free( &e_inv ); mbedtls_mpi_free( &z1 ); mbedtls_mpi_free( &z2 );

    return( ret );
}

/*
 * Convert a signature (given by context) to ASN.1
 */
static int gost_signature_to_asn1( size_t n_size, const mbedtls_mpi *r, const mbedtls_mpi *s,
                                   unsigned char *sig, size_t *slen )
{
    int ret;
    unsigned char buf[MBEDTLS_ECGOST_MAX_LEN];
    unsigned char *p = buf + sizeof( buf );

    p -= n_size;
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( r, p, n_size ) );

    p -= n_size;
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( s, p, n_size ) );

    *slen = n_size << 1;
    memcpy( sig, p, *slen );

    ret = 0;

cleanup:
    return( ret );
}

/*
 * Compute and write signature
 */
int mbedtls_ecgost_write_signature( mbedtls_ecgost_context *ctx,
                           const unsigned char *hash, size_t hlen,
                           unsigned char *sig, size_t *slen,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng )
{
    int ret;
    mbedtls_mpi r, s;

    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );

    MBEDTLS_MPI_CHK( mbedtls_ecgost_sign( &ctx->key.grp, &r, &s, &ctx->key.d,
                         hash, hlen, f_rng, p_rng ) );

    /* GOST algorithm can only sign fixed size hash, n_size = hlen */
    MBEDTLS_MPI_CHK( gost_signature_to_asn1( hlen, &r, &s, sig, slen ) );

cleanup:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );

    return( ret );
}

/*
 * Read and check signature
 */
int mbedtls_ecgost_read_signature( mbedtls_ecgost_context *ctx,
                          const unsigned char *hash, size_t hlen,
                          const unsigned char *sig, size_t slen )
{
    int ret;
    unsigned char *p = (unsigned char *) sig;
    size_t n_size = ( ctx->key.grp.nbits + 7 ) / 8;
    mbedtls_mpi r, s;

    if( slen != n_size << 1 )
        return( MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH );

    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );

    if( ( ret = mbedtls_mpi_read_binary( &s, p, n_size ) ) != 0 )
    {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    p += n_size;

    if( ( ret = mbedtls_mpi_read_binary( &r, p, n_size ) ) != 0 )
    {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    if( ( ret = mbedtls_ecgost_verify( &ctx->key.grp, hash, hlen,
                              &ctx->key.Q, &r, &s ) ) != 0 )
        goto cleanup;

cleanup:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );

    return( ret );
}

/*
 * Export a point into unsigned binary data (RFC 4357)
 */
int mbedtls_ecgost_write_pubkey( const mbedtls_ecp_group *grp, const mbedtls_ecp_point *P,
                            size_t *olen, unsigned char *buf, size_t buflen )
{
    int ret;
    unsigned char pubkey[MBEDTLS_ECGOST_MAX_LEN];
    unsigned char *p = pubkey + sizeof( pubkey );
    size_t n_size = ( grp->nbits + 7 ) / 8;
    size_t len = n_size;

    /* GOST algorithm can only work with GOST ECP groups */
    if( !is_gost_ecp_group( grp->id ) )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    p -= n_size;
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary_le( &P->Y, p, len ) );

    p -= n_size;
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary_le( &P->X, p, len ) );

    len <<= 1;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &p, pubkey, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &p, pubkey, MBEDTLS_ASN1_OCTET_STRING ) );

    *olen = len;

    if( buflen < *olen )
        return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

    memcpy( buf, p, len );

    ret = 0;

cleanup:
    return( ret );
}

/*
 * Import a point from unsigned binary data (RFC 4357)
 */
int mbedtls_ecgost_read_pubkey( const mbedtls_ecp_group *grp, mbedtls_ecp_point *pt,
                           const unsigned char *buf, size_t ilen )
{
    int ret;
    unsigned char *p = (unsigned char *) buf;
    const unsigned char *end = buf + ilen;
    size_t len;
    size_t n_size = ( grp->nbits + 7 ) / 8;

    /* GOST algorithm can only work with GOST ECP groups */
    if( !is_gost_ecp_group( grp->id ) )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
    {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    if( p + len != end )
    {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA +
              MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
        goto cleanup;
    }

    if( len != n_size << 1 )
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    if( ( ret = mbedtls_mpi_read_binary_le( &pt->X, p, n_size ) ) != 0 )
    {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    p += n_size;

    if( ( ret = mbedtls_mpi_read_binary_le( &pt->Y, p, n_size ) ) != 0 )
    {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &pt->Z, 1 ) );

cleanup:
    return( ret );
}

/*
 * Generate key pair
 */
int mbedtls_ecgost_genkey( mbedtls_ecgost_context *ctx, mbedtls_ecp_group_id gid,
                  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    /* GOST algorithm can only work with GOST ECP groups */
    if( !is_gost_ecp_group( gid ) )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    return( mbedtls_ecp_group_load( &ctx->key.grp, gid ) ||
            mbedtls_ecp_gen_keypair( &ctx->key.grp, &ctx->key.d, &ctx->key.Q, f_rng, p_rng ) );
}

/*
 * Set context from an mbedtls_ecp_keypair
 */
int mbedtls_ecgost_from_keypair( mbedtls_ecgost_context *ctx, const mbedtls_ecp_keypair *key )
{
    int ret;

    /* GOST algorithm can only work with GOST ECP groups */
    if( !is_gost_ecp_group( key->grp.id ) )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedtls_ecp_group_copy( &ctx->key.grp, &key->grp ) ) != 0 ||
        ( ret = mbedtls_mpi_copy( &ctx->key.d, &key->d ) ) != 0 ||
        ( ret = mbedtls_ecp_copy( &ctx->key.Q, &key->Q ) ) != 0 )
    {
        mbedtls_ecgost_free( ctx );
    }

    return( ret );
}

/*
 * Initialize context
 */
void mbedtls_ecgost_init( mbedtls_ecgost_context *ctx,
                          mbedtls_md_type_t gost_md_alg,
                          mbedtls_cipher_id_t gost89_alg )
{
    mbedtls_ecp_keypair_init( &ctx->key );

    ctx->gost_md_alg = gost_md_alg;
    ctx->gost89_alg = gost89_alg;
}

/*
 * Free context
 */
void mbedtls_ecgost_free( mbedtls_ecgost_context *ctx )
{
    mbedtls_ecp_keypair_free( &ctx->key );
}

#endif /* MBEDTLS_ECGOST_C */
