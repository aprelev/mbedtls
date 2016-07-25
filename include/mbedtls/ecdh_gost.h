/**
 * \file ecdh_gost.h
 *
 * \brief Elliptic curve GOST Diffie-Hellman
 */
#ifndef MBEDTLS_ECDH_GOST_H
#define MBEDTLS_ECDH_GOST_H

#include "ecgost.h"
#include "pk.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * When importing from an GOST key, select if it is our key or the peer's key
 */
typedef enum
{
    MBEDTLS_ECDH_GOST_OURS,
    MBEDTLS_ECDH_GOST_THEIRS,
} mbedtls_ecdh_gost_side;

/**
 * \brief           ECDH-GOST context structure
 */
typedef struct
{
    mbedtls_ecgost_context ecgost;         /*!<  our key pair with GOST params     */
    mbedtls_ecp_point Qp;                  /*!<  peer's public value (public key)  */
    unsigned char z[MBEDTLS_MD_MAX_SIZE];  /*!<  shared secret                     */
}
mbedtls_ecdh_gost_context;

/**
 * \brief           Generate a public key.
 *                  Raw function that only does the core computation.
 *
 * \param grp       ECP group
 * \param d         Destination MPI (secret exponent, aka private key)
 * \param Q         Destination point (public key)
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful,
 *                  or a MBEDTLS_ERR_ECP_XXX or MBEDTLS_MPI_XXX error code
 */
int mbedtls_ecdh_gost_gen_public( mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng );

/**
 * \brief           Compute shared secret
 *                  Raw function that only does the core computation.
 *
 * \param grp       ECP group
 * \param z         Destination buffer (shared secret)
 * \param Q         Public key from other party
 * \param d         Our secret exponent (private key)
 * \param ukm       User keying material
 * \param ukm_len   UKM length
 * \param md_alg    Message digest for hashing coordinates
 * \param f_rng     RNG function (see notes)
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful,
 *                  or a MBEDTLS_ERR_ECP_XXX or MBEDTLS_MPI_XXX error code
 *
 * \note            If f_rng is not NULL, it is used to implement
 *                  countermeasures against potential elaborate timing
 *                  attacks, see \c mbedtls_ecp_mul() for details.
 */
int mbedtls_ecdh_gost_compute_shared( mbedtls_ecp_group *grp, unsigned char *z,
                         const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                         const unsigned char *ukm, size_t ukm_len, mbedtls_md_type_t md_alg,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng );

/**
 * \brief           Initialize context
 *
 * \param ctx            Context to initialize
 * \param gost_md_alg    GOST MD for hashing coordinates
 * \param gost89_alg     GOST89 algorithm
 */
void mbedtls_ecdh_gost_init( mbedtls_ecdh_gost_context *ctx,
                             mbedtls_md_type_t gost_md_alg,
                             mbedtls_cipher_id_t gost89_alg );

/**
 * \brief           Free context
 *
 * \param ctx       Context to free
 */
void mbedtls_ecdh_gost_free( mbedtls_ecdh_gost_context *ctx );

/**
 * \brief           Setup an ECDH-GOST context from an EC key.
 *                  (Used by clients and servers in place of the
 *                  ServerKeyEchange for static ECDH-GOST: import ECDH-GOST parameters
 *                  from a certificate's GOST key information.)
 *
 * \param ctx       ECDH-GOST context to set
 * \param key       GOST key with params to use
 * \param side      Is it our key (1) or the peer's key (0) ?
 *
 * \return          0 if successful, or an MBEDTLS_ERR_ECP_XXX error code
 */
int mbedtls_ecdh_gost_get_params( mbedtls_ecdh_gost_context *ctx, const mbedtls_ecgost_context *key,
                     mbedtls_ecdh_gost_side side );

/**
 * \brief           Generate a public key and a TLS ClientKeyExchange payload.
 *                  (Second function used by a TLS client for ECDH(E)-GOST.)
 *
 * \param ctx       ECDH-GOST context
 * \param pk_info   GOST PK information to use
 * \param olen      number of bytes actually written
 * \param buf       destination buffer
 * \param blen      size of destination buffer
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful, or an MBEDTLS_ERR_ECP_XXX error code
 */
int mbedtls_ecdh_gost_make_public( mbedtls_ecdh_gost_context *ctx,
                      const mbedtls_pk_info_t *pk_info,
                      size_t *olen, unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng );

/**
 * \brief           Parse and process a TLS ClientKeyExchange payload.
 *                  (Second function used by a TLS server for ECDH(E)-GOST.)
 *
 * \param ctx       ECDH-GOST context
 * \param pk_info   GOST PK information to use
 * \param buf       start of input buffer
 * \param blen      length of input buffer
 *
 * \return          0 if successful, or an MBEDTLS_ERR_ECP_XXX error code
 */
int mbedtls_ecdh_gost_read_public( mbedtls_ecdh_gost_context *ctx,
                      const mbedtls_pk_info_t *pk_info,
                      const unsigned char *buf, size_t blen );

/**
 * \brief           Derive and export the shared secret.
 *                  (Last function used by both TLS client en servers.)
 *
 * \param ctx       ECDH-GOST context
 * \param md_alg    MD for hashing coordinates
 * \param ukm       User keying material
 * \param ukm_len   UKM length
 * \param olen      number of bytes written
 * \param buf       destination buffer
 * \param blen      buffer length
 * \param f_rng     RNG function, see notes for \c mbedtls_ecdh_gost_compute_shared()
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful, or an MBEDTLS_ERR_ECP_XXX error code
 */
int mbedtls_ecdh_gost_calc_secret( mbedtls_ecdh_gost_context *ctx,
                      mbedtls_md_type_t md_alg,
                      const unsigned char *ukm, size_t ukm_len,
                      size_t *olen, unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng );

#ifdef __cplusplus
}
#endif

#endif /* ecdh_gost.h */
