/**
 * \file ecdh_gost.h
 *
 * \brief Elliptic curve GOST Diffie-Hellman
 */
#ifndef MBEDTLS_ECDH_GOST_H
#define MBEDTLS_ECDH_GOST_H

#include "ecp.h"
#include "md.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief           ECDH-GOST context structure
 */
typedef struct
{
    mbedtls_ecp_group grp;      /*!<  elliptic curve used                           */
    mbedtls_mpi d;              /*!<  our secret value (private key)                */
    mbedtls_ecp_point Q;        /*!<  our public value (public key)                 */
    mbedtls_ecp_point Qp;       /*!<  peer's public value (public key)              */
    mbedtls_ecp_point P;        /*!<  shared secret                                 */
    mbedtls_md_type_t md_alg;   /*!<  message digest for hashing P coordinates      */
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
 * \param P         Destination elliptic curve point (shared secret)
 * \param Q         Public key from other party
 * \param d         Our secret exponent (private key)
 * \param ukm       User keying material
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
int mbedtls_ecdh_gost_compute_shared( mbedtls_ecp_group *grp, mbedtls_ecp_point *P,
                         const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                         const mbedtls_mpi *ukm,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng );

/**
 * \brief           Initialize context
 *
 * \param ctx       Context to initialize
 * \param md_alg    Message digest for hashing shared secret coordinates
 */
void mbedtls_ecdh_gost_init( mbedtls_ecdh_gost_context *ctx,
                             mbedtls_md_type_t md_alg );

/**
 * \brief           Free context
 *
 * \param ctx       Context to free
 */
void mbedtls_ecdh_gost_free( mbedtls_ecdh_gost_context *ctx );

/**
 * \brief           Derive and export the shared secret.
 *                  (Last function used by both TLS client en servers.)
 *
 * \param ctx       ECDH-GOST context
 * \param ukm       8-byte user keying material
 * \param olen      number of bytes written
 * \param buf       destination buffer
 * \param blen      buffer length
 * \param f_rng     RNG function, see notes for \c mbedtls_ecdh_gost_compute_shared()
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful, or an MBEDTLS_ERR_ECP_XXX error code
 */
int mbedtls_ecdh_gost_calc_secret( mbedtls_ecdh_gost_context *ctx,
                      unsigned char ukm[8], size_t *olen,
                      unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng );

#ifdef __cplusplus
}
#endif

#endif /* ecdh_gost.h */
