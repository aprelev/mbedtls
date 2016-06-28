/**
 * \file ecgost.h
 *
 * \brief Elliptic curve GOST algorithms
 */
#ifndef MBEDTLS_ECGOST_H
#define MBEDTLS_ECGOST_H

#include "ecp.h"
#include "md.h"
#include "cipher.h"

/*
 * RFC 4357 page 28:
 *
 *     GostR3410-2001-PublicKey ::= OCTET STRING (SIZE (64)),
 *
 *     where first half of octet string is X_Q in little-endian format
 *     and second half is Y_Q in little-endian format
 *
 * http://tc26.ru/methods/recommendation/%D0%A2%D0%9A26CMS.pdf page 6-7:
 *
 *     GostR3410-2012-256-Signature ::= OCTET STRING (SIZE (64)),
 *     GostR3410-2012-512-Signature ::= OCTET STRING (SIZE (128)),
 *
 *     where first half of octet string is s in big-endian format
 *     and second half is r in big-endian format
 *
 * Size is at most
 *    ECP_MAX_BYTES for each of r (X_Q) and s (Y_Q),
 *    twice that + 1 (tag) + 2 (len) for the sequence
 * (assuming ECP_MAX_BYTES is less than 126 for r and s, total len <= 255 for the sequence)
 */
#if MBEDTLS_ECP_MAX_BYTES > 126
#error "MBEDTLS_ECP_MAX_BYTES bigger than expected, please fix MBEDTLS_ECGOST_MAX_LEN"
#endif
/** Maximum size of an ECGOST signature or public key in bytes */
#define MBEDTLS_ECGOST_MAX_LEN  ( 3 + 2 * MBEDTLS_ECP_MAX_BYTES )

/**
 * \brief           ECGOST context structure
 */
typedef struct
{
    mbedtls_ecp_keypair key;         /*!<  Key pair          */
    mbedtls_md_type_t   gost94_alg;  /*!<  GOST94 algorithm  */
    mbedtls_cipher_id_t gost89_alg;  /*!<  GOST89 algorithm  */
}
mbedtls_ecgost_context;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief           Compute GOST signature of a previously hashed message
 *
 * \note            The deterministic version is usually prefered.
 *
 * \param grp       ECP group
 * \param r         First output integer
 * \param s         Second output integer
 * \param d         Private signing key
 * \param buf       Message hash
 * \param blen      Length of buf
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful,
 *                  or a MBEDTLS_ERR_ECP_XXX or MBEDTLS_MPI_XXX error code
 */
int mbedtls_ecgost_sign( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           Verify GOST signature of a previously hashed message
 *
 * \param grp       ECP group
 * \param buf       Message hash
 * \param blen      Length of buf
 * \param Q         Public key to use for verification
 * \param r         First integer of the signature
 * \param s         Second integer of the signature
 *
 * \return          0 if successful,
 *                  MBEDTLS_ERR_ECP_BAD_INPUT_DATA if signature is invalid
 *                  or a MBEDTLS_ERR_ECP_XXX or MBEDTLS_MPI_XXX error code
 */
int mbedtls_ecgost_verify( mbedtls_ecp_group *grp,
                  const unsigned char *buf, size_t blen,
                  const mbedtls_ecp_point *Q, const mbedtls_mpi *r, const mbedtls_mpi *s);

/**
 * \brief           Compute GOST signature and write it to buffer,
 *                  serialized as defined in
 *                  http://tc26.ru/methods/recommendation/%D0%A2%D0%9A26CMS.pdf page 6-7
 *                  without OCTET STRING tag and length.
 *                  (Not thread-safe to use same context in multiple threads)
 *
 * \param ctx       ECGOST context
 * \param hash      Message hash
 * \param hlen      Length of hash
 * \param sig       Buffer that will hold the signature
 * \param slen      Length of the signature written
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \note            The "sig" buffer must be at least as large as twice the
 *                  size of the curve used, plus 3 (eg. 67 bytes if a 256-bit
 *                  curve is used). MBEDTLS_ECGOST_MAX_LEN is always safe.
 *
 * \return          0 if successful,
 *                  or a MBEDTLS_ERR_ECP_XXX, MBEDTLS_ERR_MPI_XXX or
 *                  MBEDTLS_ERR_ASN1_XXX error code
 */
int mbedtls_ecgost_write_signature( mbedtls_ecgost_context *ctx,
                           const unsigned char *hash, size_t hlen,
                           unsigned char *sig, size_t *slen,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng );

/**
 * \brief           Read and verify an GOST signature
 *
 * \param ctx       ECGOST context
 * \param hash      Message hash
 * \param hlen      Size of hash
 * \param sig       Signature to read and verify
 * \param slen      Size of sig
 *
 * \return          0 if successful,
 *                  MBEDTLS_ERR_ECP_BAD_INPUT_DATA if signature is invalid,
 *                  MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH if the signature is
 *                  valid but its actual length is less than siglen,
 *                  or a MBEDTLS_ERR_ECP_XXX or MBEDTLS_ERR_MPI_XXX error code
 */
int mbedtls_ecgost_read_signature( mbedtls_ecgost_context *ctx,
                          const unsigned char *hash, size_t hlen,
                          const unsigned char *sig, size_t slen );

/**
 * \brief           Export a point into unsigned binary data
 *
 * \param grp       Group to which the point should belong
 * \param P         Point to export
 * \param olen      Length of the actual output
 * \param buf       Output buffer
 * \param buflen    Length of the output buffer
 *
 * \return          0 if successful,
 *                  or MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL
 */
int mbedtls_ecgost_write_pubkey( const mbedtls_ecp_group *grp, const mbedtls_ecp_point *P,
                            size_t *olen, unsigned char *buf, size_t buflen );

/**
 * \brief           Import a point from unsigned binary data
 *
 * \param grp       Group to which the point should belong
 * \param P         Point to import
 * \param buf       Input buffer
 * \param ilen      Actual length of input
 *
 * \return          0 if successful,
 *                  MBEDTLS_ERR_ECP_BAD_INPUT_DATA if input is invalid,
 *                  MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed.
 *
 * \note            This function does NOT check that the point actually
 *                  belongs to the given group, see mbedtls_ecp_check_pubkey() for
 *                  that.
 */
int mbedtls_ecgost_read_pubkey( const mbedtls_ecp_group *grp, mbedtls_ecp_point *P,
                           const unsigned char *buf, size_t ilen );

/**
 * \brief           Generate an GOST keypair on the given curve
 *
 * \param ctx       ECGOST context in which the keypair should be stored
 * \param gid       Group (elliptic curve) to use. One of the various
 *                  MBEDTLS_ECP_DP_XXX macros depending on configuration.
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 on success, or a MBEDTLS_ERR_ECP_XXX code.
 */
int mbedtls_ecgost_genkey( mbedtls_ecgost_context *ctx, mbedtls_ecp_group_id gid,
                  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           Set an ECGOST context from an EC key pair
 *
 * \param ctx       ECGOST context to set
 * \param key       EC key to use
 *
 * \return          0 on success, or a MBEDTLS_ERR_ECP_XXX code.
 */
int mbedtls_ecgost_from_keypair( mbedtls_ecgost_context *ctx, const mbedtls_ecp_keypair *key );

/**
 * \brief           Initialize context
 *
 * \param ctx       Context to initialize
 */
void mbedtls_ecgost_init( mbedtls_ecgost_context *ctx );

/**
 * \brief           Free context
 *
 * \param ctx       Context to free
 */
void mbedtls_ecgost_free( mbedtls_ecgost_context *ctx );

#ifdef __cplusplus
}
#endif

#endif /* ecgost.h */
