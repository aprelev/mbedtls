/**
 * \file gost89.h
 *
 * \brief GOST 28147-89 block cipher
 */
#ifndef MBEDTLS_GOST89_H
#define MBEDTLS_GOST89_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_GOST89_ENCRYPT     1
#define MBEDTLS_GOST89_DECRYPT     0
#define MBEDTLS_GOST89_BLOCKSIZE   8

#define MBEDTLS_ERR_GOST89_INVALID_INPUT_LENGTH              -0x0042  /**< Invalid data input length. */

#define MBEDTLS_GOST89_KEY_SIZE    32

#if !defined(MBEDTLS_GOST89_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Available S-Boxes
 */
typedef enum
{
    MBEDTLS_GOST89_SBOX_TEST = 0,
    MBEDTLS_GOST89_SBOX_A,
    MBEDTLS_GOST89_SBOX_Z,
} mbedtls_gost89_sbox_id_t;

/**
 * \brief          GOST89 context structure
 */
typedef struct
{
    uint32_t rk[8];                   /*!<  round keys                */
    mbedtls_gost89_sbox_id_t sbox_id; /*!<  S-Box                     */
    size_t processed_len;             /*!<  number of processed bytes */
} mbedtls_gost89_context;

/**
 * \brief          Initialize GOST89 context
 *
 * \param ctx      GOST89 context to be initialized
 * \param sbox_id  S-Box identifier
 */
void mbedtls_gost89_init( mbedtls_gost89_context *ctx,
                          mbedtls_gost89_sbox_id_t sbox_id );

/**
 * \brief          Clear GOST89 context
 *
 * \param ctx      GOST89 context to be cleared
 */
void mbedtls_gost89_free( mbedtls_gost89_context *ctx );

/**
 * \brief          GOST89 key schedule
 *
 * \param ctx      GOST89 context to be initialized
 * \param key      32-byte secret key
 *
 * \return         0
 */
int mbedtls_gost89_setkey( mbedtls_gost89_context *ctx,
                           const unsigned char key[MBEDTLS_GOST89_KEY_SIZE] );

/**
 * \brief          GOST89-ECB block encryption/decryption
 *
 * \param ctx      GOST89 context
 * \param mode     MBEDTLS_GOST89_ENCRYPT or MBEDTLS_GOST89_DECRYPT
 * \param input    8-byte input block
 * \param output   8-byte output block
 *
 * \return         0 if successful
 */
int mbedtls_gost89_crypt_ecb( mbedtls_gost89_context *ctx,
                              int mode,
                              const unsigned char input[MBEDTLS_GOST89_BLOCKSIZE],
                              unsigned char output[MBEDTLS_GOST89_BLOCKSIZE] );

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/**
 * \brief          GOST89-CBC buffer encryption/decryption
 *                 Length should be a multiple of the block
 *                 size (8 bytes)
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      GOST89 context
 * \param mode     MBEDTLS_GOST89_ENCRYPT or MBEDTLS_GOST89_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful, or MBEDTLS_ERR_GOST89_INVALID_INPUT_LENGTH
 */
int mbedtls_gost89_crypt_cbc( mbedtls_gost89_context *ctx,
                              int mode,
                              size_t length,
                              unsigned char iv[MBEDTLS_GOST89_BLOCKSIZE],
                              const unsigned char *input,
                              unsigned char *output );
#endif /* MBEDTLS_CIPHER_MODE_CBC */

/**
 * \brief           Internal GOST89 block encryption function
 *                  (Only exposed to allow overriding it,
 *                  see MBEDTLS_GOST89_ENCRYPT_ALT)
 *
 * \param ctx       GOST89 context
 * \param input     Plaintext block
 * \param output    Output (ciphertext) block
 */
void mbedtls_gost89_encrypt( mbedtls_gost89_context *ctx,
                             const unsigned char input[MBEDTLS_GOST89_BLOCKSIZE],
                             unsigned char output[MBEDTLS_GOST89_BLOCKSIZE] );

/**
 * \brief           Internal GOST89 block decryption function
 *                  (Only exposed to allow overriding it,
 *                  see MBEDTLS_GOST89_DECRYPT_ALT)
 *
 * \param ctx       GOST89 context
 * \param input     Ciphertext block
 * \param output    Output (plaintext) block
 */
void mbedtls_gost89_decrypt( mbedtls_gost89_context *ctx,
                             const unsigned char input[MBEDTLS_GOST89_BLOCKSIZE],
                             unsigned char output[MBEDTLS_GOST89_BLOCKSIZE] );

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_GOST89_ALT */
#include "gost89_alt.h"
#endif /* MBEDTLS_GOST89_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_gost89_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* gost89.h */
