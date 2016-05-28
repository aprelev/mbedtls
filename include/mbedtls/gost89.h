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
#define MBEDTLS_GOST89_KEY_SIZE    32

#define MBEDTLS_ERR_GOST89_INVALID_INPUT_LENGTH              -0x007E  /**< Invalid data input length. */

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
    MBEDTLS_GOST89_SBOX_TEST = 0, /**< 1.2.643.2.2.31.0    */
    MBEDTLS_GOST89_SBOX_A,        /**< 1.2.643.2.2.31.1    */
    MBEDTLS_GOST89_SBOX_Z,        /**< 1.2.643.7.1.2.5.1.1 */
} mbedtls_gost89_sbox_id_t;

typedef enum
{
    MBEDTLS_GOST89_KEY_MESHING_NONE = 0,  /**< not use key meshing                  */
    MBEDTLS_GOST89_KEY_MESHING_CRYPTOPRO, /**< CryptoPro Key Meshing (see RFC 4357) */
} mbedtls_gost89_key_meshing_t;

/**
 * \brief          GOST89 context structure
 */
typedef struct
{
    uint32_t rk[8];                           /*!< round keys                                               */
    mbedtls_gost89_sbox_id_t sbox_id;         /*!< S-Box identifier                                         */
    mbedtls_gost89_key_meshing_t key_meshing; /*!< key meshing type                                         */
    size_t processed_len;                     /*!< number of processed bytes (for CNT mode only)            */
    int iv_encrypted;                         /*!< flag indicates that IV was encrypted (for CNT mode only) */
} mbedtls_gost89_context;

/**
 * \brief          GOST89-MAC context structure
 */
typedef struct
{
    uint32_t rk[8];                                          /*!< round keys                 */
    mbedtls_gost89_sbox_id_t sbox_id;                        /*!< S-Box identifier           */
    unsigned char buffer[MBEDTLS_GOST89_BLOCKSIZE];          /*!< data block being processed */
    unsigned char encrypted_block[MBEDTLS_GOST89_BLOCKSIZE]; /*!< previous encrypted block   */
    size_t processed_len;                                    /*!< number of processed bytes  */
} mbedtls_gost89_mac_context;

/**
 * \brief             Initialize GOST89 context
 *
 * \param ctx         GOST89 context to be initialized
 * \param sbox_id     S-Box identifier
 * \param key_meshing key meshing to use
 */
void mbedtls_gost89_init( mbedtls_gost89_context *ctx,
                          mbedtls_gost89_sbox_id_t sbox_id,
                          mbedtls_gost89_key_meshing_t key_meshing );

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
 * \return         0 if successful
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

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/**
 * \brief               GOST89-CNT buffer encryption/decryption
 *
 * Warning: You have to keep the maximum use of your counter in mind!
 *
 * \param ctx           GOST89 context
 * \param length        The length of the data
 * \param nc_off        The offset in the current stream_block (for resuming
 *                      within current cipher stream). The offset pointer to
 *                      should be 0 at the start of a stream.
 * \param nonce_counter The 64-bit nonce and counter.
 * \param stream_block  The saved stream-block for resuming. Is overwritten
 *                      by the function.
 * \param input         The input data stream
 * \param output        The output data stream
 *
 * \return              0 if successful
 */
int mbedtls_gost89_crypt_cnt( mbedtls_gost89_context *ctx,
                              size_t length,
                              size_t *nc_off,
                              unsigned char nonce_counter[MBEDTLS_GOST89_BLOCKSIZE],
                              unsigned char stream_block[MBEDTLS_GOST89_BLOCKSIZE],
                              const unsigned char *input,
                              unsigned char *output );
#endif /* MBEDTLS_CIPHER_MODE_CTR */

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

/**
 * \brief          Initialize GOST89-MAC context
 *
 * \param ctx      GOST89-MAC context to be initialized
 * \param sbox_id  S-Box identifier
 */
void mbedtls_gost89_mac_init( mbedtls_gost89_mac_context *ctx,
                              mbedtls_gost89_sbox_id_t sbox_id );

/**
 * \brief          Clear GOST89-MAC context
 *
 * \param ctx      GOST89-MAC context to be cleared
 */
void mbedtls_gost89_mac_free( mbedtls_gost89_mac_context *ctx );

/**
 * \brief          GOST89-MAC key schedule
 *
 * \param ctx      GOST89-MAC context to be initialized
 * \param key      32-byte secret key
 *
 * \return         0 if successful
 */
int mbedtls_gost89_mac_setkey( mbedtls_gost89_mac_context *ctx,
                               const unsigned char key[MBEDTLS_GOST89_KEY_SIZE] );

/**
 * \brief          Clone (the state of) a GOST89-MAC context
 *
 * \param dst      The destination context
 * \param src      The context tostate be cloned
 */
void mbedtls_gost89_mac_clone( mbedtls_gost89_mac_context *dst,
                               const mbedtls_gost89_mac_context *src );

/**
 * \brief          GOST89-MAC context setup
 *
 * \param ctx      context to be initialized
 */
void mbedtls_gost89_mac_starts( mbedtls_gost89_mac_context *ctx );

/**
 * \brief          GOST89-MAC process buffer
 *
 * \param ctx      GOST89-MAC context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void mbedtls_gost89_mac_update( mbedtls_gost89_mac_context *ctx, const unsigned char *input,
                                size_t ilen );

/**
 * \brief          GOST89-MAC final digest
 *
 * \param ctx      GOST89-MAC context
 * \param output   GOST89-MAC checksum result
 */
void mbedtls_gost89_mac_finish( mbedtls_gost89_mac_context *ctx, unsigned char output[4] );

/* Internal use */
void mbedtls_gost89_mac_process( mbedtls_gost89_mac_context *ctx,
                                 const unsigned char data[MBEDTLS_GOST89_BLOCKSIZE] );

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
 * \brief          Output = GOST89-MAC( input buffer )
 *
 * \param sbox_id  S-Box identifier
 * \param key      32-byte secret key
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   GOST89-MAC checksum result
 */
void mbedtls_gost89_mac( mbedtls_gost89_sbox_id_t sbox_id,
                         const unsigned char key[MBEDTLS_GOST89_KEY_SIZE],
                         const unsigned char *input, size_t ilen,
                         unsigned char output[4] );

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
