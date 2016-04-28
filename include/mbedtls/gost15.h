/**
 * \file gost15.h
 *
 * \brief GOST 34.12-2015 block cipher
 */
#ifndef MBEDTLS_GOST15_H
#define MBEDTLS_GOST15_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_GOST15_ENCRYPT     1
#define MBEDTLS_GOST15_DECRYPT     0
#define MBEDTLS_GOST15_BLOCKSIZE   16

#define MBEDTLS_ERR_GOST15_INVALID_INPUT_LENGTH              -0x0042  /**< Invalid data input length. */

#define MBEDTLS_GOST15_KEY_SIZE    32


#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif

#endif /* gost15.h */