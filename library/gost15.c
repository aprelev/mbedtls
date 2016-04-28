/*
 *  GOST 34.12-2015 implementation
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_GOST15_C)

#include <memory.h>

#include "mbedtls/gost15.h"

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

/* Implementation goes here. */

typedef void ISOCompilerHappiness_t;

#endif /* MBEDTLS_GOST15_C */
