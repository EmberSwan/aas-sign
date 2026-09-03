#ifndef AAS_SIGN_MBEDTLS_USER_CONFIG_H
#define AAS_SIGN_MBEDTLS_USER_CONFIG_H

// TLS 1.3 uses PSA global state, and signing workers use it concurrently.
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_PTHREAD

#endif
