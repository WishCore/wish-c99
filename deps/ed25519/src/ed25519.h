#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>

#if defined(_WIN32)
    #if defined(ED25519_BUILD_DLL)
        #define ED25519_DECLSPEC __declspec(dllexport)
    #elif defined(ED25519_DLL)
        #define ED25519_DECLSPEC __declspec(dllimport)
    #else
        #define ED25519_DECLSPEC
    #endif
    #define ED25519_RODATA_DECLSPEC 
#elif defined(COMPILING_FOR_ESP8266)
    /* A declaration specifier which will make statically allocated
     * array to be moved to flash (instead of RAM) */
    #define ED25519_RODATA_DECLSPEC __attribute__((section(".irom0.text"))) __attribute__((aligned(4)))
    /* Note that we do not need to specify any special declration
     * specifiers for the ED25519 functions, because they are already
     * placed to flash by our special LD script */
    #define ED25519_DECLSPEC
#else
    #define ED25519_RODATA_DECLSPEC 
    #define ED25519_DECLSPEC
#endif


#ifdef __cplusplus
extern "C" {
#endif

int ED25519_DECLSPEC ed25519_create_seed(unsigned char *seed);
void ED25519_DECLSPEC ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
void ED25519_DECLSPEC ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *private_key);
int ED25519_DECLSPEC ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);
void ED25519_DECLSPEC ed25519_add_scalar(unsigned char *public_key, unsigned char *private_key, const unsigned char *scalar);
void ED25519_DECLSPEC ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);


#ifdef __cplusplus
}
#endif

#endif
