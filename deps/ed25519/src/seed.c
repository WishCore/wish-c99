#include "ed25519.h"

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#if defined(COMPILING_FOR_ESP8266)
#include "osapi.h"
#else
#include <stdio.h>
#endif
#endif

int ed25519_create_seed(unsigned char *seed) {
#ifdef _WIN32
    HCRYPTPROV prov;

    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))  {
        return 1;
    }

    if (!CryptGenRandom(prov, 32, seed))  {
        CryptReleaseContext(prov, 0);
        return 1;
    }

    CryptReleaseContext(prov, 0);
#else
#if defined(COMPILING_FOR_ESP8266)
    os_get_random(seed, 32);
#else
    /* Your basic Linux implementation which reads from 'user random
     * source' */
    FILE *f = fopen("/dev/urandom", "rb");

    if (f == NULL) {
        return 1;
    }

    size_t read_cnt = fread(seed, 1, 32, f);
    if (read_cnt == 0) {
        return 2;
    }
    fclose(f);
#endif
#endif

    return 0;
}

