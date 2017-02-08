/**
 * Useful linker attributes for the Wish project
 */

/* Declaration specifier for moving an array to flash */

#ifdef COMPILING_FOR_ESP8266
/* Declaration specific for ESP8266 */
#define WISH_ROM_DECL_SPEC __attribute__((section(".irom0.text"))) __attribute__((aligned(4)))
#else
/* It can be empty if you do not have special needs - as you probably
+ * not have if you are on a large system such a "normal computer"  */
#define WISH_ROM_DECL_SPEC
#endif


