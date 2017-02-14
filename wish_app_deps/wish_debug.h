#ifndef WISH_DEBUG_H
#define WISH_DEBUG_H

#include "wish_platform.h"
#include <stdarg.h>
#include "cbson.h"

#ifdef COMPILING_FOR_ESP8266
int os_printf_plus(const char *format, ...)  __attribute__ ((format (printf, 1, 2)));
#endif

/* Log levels
 *
 * 1: informative
 * ...
 * 10: critical error
 *
 */

/* Informative prints */
#define LOG_TRIVIAL     0
#define LOG_INFO        1
#define LOG_DEBUG       1

/* Messages from the on-wire protocol */
#define LOG_WIRE         5

/* Critical error */
#define LOG_CRITICAL    9
/* Debug level for messages which will be printed in any case */
#define LOG_NORMAL      10


/* The logging threshold. Any log message with a lower threshold will
 * not be printed out */
#define LOG_THRESHOLD   9

void wish_debug_set_stream(unsigned int stream, bool enable);

void wish_debug_printf(int stream, const char* format, ...);

/* Debug macros: See https://gcc.gnu.org/onlinedocs/gcc/Variadic-Macros.html */
/* Wish debug message with EOL chars at the end.
 * NOTE: The ## __VA_ARGS__ thing is something proprietary to GCC. 
 * This means that we should consider moving this to be function instead. */

#ifdef RELEASE_BUILD
  #define WISHDEBUG(lvl, format, ...) do {} while (0);
#else
  #ifndef COMPILING_FOR_ESP8266
  #define WISHDEBUG(lvl, format, ...) \
    if (lvl >= LOG_THRESHOLD) wish_platform_printf(format "\n\r", ## __VA_ARGS__)
    //wish_debug_printf(lvl, format "\n", ## __VA_ARGS__);
  #else
  /* Special version needed for ESP8266 for now - this is just silly */
  #define WISHDEBUG(lvl, format, ...) \
      if (lvl >= LOG_THRESHOLD) os_printf_plus(format "\n\r", ## __VA_ARGS__);

  #endif
#endif


#ifdef RELEASE_BUILD
  #define WISHDEBUG2(lvl, format, ...) do {} while (0);
#else
  /* Wish debug message with no EOL chars, useful when printing out arrays */
  #ifndef COMPILING_FOR_ESP8266
  #define WISHDEBUG2(lvl, format, ...) \
    if (lvl >= LOG_THRESHOLD) wish_platform_printf(format, ## __VA_ARGS__)
    //wish_debug_printf(lvl, format, ## __VA_ARGS__);
  #else
  /* Special version needed for ESP8266 for now - this is just silly */
  #define WISHDEBUG2(lvl, format, ...) \
      if (lvl >= LOG_THRESHOLD) os_printf_plus(format, ## __VA_ARGS__);
  #endif
#endif

/* Print out an array on the terminal */
void wish_debug_print_array(int log_lvl, char* title, uint8_t* array, uint8_t len);


/* Platform-dependent function to immediately cease all processing and
 * just wait performing only the minimum amount of activity, such as
 * watchdog feed etc. 
 * This is useful to debug problems which would othervise lead to
 * watchdog resets. */
void wish_debug_die();


void elem_visitor(char *elem_name, uint8_t elem_type, uint8_t *elem, uint8_t depth);

#endif
