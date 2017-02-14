#ifndef BASEDEFS_H
#define BASEDEFS_H

#if (defined(_WIN32) || defined(_WIN64))
#	if (defined(WISH_NODLL) || defined(WISH_STATIC))  
#		define WISH_EXPORT
#	else
#		ifdef WISH_API_EXPORTS
#			define WISH_EXPORT __declspec(dllexport)
#		else
#			define WISH_EXPORT __declspec(dllimport)
#		endif
#	endif
#else
#   if __GNUC__ >= 4
#       define WISH_EXPORT __attribute__ ((visibility("default")))
#   else
#       define WISH_EXPORT
#   endif
#endif
    

#endif /* BASEDEFS_H */

