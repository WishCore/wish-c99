#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// This should be defined in makefile using 
//    git describe --abbrev=4 --always --tags
// and 
//    if ! [ -z "$(git status --porcelain)" ]; then echo "-dirty"; fi
//
// resulting in:
//    v0.0.16-alpha-26-g3df2
//    v0.0.16-alpha-26-g3df2-dirty
// or a clean release:
//    v0.4.0

#ifndef MIST_API_VERSION_STRING
#define MIST_API_VERSION_STRING "rogue-build"
#endif
    
#ifdef __cplusplus
}
#endif
