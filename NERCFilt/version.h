// version.h - single source of truth for the NERCFilt version.
// The release workflow refuses to publish a tag that does not match.
//
// Part of NERCFilt.  SPDX-License-Identifier: MIT

#pragma once

#define NERCFILT_VERSION_MAJOR 2
#define NERCFILT_VERSION_MINOR 0
#define NERCFILT_VERSION_PATCH 0

#define NERCFILT_STRINGIFY2(x) #x
#define NERCFILT_STRINGIFY(x) NERCFILT_STRINGIFY2(x)
#define NERCFILT_VERSION_STRING                                                \
  NERCFILT_STRINGIFY(NERCFILT_VERSION_MAJOR)                                   \
  "." NERCFILT_STRINGIFY(NERCFILT_VERSION_MINOR) "." NERCFILT_STRINGIFY(       \
      NERCFILT_VERSION_PATCH)
