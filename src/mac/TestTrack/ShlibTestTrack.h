/*
 *   Copyright (C) 1997 by the Massachusetts Institute of Technology
 *   All rights reserved.
 *
 *   For copying and distribution information, please see the file
 *   COPYRIGHT.
 */

#ifndef __SHLIB_TESTTRACK__
#define __SHLIB_TESTTRACK__

#include <CodeFragments.h>

/*	Special version of TestTrack for shared libraries -- uses calling application's
	version information */

OSErr ShlibTestTrack(CFragInitBlockPtr ibp);

#endif /* __SHLIB_TESTTRACK__ */