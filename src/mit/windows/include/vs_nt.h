#include "mitcpyrt.h"

/* il 7/24/95 -- adding nt */

#ifndef _vs_nt_h_
#define _ve_nt_h_

#ifdef _WIN32



/* the #undef instructions are not needed, but left to avoid possible
 * conflicts with windows.h's similar definitions */

#undef FAR
#undef far
#undef _far
#undef __far

#define FAR
#define far
#define _far
#define __far

#undef _osmajor
#undef _osmanor
#define _osmajor _winmajor
#define _osminor _winminor

#undef _fstrlen
#undef _fstrcat
#define _fstrlen strlen
#define _fstrcat strcat

#include <stdlib.h>


#undef WINDOWS
#define WINDOWS

#endif
#endif
