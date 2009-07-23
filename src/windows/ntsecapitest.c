/* Simple program to show what is in ntsecapi.h.
   Compile -P to generate preprocessor output.
 */

#define _WIN32_WINNT 0x0600
#include "ntsecapi.h"

#ifdef TRUST_ATTRIBUTE_TRUST_USES_AES_KEYS
VISTA_SDK_VERSION
#else
NT_SDK_VERSION
#endif
