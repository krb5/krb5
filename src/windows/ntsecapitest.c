/* Simple program to show what is in ntsecapi.h.
   Compile -P to generate preprocessor output.
 */

#include "ntsecapi.h"

#ifdef TRUST_ATTRIBUTE_TRUST_USES_AES_KEYS 
VISTA_SDK_VERSION
#else
NT_SDK_VERSION
#endif