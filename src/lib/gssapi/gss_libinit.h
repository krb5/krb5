#ifndef KRB5_LIBINIT_H
#define KRB5_LIBINIT_H

#include "gssapi.h"

OM_uint32 gssint_initialize_library (void);
void gssint_cleanup_library (void);

#endif /* KRB5_LIBINIT_H */
