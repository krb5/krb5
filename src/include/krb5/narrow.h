/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * definitions to un-widen prototype types...see <krb5/widen.h>
 * and <krb5/base-defs.h>
 */

#ifndef NARROW_PROTOTYPES

/* only needed if not narrow, i.e. wide */

#undef krb5_boolean
#undef krb5_msgtype
#undef krb5_kvno

#undef krb5_addrtype
#undef krb5_keytype
#undef krb5_enctype
#undef krb5_cksumtype
#undef krb5_authdatatype

#endif /* not NARROW_PROTOTYPES */
