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
 * definitions to widen prototype types temporarily...also see <krb5/narrow.h>
 * and <krb5/base-defs.h>
 */

#ifndef NARROW_PROTOTYPES

/* WARNING ! ! !
   Only include declarations in source files between this file and narrow.h
   if none of the functions declared therein uses pointers to any of the
   narrowed types.  If you're not careful, you could widen the pointed-to
   object, which is WRONG.
 */

/* only needed if not narrow, i.e. wide */

#define krb5_boolean	int
#define krb5_msgtype	int
#define krb5_kvno	int

/* these are unsigned shorts, but promote to signed ints.  Ick. */
#define krb5_addrtype	int
#define krb5_keytype	int
#define krb5_enctype	int
#define krb5_cksumtype	int
#define krb5_authdatatype	int

#endif /* not NARROW_PROTOTYPES */
