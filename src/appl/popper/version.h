/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 *
 * static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
 * based on @(#)version.h	2.6  4/3/91
 *
 */

/*
 *  Current version of this POP implementation
 */
#ifdef KERBEROS
#ifdef KRB5
#define VERSION         "1.831beta Kerberos5"
#else
#define VERSION         "1.831beta KerberosIV"
#endif
#else
#define VERSION         "1.831beta"
#endif
