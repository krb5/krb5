/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Configuration file for Kerberos V5 library.
 * This config file works for IBM RT/PC running AOS 4.3 and VAX running 4.3BSD
 */

#include <krb5/copyright.h>

#ifndef KRB5_CONFIG__
#define KRB5_CONFIG__

#if defined(vax) || defined(__vax__)
#define BITS32
#endif

#if defined(ibm032) || defined(__ibm032__)
#define BITS32
#endif

#if defined(mips) || defined(__mips__)
#define BITS32
#endif

#define PROVIDE_DES_CBC_CRC
#define PROVIDE_CRC32
#define PROVIDE_DES_CBC_CKSUM

#define DEFAULT_PWD_STRING1 "Enter password:"
#define DEFAULT_PWD_STRING2 "Re-enter password for verification:"

#endif /* KRB5_CONFIG__ */
