/*
 *	KerberosHeaders.pch
 *
 *	Script to generate the 'MacHeaders<xxx>' precompiled header for Metrowerks C/C++.
 *  Copyright © 1993 metrowerks inc.  All rights reserved.
 * Modified for Kerberos5 Mac port to include compile options
 */

/*
 * Add the compile flag switches for kerberos compile
 */
#define KRB5 1

#define _MACINTOSH
#define SIZEOF_INT 4
#define SIZEOF_SHORT 2
#define ENOMEM -1
#define HAVE_SRAND
#define NO_PASSWORD
#define HAS_LABS
#define ANSI_STDIO
#ifndef _SIZET
typedef unsigned int size_t;
#define _SIZET

#include <unix.h>
#include <ctype.h>

#endif

#define PROVIDE_RSA_MD4
#define PROVIDE_RSA_MD5
#define PROVIDE_CRC32
#define PROVIDE_DES_CBC_CKSUM
#define PROVIDE_DES_CBC_CRC
#define PROVIDE_DES_CBC_MD5
#define PROVIDE_DES_CBC_RAW
#define PROVIDE_DES3_CBC_MD5
#define PROVIDE_DES3_CBC_RAW


#define NO_SYS_TYPES_H
#define NO_SYS_STAT_H

/*
 * Rename various socket type operations to avoid cluttering the namespace
 */
#define socket			krb5_socket
#define closesocket		krb5_closesocket
#define connect			krb5_connect
#define bind			krb5_bind
#define send			krb5_send
#define recv			krb5_recv
#define sendto			krb5_sendto
#define select			krb5_select
#define recvfrom		krb5_recvfrom
#define inet_ntoa		krb5_inet_ntoa
#define gethostbyname	krb5_gethostbyname
#define gethostbyaddr	krb5_gethostbyaddr
#define gethostname		krb5_gethostname
#define getsockname		krb5_getsockname
#define getmyipaddr		krb5_getmyipaddr

#define OpenOurRF 		krb5_OpenOurRF
#define OpenResolver	krb5_OpenResolver
#define CloseResolver	krb5_CloseResolver
#define StrToAddr		krb5_StrToAddr
#define AddrToStr		krb5_AddrToStr
#define EnumCache		krb5_EnumCache
#define AddrToName		krb5_AddrToName
#define dnr				krb5_dnr
#define codeHndl		krb5_codeHndl

typedef int datum;

//jfm need to reimplement
#define mktemp(a)

enum {
ENOENT = -43,
EPERM,
EACCES,
EISDIR,
ENOTDIR,
ELOOP,
ETXTBSY,
EBUSY,
EROFS,
EINVAL,
EEXIST,
EFAULT,
EBADF,
ENAMETOOLONG,
EWOULDBLOCK,
EDQUOT,
ENOSPC,
EIO,
ENFILE,
EMFILE,
ENXIO
};
#define HAVE_STRFTIME 1
#define MAXPATHLEN 255
#define HAVE_SYSLOG_H 1
#define HAVE_STDLIB_H 1
