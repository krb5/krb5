/*
 * Copyright (C) 2001 by the Massachusetts Institute of Technology,
 * Cambridge, MA, USA.  All Rights Reserved.
 * 
 * This software is being provided to you, the LICENSEE, by the 
 * Massachusetts Institute of Technology (M.I.T.) under the following 
 * license.  By obtaining, using and/or copying this software, you agree 
 * that you have read, understood, and will comply with these terms and 
 * conditions:  
 * 
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify and distribute 
 * this software and its documentation for any purpose and without fee or 
 * royalty is hereby granted, provided that you agree to comply with the 
 * following copyright notice and statements, including the disclaimer, and 
 * that the same appear on ALL copies of the software and documentation, 
 * including modifications that you make for internal use or for 
 * distribution:
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS", AND M.I.T. MAKES NO REPRESENTATIONS 
 * OR WARRANTIES, EXPRESS OR IMPLIED.  By way of example, but not 
 * limitation, M.I.T. MAKES NO REPRESENTATIONS OR WARRANTIES OF 
 * MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF 
 * THE LICENSED SOFTWARE OR DOCUMENTATION WILL NOT INFRINGE ANY THIRD PARTY 
 * PATENTS, COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS.   
 * 
 * The name of the Massachusetts Institute of Technology or M.I.T. may NOT 
 * be used in advertising or publicity pertaining to distribution of the 
 * software.  Title to copyright in this software and any associated 
 * documentation shall at all times remain with M.I.T., and USER agrees to 
 * preserve same.
 *
 * Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.  
 */

#ifndef FAI_DEFINED
#define FAI_DEFINED
#include "port-sockets.h"
#include "socket-utils.h"

#ifndef FAI_PREFIX
# error "FAI_PREFIX must be defined when fake-addrinfo.h is included"
#endif

#define FAI_CONCAT(A,B) FAI_CONCAT2(A,B)
#define FAI_CONCAT2(A,B) A ## B

/* Various C libraries have broken implementations of getaddrinfo.  */
#undef fixup_addrinfo
#define fixup_addrinfo FAI_CONCAT(FAI_PREFIX, _fixup_addrinfo)

extern void fixup_addrinfo (struct addrinfo *ai);

#if !defined (HAVE_GETADDRINFO) || defined (BROKEN_GETADDRINFO)

#undef  getaddrinfo
#define getaddrinfo	FAI_CONCAT(FAI_PREFIX, _fake_getaddrinfo)
#undef  getnameinfo
#define getnameinfo	FAI_CONCAT(FAI_PREFIX, _fake_getnameinfo)
#undef  freeaddrinfo
#define freeaddrinfo	FAI_CONCAT(FAI_PREFIX, _fake_freeaddrinfo)
#undef  gai_strerror
#define gai_strerror	FAI_CONCAT(FAI_PREFIX, _fake_gai_strerror)
#undef  addrinfo
#define addrinfo	FAI_CONCAT(FAI_PREFIX, _fake_addrinfo)

struct addrinfo {
    int ai_family;		/* PF_foo */
    int ai_socktype;		/* SOCK_foo */
    int ai_protocol;		/* 0, IPPROTO_foo */
    int ai_flags;		/* AI_PASSIVE etc */
    size_t ai_addrlen;		/* real length of socket address */
    char *ai_canonname;		/* canonical name of host */
    struct sockaddr *ai_addr;	/* pointer to variable-size address */
    struct addrinfo *ai_next;	/* next in linked list */
};

#undef	AI_PASSIVE
#define	AI_PASSIVE	0x01
#undef	AI_CANONNAME
#define	AI_CANONNAME	0x02
#undef	AI_NUMERICHOST
#define	AI_NUMERICHOST	0x04
/* N.B.: AI_V4MAPPED, AI_ADDRCONFIG, AI_ALL, and AI_DEFAULT are part
   of the spec for getipnodeby*, and *not* part of the spec for
   getaddrinfo.  Don't use them!  */
#undef	AI_V4MAPPED
#define	AI_V4MAPPED	eeeevil!
#undef	AI_ADDRCONFIG
#define	AI_ADDRCONFIG	eeeevil!
#undef	AI_ALL
#define	AI_ALL		eeeevil!
#undef	AI_DEFAULT
#define AI_DEFAULT	eeeevil!

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif
#ifndef NI_MAXSERV
#define NI_MAXSERV 32
#endif

#undef	NI_NUMERICHOST
#define NI_NUMERICHOST	0x01
#undef	NI_NUMERICSERV
#define NI_NUMERICSERV	0x02
#undef	NI_NAMEREQD
#define NI_NAMEREQD	0x04
#undef	NI_DGRAM
#define NI_DGRAM	0x08
#undef	NI_NOFQDN
#define NI_NOFQDN	0x10


#undef  EAI_ADDRFAMILY
#define EAI_ADDRFAMILY	1
#undef  EAI_AGAIN
#define EAI_AGAIN	2
#undef  EAI_BADFLAGS
#define EAI_BADFLAGS	3
#undef  EAI_FAIL
#define EAI_FAIL	4
#undef  EAI_FAMILY
#define EAI_FAMILY	5
#undef  EAI_MEMORY
#define EAI_MEMORY	6
#undef  EAI_NODATA
#define EAI_NODATA	7
#undef  EAI_NONAME
#define EAI_NONAME	8
#undef  EAI_SERVICE
#define EAI_SERVICE	9
#undef  EAI_SOCKTYPE
#define EAI_SOCKTYPE	10
#undef  EAI_SYSTEM
#define EAI_SYSTEM	11

int getaddrinfo (const char *name, const char *serv,
		 const struct addrinfo *hint, struct addrinfo **result);

int getnameinfo (const struct sockaddr *addr, socklen_t len,
		 char *host, size_t hostlen,
		 char *service, size_t servicelen,
		 int flags);

void freeaddrinfo (struct addrinfo *ai);

char *gai_strerror (int code);

#define HAVE_FAKE_GETADDRINFO
#define HAVE_GETADDRINFO
#undef  HAVE_GETNAMEINFO
#define HAVE_GETNAMEINFO

#endif /* HAVE_GETADDRINFO */

/* Fudge things on older gai implementations.  */
/* AIX 4.3.3 is based on RFC 2133; no AI_NUMERICHOST.  */
#ifndef AI_NUMERICHOST
# define AI_NUMERICHOST 0
#endif

#endif /* FAI_DEFINED */
