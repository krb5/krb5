#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

/* Some useful stuff cross-platform.  */

/* for HAVE_SOCKLEN_T, KRB5_USE_INET6, HAVE_SA_LEN */
#include "krb5/autoconf.h"

/* Either size_t or int or unsigned int is probably right.  Under
   SunOS 4, it looks like int is desired, according to the accept man
   page.  */
#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

/* XXX should only be done if sockaddr_storage not found */
#ifndef KRB5_USE_INET6
struct krb5int_sockaddr_storage { struct sockaddr_in s; };
#define sockaddr_storage krb5int_sockaddr_storage
#endif

#if defined (__GNUC__)
/* There's a lot of confusion between pointers to different sockaddr
   types, and pointers with different degrees of indirection, as in
   the locate_kdc type functions.  Use these function to ensure we
   don't do something silly like cast a "sockaddr **" to a
   "sockaddr_in *".  */
static __inline__ struct sockaddr_in *sa2sin (struct sockaddr *sa)
{
    return (struct sockaddr_in *) sa;
}
#ifdef KRB5_USE_INET6xxNotUsed
static __inline__ struct sockaddr_in6 *sa2sin6 (struct sockaddr *sa)
{
    return (struct sockaddr_in6 *) sa;
}
#endif
static __inline__ struct sockaddr *ss2sa (struct sockaddr_storage *ss)
{
    return (struct sockaddr *) ss;
}
static __inline__ struct sockaddr_in *ss2sin (struct sockaddr_storage *ss)
{
    return (struct sockaddr_in *) ss;
}
static __inline__ struct sockaddr_in6 *ss2sin6 (struct sockaddr_storage *ss)
{
    return (struct sockaddr_in6 *) ss;
}
#else
#define sa2sin(S)	((struct sockaddr_in *)(S))
#define sa2sin6(S)	((struct sockaddr_in6 *)(S))
#define ss2sa(S)	((struct sockaddr *)(S))
#define ss2sin(S)	((struct sockaddr_in *)(S))
#define ss2sin6(S)	((struct sockaddr_in6 *)(S))
#endif

#if !defined (socklen)
/* size_t socklen (struct sockaddr *) */
/* Should this return socklen_t instead? */
#  ifdef HAVE_SA_LEN
#    define socklen(X) ((X)->sa_len)
#  else
#    ifdef KRB5_USE_INET6
#      define socklen(X) ((X)->sa_family == AF_INET6 ? sizeof (struct sockaddr_in6) : (X)->sa_family == AF_INET ? sizeof (struct sockaddr_in) : sizeof (struct sockaddr))
#    else
#      define socklen(X) ((X)->sa_family == AF_INET ? sizeof (struct sockaddr_in) : sizeof (struct sockaddr))
#    endif
#  endif
#endif

#endif /* SOCKET_UTILS_H */
