#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifndef HAVE_GETADDRINFO

#ifndef FAI_PREFIX
# error "FAI_PREFIX must be defined when fake-addrinfo.h is included"
#endif

#define FAI_CONCAT(A,B) FAI_CONCAT2(A,B)
#define FAI_CONCAT2(A,B) A ## B

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
#undef	AI_V4MAPPED
#define	AI_V4MAPPED	0x08	/* ignored */
#undef	AI_ADDRCONFIG
#define	AI_ADDRCONFIG	0x10	/* ignored */
#undef	AI_ALL
#define	AI_ALL		0x20	/* ignored */

#define AI_DEFAULT	(AI_V4MAPPED | AI_ADDRCONFIG)

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

#ifdef FAI_IMPLEMENTATION

static int translate_h_errno (int h);

static int fai_add_entry (struct addrinfo **result, void *addr, int port,
			  const struct addrinfo *template)
{
    struct addrinfo *n = malloc (sizeof (struct addrinfo));
    struct sockaddr_in *sin4;
    if (n == 0)
	return EAI_MEMORY;
    if (template->ai_family != AF_INET)
	return EAI_FAMILY;
    *n = *template;
    sin4 = malloc (sizeof (struct sockaddr_in));
    if (sin4 == 0)
	return EAI_MEMORY;
    n->ai_addr = (struct sockaddr *) sin4;
    sin4->sin_family = AF_INET;
    sin4->sin_addr = *(struct in_addr *)addr;
    sin4->sin_port = port;
#ifdef HAVE_SA_LEN
    sin4->sin_len = sizeof (struct sockaddr_in);
#endif
    n->ai_next = *result;
    *result = n;
    return 0;
}

static int fai_add_hosts_by_name (const char *name, int af,
				  struct addrinfo *template,
				  int portnum, int flags,
				  struct addrinfo **result)
{
    struct hostent *hp;
    int i, r;

    if (af != AF_INET)
	/* For now, real ipv6 support needs real getaddrinfo.  */
	return EAI_FAMILY;
    hp = gethostbyname (name);
    if (hp == 0)
	return translate_h_errno (h_errno);
    for (i = 0; hp->h_addr_list[i]; i++) {
	r = fai_add_entry (result, hp->h_addr_list[i], portnum, template);
	if (r)
	    return r;
    }
    if (*result && (flags & AI_CANONNAME))
	(*result)->ai_canonname = strdup (hp->h_name);
    return 0;
}

int getaddrinfo (const char *name, const char *serv,
		 const struct addrinfo *hint, struct addrinfo **result)
{
    struct addrinfo *res = 0;
    int ret;
    int port = 0, socktype;
    int flags;
    struct addrinfo template;

    if (hint != 0) {
	if (hint->ai_family != 0 && hint->ai_family != AF_INET)
	    return EAI_NODATA;
	socktype = hint->ai_socktype;
	flags = hint->ai_flags;
    } else {
	socktype = 0;
	flags = 0;
    }

    if (serv) {
	size_t numlen = strspn (serv, "0123456789");
	if (serv[numlen] == '\0') {
	    /* pure numeric */
	    unsigned long p = strtoul (serv, 0, 10);
	    if (p == 0 || p > 65535)
		return EAI_NONAME;
	    port = htons (p);
	} else {
	    struct servent *sp;
	    int try_dgram_too = 0;
	    if (socktype == 0) {
		try_dgram_too = 1;
		socktype = SOCK_STREAM;
	    }
	try_service_lookup:
	    sp = getservbyname (serv, socktype == SOCK_STREAM ? "tcp" : "udp");
	    if (sp == 0) {
		if (try_dgram_too) {
		    socktype = SOCK_DGRAM;
		    goto try_service_lookup;
		}
		return EAI_SERVICE;
	    }
	    port = sp->s_port;
	}
    }

    if (name == 0) {
	name = (flags & AI_PASSIVE) ? "0.0.0.0" : "127.0.0.1";
	flags |= AI_NUMERICHOST;
    }

    template.ai_family = AF_INET;
    template.ai_addrlen = sizeof (struct sockaddr_in);
    template.ai_socktype = socktype;
    template.ai_protocol = 0;
    template.ai_flags = 0;
    template.ai_canonname = 0;
    template.ai_next = 0;
    template.ai_addr = 0;

    /* If NUMERICHOST is set, parse a numeric address.
       If it's not set, don't accept such names.  */
    if (flags & AI_NUMERICHOST) {
	struct in_addr addr4;
#if 0
	ret = inet_aton (name, &addr4);
	if (ret)
	    return EAI_NONAME;
#else
	addr4.s_addr = inet_addr (name);
	if (addr4.s_addr == 0xffffffff || addr4.s_addr == -1)
	    /* 255.255.255.255 or parse error, both bad */
	    return EAI_NONAME;
#endif
	ret = fai_add_entry (&res, &addr4, port, &template);
    } else {
	ret = fai_add_hosts_by_name (name, AF_INET, &template, port, flags,
				     &res);
    }

    if (ret && ret != NO_ADDRESS) {
	freeaddrinfo (res);
	return ret;
    }
    if (res == 0)
	return NO_ADDRESS;
    *result = res;
    return 0;
}

int getnameinfo (const struct sockaddr *sa, socklen_t len,
		 char *host, size_t hostlen,
		 char *service, size_t servicelen,
		 int flags)
{
    struct hostent *hp;
    const struct sockaddr_in *sinp;
    struct servent *sp;

    if (sa->sa_family != AF_INET) {
	return EAI_FAMILY;
    }
    sinp = (const struct sockaddr_in *) sa;

    if (host) {
	if (flags & NI_NUMERICHOST) {
	    char *p;
	numeric_host:
	    p = inet_ntoa (sinp->sin_addr);
	    if (strlen (p) < hostlen)
		strcpy (host, p);
	    else
		return EAI_FAIL; /* ?? */
	} else {
	    hp = gethostbyaddr (&sinp->sin_addr, sizeof (struct in_addr),
				AF_INET);
	    if (hp == 0) {
		if (h_errno == NO_ADDRESS && !(flags & NI_NAMEREQD)) /* ??? */
		    goto numeric_host;
		return translate_h_errno (h_errno);
	    }
	    if (strlen (hp->h_name) < hostlen)
		strcpy (host, hp->h_name);
	    else
		return EAI_FAIL; /* ?? */
	}
    }

    if (service) {
	if (flags & NI_NUMERICSERV) {
	    char numbuf[10];
	    int port;
	numeric_service:
	    port = ntohs (sinp->sin_port);
	    if (port < 0 || port > 65535)
		return EAI_FAIL;
	    sprintf (numbuf, "%d", port);
	    if (strlen (numbuf) < servicelen)
		strcpy (service, numbuf);
	    else
		return EAI_FAIL;
	} else {
	    sp = getservbyport (sinp->sin_port,
				(flags & NI_DGRAM) ? "udp" : "tcp");
	    if (sp == 0)
		goto numeric_service;
	    if (strlen (sp->s_name) < servicelen)
		strcpy (service, sp->s_name);
	    else
		return EAI_FAIL;
	}
    }

    return 0;
}

void freeaddrinfo (struct addrinfo *ai)
{
    struct addrinfo *next;
    while (ai) {
	next = ai->ai_next;
	free (ai->ai_canonname);
	free (ai->ai_addr);
	free (ai);
	ai = next;
    }
}

char *gai_strerror (int code)
{
    switch (code) {
    case EAI_ADDRFAMILY: return "address family for nodename not supported";
    case EAI_AGAIN:	return "temporary failure in name resolution";
    case EAI_BADFLAGS:	return "bad flags to getaddrinfo/getnameinfo";
    case EAI_FAIL:	return "non-recoverable failure in name resolution";
    case EAI_FAMILY:	return "ai_family not supported";
    case EAI_MEMORY:	return "out of memory";
    case EAI_NODATA:	return "no address associated with hostname";
    case EAI_NONAME:	return "name does not exist";
    case EAI_SERVICE:	return "service name not supported for specified socket type";
    case EAI_SOCKTYPE:	return "ai_socktype not supported";
    case EAI_SYSTEM:	return strerror (errno);
    default:		return "bogus getaddrinfo error?";
    }
}

static int translate_h_errno (int h)
{
    switch (h) {
    case 0:
	return 0;
#ifdef NETDB_INTERNAL
    case NETDB_INTERNAL:
	if (errno == ENOMEM)
	    return EAI_MEMORY;
	return EAI_SYSTEM;
#endif
    case HOST_NOT_FOUND:
	return EAI_NONAME;
    case TRY_AGAIN:
	return EAI_AGAIN;
    case NO_RECOVERY:
	return EAI_FAIL;
    case NO_DATA:
#if NO_DATA != NO_ADDRESS
    case NO_ADDRESS:
#endif
	return EAI_NODATA;
    }
}

#endif /* FAI_IMPLEMENTATION */

#define HAVE_GETADDRINFO	/* fake it */
#define HAVE_GETNAMEINFO	/* well, soon... */

#endif /* HAVE_GETADDRINFO */

/* Fudge things on older gai implementations.  */
#ifndef AI_DEFAULT
# define AI_DEFAULT 0 /* (AI_V4MAPPED | AI_ADDRCONFIG) */
#endif
