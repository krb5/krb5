/*
 * lib/krb5/os/localaddr.c
 *
 * Copyright 1990,1991,2000,2001,2002 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Return the protocol addresses supported by this host.
 *
 * XNS support is untested, but "Should just work".  (Hah!)
 */

#define NEED_SOCKETS
#include "k5-int.h"

#if !defined(HAVE_MACSOCK_H) && !defined(_WIN32)

/* needed for solaris, harmless elsewhere... */
#define BSD_COMP
#include <sys/ioctl.h>
#include <sys/time.h>
#include <errno.h>
#include <stddef.h>
#include <ctype.h>

#if defined(TEST) || defined(DEBUG)
# include "fake-addrinfo.h"
#endif

#include "foreachaddr.c"

static krb5_error_code
get_localaddrs (krb5_context context, krb5_address ***addr, int use_profile);

#ifdef TEST

static int print_addr (/*@unused@*/ void *dataptr, struct sockaddr *sa)
     /*@modifies fileSystem@*/
{
    char hostbuf[NI_MAXHOST];
    int err;
    socklen_t len;

    printf ("  --> family %2d ", sa->sa_family);
    len = socklen (sa);
    err = getnameinfo (sa, len, hostbuf, (socklen_t) sizeof (hostbuf),
		       (char *) NULL, 0, NI_NUMERICHOST);
    if (err)
	printf ("<getnameinfo error %d: %s>\n", err, gai_strerror (err));
    else
	printf ("addr %s\n", hostbuf);
    return 0;
}

int main ()
{
    int r;

    (void) setvbuf (stdout, (char *)NULL, _IONBF, 0);
    r = foreach_localaddr (0, print_addr, NULL, NULL);
    printf ("return value = %d\n", r);
    return 0;
}

#else /* not TESTing */

struct localaddr_data {
    int count, mem_err, cur_idx, cur_size;
    krb5_address **addr_temp;
};

static int
count_addrs (void *P_data, struct sockaddr *a)
     /*@*/
{
    struct localaddr_data *data = P_data;
    switch (a->sa_family) {
    case AF_INET:
#ifdef KRB5_USE_INET6
    case AF_INET6:
#endif
#ifdef KRB5_USE_NS
    case AF_XNS:
#endif
	data->count++;
	break;
    default:
	break;
    }
    return 0;
}

static int
allocate (void *P_data)
     /*@*/
{
    struct localaddr_data *data = P_data;
    int i;
    void *n;

    n = realloc (data->addr_temp,
		 (1 + data->count + data->cur_idx) * sizeof (krb5_address *));
    if (n == 0) {
	data->mem_err++;
	return 1;
    }
    data->addr_temp = n;
    data->cur_size = 1 + data->count + data->cur_idx;
    for (i = data->cur_idx; i <= data->count + data->cur_idx; i++)
	data->addr_temp[i] = 0;
    return 0;
}

static /*@null@*/ krb5_address *
make_addr (int type, size_t length, const void *contents)
    /*@*/
{
    krb5_address *a;
    void *data;

    data = malloc (length);
    if (data == NULL)
	return NULL;
    a = malloc (sizeof (krb5_address));
    if (a == NULL) {
	free (data);
	return NULL;
    }
    memcpy (data, contents, length);
    a->magic = KV5M_ADDRESS;
    a->addrtype = type;
    a->length = length;
    a->contents = data;
    return a;
}

static int
add_addr (void *P_data, struct sockaddr *a)
     /*@modifies *P_data@*/
{
    struct localaddr_data *data = P_data;
    /*@null@*/ krb5_address *address = 0;

    switch (a->sa_family) {
#ifdef HAVE_NETINET_IN_H
    case AF_INET:
	address = make_addr (ADDRTYPE_INET, sizeof (struct in_addr),
			     &((const struct sockaddr_in *) a)->sin_addr);
	if (address == NULL)
	    data->mem_err++;
	break;

#ifdef KRB5_USE_INET6
    case AF_INET6:
    {
	const struct sockaddr_in6 *in = (const struct sockaddr_in6 *) a;
	
	if (IN6_IS_ADDR_LINKLOCAL (&in->sin6_addr))
	    break;

	address = make_addr (ADDRTYPE_INET6, sizeof (struct in6_addr),
			     &in->sin6_addr);
	if (address == NULL)
	    data->mem_err++;
	break;
    }
#endif /* KRB5_USE_INET6 */
#endif /* netinet/in.h */

#ifdef KRB5_USE_NS
    case AF_XNS:
	address = make_addr (ADDRTYPE_XNS, sizeof (struct ns_addr),
			     &((const struct sockaddr_ns *)a)->sns_addr);
	if (address == NULL)
	    data->mem_err++;
	break;
#endif

#ifdef AF_LINK
	/* Some BSD-based systems (e.g. NetBSD 1.5) and AIX will
	   include the ethernet address, but we don't want that, at
	   least for now.  */
    case AF_LINK:
	break;
#endif
    /*
     * Add more address families here..
     */
    default:
	break;
    }
#ifdef __LCLINT__
    /* Redundant but unconditional store un-confuses lclint.  */
    data->addr_temp[data->cur_idx] = address;
#endif
    if (address) {
	data->addr_temp[data->cur_idx++] = address;
    }

    return data->mem_err;
}

static krb5_error_code
krb5_os_localaddr_profile (krb5_context context, struct localaddr_data *datap)
{
    krb5_error_code err;
    static const char *const profile_name[] = {
	"libdefaults", "extra_addresses", 0
    };
    char **values;
    char **iter;
    krb5_address **newaddrs;

#ifdef DEBUG
    fprintf (stderr, "looking up extra_addresses foo\n");
#endif

    err = profile_get_values (context->profile, profile_name, &values);
    /* Ignore all errors for now?  */
    if (err)
	return 0;

    for (iter = values; *iter; iter++) {
	char *cp = *iter, *next, *current;
	int i, count;

#ifdef DEBUG
	fprintf (stderr, "  found line: '%s'\n", cp);
#endif

	for (cp = *iter, next = 0; *cp; cp = next) {
	    while (isspace ((int) *cp) || *cp == ',')
		cp++;
	    if (*cp == 0)
		break;
	    /* Start of an address.  */
#ifdef DEBUG
	    fprintf (stderr, "    addr found in '%s'\n", cp);
#endif
	    current = cp;
	    while (*cp != 0 && !isspace((int) *cp) && *cp != ',')
		cp++;
	    if (*cp != 0) {
		next = cp + 1;
		*cp = 0;
	    } else
		next = cp;
	    /* Got a single address, process it.  */
#ifdef DEBUG
	    fprintf (stderr, "    processing '%s'\n", current);
#endif
	    newaddrs = 0;
	    err = krb5_os_hostaddr (context, current, &newaddrs);
	    if (err)
		continue;
	    for (i = 0; newaddrs[i]; i++) {
#ifdef DEBUG
		fprintf (stderr, "    %d: family %d", i,
			 newaddrs[i]->addrtype);
		fprintf (stderr, "\n");
#endif
	    }
	    count = i;
#ifdef DEBUG
	    fprintf (stderr, "    %d addresses\n", count);
#endif
	    if (datap->cur_idx + count >= datap->cur_size) {
		krb5_address **bigger;
		bigger = realloc (datap->addr_temp,
				  sizeof (krb5_address *) * (datap->cur_idx + count));
		if (bigger) {
		    datap->addr_temp = bigger;
		    datap->cur_size = datap->cur_idx + count;
		}
	    }
	    for (i = 0; i < count; i++) {
		if (datap->cur_idx < datap->cur_size)
		    datap->addr_temp[datap->cur_idx++] = newaddrs[i];
		else
		    free (newaddrs[i]->contents), free (newaddrs[i]);
	    }
	    free (newaddrs);
	}
    }
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_os_localaddr(krb5_context context, krb5_address ***addr)
{
    return get_localaddrs(context, addr, 1);
}

krb5_error_code
krb5int_local_addresses(krb5_context context, krb5_address ***addr)
{
    return get_localaddrs(context, addr, 0);
}

static krb5_error_code
get_localaddrs (krb5_context context, krb5_address ***addr, int use_profile)
{
    struct localaddr_data data = { 0 };
    int r;
    krb5_error_code err;

    if (use_profile) {
	err = krb5_os_localaddr_profile (context, &data);
	/* ignore err for now */
    }

    r = foreach_localaddr (&data, count_addrs, allocate, add_addr);
    if (r != 0) {
	int i;
	if (data.addr_temp) {
	    for (i = 0; i < data.count; i++)
		krb5_xfree (data.addr_temp[i]);
	    free (data.addr_temp);
	}
	if (data.mem_err)
	    return ENOMEM;
	else
	    return r;
    }

    data.cur_idx++; /* null termination */
    if (data.mem_err)
	return ENOMEM;
    else if (data.cur_idx == data.count)
	*addr = data.addr_temp;
    else {
	/* This can easily happen if we have IPv6 link-local
	   addresses.  Just shorten the array.  */
	*addr = (krb5_address **) realloc (data.addr_temp,
					   (sizeof (krb5_address *)
					    * data.cur_idx));
	if (*addr == 0)
	    /* Okay, shortening failed, but the original should still
	       be intact.  */
	    *addr = data.addr_temp;
    }

#ifdef DEBUG
    {
	int j;
	fprintf (stderr, "addresses:\n");
	for (j = 0; addr[0][j]; j++) {
	    struct sockaddr_storage ss;
	    int err2;
	    char namebuf[NI_MAXHOST];
	    void *addrp = 0;

	    fprintf (stderr, "%2d: ", j);
	    fprintf (stderr, "addrtype %2d, length %2d", addr[0][j]->addrtype,
		     addr[0][j]->length);
	    memset (&ss, 0, sizeof (ss));
	    switch (addr[0][j]->addrtype) {
	    case ADDRTYPE_INET:
	    {
		struct sockaddr_in *sinp = ss2sin (&ss);
		sinp->sin_family = AF_INET;
		addrp = &sinp->sin_addr;
#ifdef HAVE_SA_LEN
		sinp->sin_len = sizeof (struct sockaddr_in);
#endif
		break;
	    }
#ifdef KRB5_USE_INET6
	    case ADDRTYPE_INET6:
	    {
		struct sockaddr_in6 *sin6p = ss2sin6 (&ss);
		sin6p->sin6_family = AF_INET6;
		addrp = &sin6p->sin6_addr;
#ifdef HAVE_SA_LEN
		sin6p->sin6_len = sizeof (struct sockaddr_in6);
#endif
		break;
	    }
#endif
	    default:
		ss2sa(&ss)->sa_family = 0;
		break;
	    }
	    if (addrp)
		memcpy (addrp, addr[0][j]->contents, addr[0][j]->length);
	    err2 = getnameinfo (ss2sa(&ss), socklen (ss2sa (&ss)),
				namebuf, sizeof (namebuf), 0, 0,
				NI_NUMERICHOST);
	    if (err2 == 0)
		fprintf (stderr, ": addr %s\n", namebuf);
	    else
		fprintf (stderr, ": getnameinfo error %d\n", err2);
	}
    }
#endif

    return 0;
}

#endif /* not TESTing */

#else /* Windows/Mac version */

/*
 * Hold on to your lunch!  Backup kludge method of obtaining your
 * local IP address, courtesy of Windows Socket Network Programming,
 * by Robert Quinn
 */
#if defined(_WIN32)
static struct hostent *local_addr_fallback_kludge()
{
	static struct hostent	host;
	static SOCKADDR_IN	addr;
	static char *		ip_ptrs[2];
	SOCKET			sock;
	int			size = sizeof(SOCKADDR);
	int			err;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == INVALID_SOCKET)
		return NULL;

	/* connect to arbitrary port and address (NOT loopback) */
	addr.sin_family = AF_INET;
	addr.sin_port = htons(IPPORT_ECHO);
	addr.sin_addr.s_addr = inet_addr("204.137.220.51");

	err = connect(sock, (LPSOCKADDR) &addr, sizeof(SOCKADDR));
	if (err == SOCKET_ERROR)
		return NULL;

	err = getsockname(sock, (LPSOCKADDR) &addr, (int *) size);
	if (err == SOCKET_ERROR)
		return NULL;

	closesocket(sock);

	host.h_name = 0;
	host.h_aliases = 0;
	host.h_addrtype = AF_INET;
	host.h_length = 4;
	host.h_addr_list = ip_ptrs;
	ip_ptrs[0] = (char *) &addr.sin_addr.s_addr;
	ip_ptrs[1] = NULL;

	return &host;
}
#endif

/* No ioctls in winsock so we just assume there is only one networking 
 * card per machine, so gethostent is good enough. 
 */
krb5_error_code KRB5_CALLCONV
krb5_os_localaddr (krb5_context context, krb5_address ***addr) {
    char host[64];                              /* Name of local machine */
    struct hostent *hostrec;
    int err, count, i;
    krb5_address ** paddr;

    *addr = 0;
    paddr = 0;
    err = 0;
    
    if (gethostname (host, sizeof(host))) {
        err = SOCKET_ERRNO;
    }

    if (!err) {
	    hostrec = gethostbyname (host);
	    if (hostrec == NULL) {
		    err = SOCKET_ERRNO;
	    }
    }

    if (err) {
	    hostrec = local_addr_fallback_kludge();
	    if (!hostrec)
		    return err;
		else
			err = 0;  /* otherwise we will die at cleanup */
    }

    for (count = 0; hostrec->h_addr_list[count]; count++);


    paddr = (krb5_address **)malloc(sizeof(krb5_address *) * (count+1));
    if (!paddr) {
        err = ENOMEM;
        goto cleanup;
    }

    memset(paddr, 0, sizeof(krb5_address *) * (count+1));

    for (i = 0; i < count; i++)
    {
        paddr[i] = (krb5_address *)malloc(sizeof(krb5_address));
        if (paddr[i] == NULL) {
            err = ENOMEM;
            goto cleanup;
        }

        paddr[i]->magic = KV5M_ADDRESS;
        paddr[i]->addrtype = hostrec->h_addrtype;
        paddr[i]->length = hostrec->h_length;
        paddr[i]->contents = (unsigned char *)malloc(paddr[i]->length);
        if (!paddr[i]->contents) {
            err = ENOMEM;
            goto cleanup;
        }
        memcpy(paddr[i]->contents,
               hostrec->h_addr_list[i],
               paddr[i]->length);
    }

 cleanup:
    if (err) {
        if (paddr) {
            for (i = 0; i < count; i++)
            {
                if (paddr[i]) {
                    if (paddr[i]->contents)
                        free(paddr[i]->contents);
                    free(paddr[i]);
                }
            }
            free(paddr);
        }
    }
    else
        *addr = paddr;

    return(err);
}
#endif
