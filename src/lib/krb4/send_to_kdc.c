/*
 * send_to_kdc.c
 *
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"

#define	DEFINE_SOCKADDR		/* Ask for sockets declarations from krb.h. */
#include "krb.h"
#include "krbports.h"
#include "prot.h"
#include <stdio.h>
#include <string.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#define S_AD_SZ sizeof(struct sockaddr_in)

#ifdef HAS_STDLIB_H
#include <stdlib.h>
#else
extern char *malloc(), *calloc(), *realloc();
#endif

static int cached_krb_udp_port = 0;
static int cached_krbsec_udp_port = 0;

static int
send_recv PROTOTYPE ((KTEXT pkt, KTEXT rpkt, SOCKET f,
		      struct sockaddr_in *_to, struct hostent *addrs));


#ifdef DEBUG
static char *prog = "send_to_kdc";
#endif

/*
 * send_to_kdc() sends a message to the Kerberos authentication
 * server(s) in the given realm and returns the reply message.
 * The "pkt" argument points to the message to be sent to Kerberos;
 * the "rpkt" argument will be filled in with Kerberos' reply.
 * The "realm" argument indicates the realm of the Kerberos server(s)
 * to transact with.  If the realm is null, the local realm is used.
 *
 * If more than one Kerberos server is known for a given realm,
 * different servers will be queried until one of them replies.
 * Several attempts (retries) are made for each server before
 * giving up entirely.
 *
 * The following results can be returned:
 *
 * KSUCCESS	- an answer was received from a Kerberos host
 *
 * SKDC_CANT    - can't get local realm
 *              - can't find "kerberos" in /etc/services database
 *              - can't open socket
 *              - can't bind socket
 *              - all ports in use
 *              - couldn't find any Kerberos host
 *
 * SKDC_RETRY   - couldn't get an answer from any Kerberos server,
 *		  after several retries
 */

send_to_kdc(pkt,rpkt,realm)
    KTEXT pkt;
    KTEXT rpkt;
    char *realm;
{
    int i;
    SOCKET f;
    int no_host; /* was a kerberos host found? */
    int retry;
    int n_hosts;
    int retval;
    struct sockaddr_in to;
    struct hostent FAR *farkedhost;
    struct hostent *host, *hostlist;
    char *cp;
    char krbhst[MAXHOSTNAMELEN];
    char lrealm[REALM_SZ];
    char *scol;
    int krb_udp_port = 0;
    int krbsec_udp_port = 0;
    int default_port;

    /*
     * If "realm" is non-null, use that, otherwise get the
     * local realm.
     */
    if (realm)
	(void) strcpy(lrealm, realm);
    else
	if (krb_get_lrealm(lrealm,1)) {
	    DEB (("%s: can't get local realm\n", prog));
	    return(SKDC_CANT);
	}
    DEB (("lrealm is %s\n", lrealm));

    if (SOCKET_INITIALIZE()) {
	DEB (("%s: can't initialize sockets library\n",prog));
	return (SKDC_CANT);
    }
    /* from now on, exit through rtn label for cleanup */

    /* The first time, decide what port to use for the KDC.  */
    if (cached_krb_udp_port == 0) {
        register struct servent FAR *sp;
        if (sp = getservbyname("kerberos","udp"))
	    cached_krb_udp_port = sp->s_port;
	else
	    cached_krb_udp_port = htons(KERBEROS_PORT); /* kerberos/udp */
        DEB (("cached_krb_udp_port is %d\n", cached_krb_udp_port));
    }
    /* If kerberos/udp isn't 750, try using kerberos-sec/udp (or 750) 
       as a fallback. */
    if (cached_krbsec_udp_port == 0 && 
	cached_krb_udp_port != htons(KERBEROS_PORT)) {
        register struct servent FAR *sp;
        if (sp = getservbyname("kerberos-sec","udp"))
	    cached_krbsec_udp_port = sp->s_port;
	else
	    cached_krbsec_udp_port = htons(KERBEROS_PORT); /* kerberos/udp */
        DEB (("cached_krbsec_udp_port is %d\n", cached_krbsec_udp_port));
    }

    memset((char *)&to, 0, S_AD_SZ);
    hostlist = (struct hostent *) malloc(sizeof(struct hostent));
    if (!hostlist) {
	retval = /*errno */SKDC_CANT;
	goto rtn_clean;		/* Run SOCKET_CLEANUP then return.  */
    }
    hostlist->h_name = 0;	/* so it gets properly freed at "rtn" */
    
    f = socket(AF_INET, SOCK_DGRAM, 0);
    if (f == INVALID_SOCKET) {
        DEB (("%s: Can't open socket\n", prog));
	retval = /*errno */SKDC_CANT;
	goto rtn_clean;		/* Run SOCKET_CLEANUP then return.  */
    }

/*
** FIXME!  FTP Software's WINSOCK implmentation insists that
** a socket be bound before it can receive datagrams.
** This is outside specs.  Since it shouldn't hurt any
** other implementations we'll go ahead and do it for
** now.
*/
    {
	struct sockaddr_in from;
	memset ((char *)&from, 0, S_AD_SZ);
	from.sin_family = AF_INET;
	from.sin_addr.s_addr = INADDR_ANY;
	if ( bind(f, (struct sockaddr *)&from, S_AD_SZ) == SOCKET_ERROR ) {
	    DEB (("%s : Can't bind\n", prog));
	    retval = SKDC_CANT;
	    goto rtn;
	}
    }
/* End of kludge (FIXME) for FTP Software WinSock stack.  */

    no_host = 1;
    default_port = 0;
    /* get an initial allocation */
    n_hosts = 0;
    for (i = 1; krb_get_krbhst(krbhst, lrealm, i) == KSUCCESS; ++i) {
#ifdef DEBUG
        if (krb_debug) {
            DEB (("Getting host entry for %s...",krbhst));
            (void) fflush(stdout);
        }
#endif
	if (0 != (scol = strchr(krbhst,':'))) {
	    krb_udp_port = htons(atoi(scol+1));
	    *scol = 0;
	    if (krb_udp_port == 0) {
#ifdef DEBUG
		if (krb_debug) {
		    DEB (("bad port number %s\n",scol+1));
		    (void) fflush(stdout);
		}
#endif
		continue;
	    }
	    krbsec_udp_port = 0;
	} else {
	    krb_udp_port = cached_krb_udp_port;
	    krbsec_udp_port = cached_krbsec_udp_port;
	    default_port = 1;
	}
        farkedhost = gethostbyname(krbhst);
#ifdef DEBUG
        if (krb_debug) {
            DEB (("%s.\n", farkedhost ? "Got it" : "Didn't get it"));
            (void) fflush(stdout);
        }
#endif
        if (!farkedhost)
            continue;
        no_host = 0;    /* found at least one */
        n_hosts++;
        /* preserve host network address to check later
         * (would be better to preserve *all* addresses,
         * take care of that later)
         */
        hostlist = (struct hostent *)
            realloc((char *)hostlist,
                    (unsigned)
                    sizeof(struct hostent)*(n_hosts+1));
        if (!hostlist) {
            retval = /*errno */SKDC_CANT;
	    goto rtn;
	}
	hostlist[n_hosts-1] = *farkedhost;	/* Copy into array */
        memset((char *)&hostlist[n_hosts], 0, sizeof(struct hostent));
        host = &hostlist[n_hosts-1];
        cp = malloc((unsigned)host->h_length);
        if (!cp) {
            retval = /*errno */SKDC_CANT;
            goto rtn;
        }
        _fmemcpy(cp, host->h_addr, host->h_length);

/* At least Sun OS version 3.2 (or worse) and Ultrix version 2.2
   (or worse) only return one name ... */
#if !(defined(ULTRIX022) || (defined(SunOS) && SunOS < 40))
        host->h_addr_list = (char **)malloc(sizeof(char *));
        if (!host->h_addr_list) {
            retval = /*errno */SKDC_CANT;
            goto rtn;
        }
#endif /* ULTRIX022 || SunOS */
        host->h_addr = cp;
        to.sin_family = host->h_addrtype;
        memcpy((char *)&to.sin_addr, host->h_addr, 
	       host->h_length);
        to.sin_port = krb_udp_port;
        if (send_recv(pkt, rpkt, f, &to, hostlist)) {
            retval = KSUCCESS;
            goto rtn;
        }
	if (krbsec_udp_port) {
	  to.sin_port = krbsec_udp_port;
	  if (send_recv(pkt, rpkt, f, &to, hostlist)) {
            retval = KSUCCESS;
            goto rtn;
	  }
	}
        DEB (("Timeout, error, or wrong descriptor\n"));
    }
    if (no_host) {
	DEB (("%s: can't find any Kerberos host.\n", prog));
        retval = SKDC_CANT;
        goto rtn;
    }

    /* retry each host in sequence */
    for (retry = 0; retry < CLIENT_KRB_RETRY; ++retry) {
        for (host = hostlist; host->h_name != (char *)NULL; host++) {
            to.sin_family = host->h_addrtype;
            memcpy((char *)&to.sin_addr, host->h_addr, 
		   host->h_length);
            if (send_recv(pkt, rpkt, f, &to, hostlist)) {
                retval = KSUCCESS;
                goto rtn;
            }
        }
    }
    retval = SKDC_RETRY;
rtn:
    (void) closesocket (f);
rtn_clean:
    SOCKET_CLEANUP();		/* Done with using sockets for awhile */
    if (hostlist) {
        register struct hostent *hp;
        for (hp = hostlist; hp->h_name; hp++)
#if !(defined(ULTRIX022) || (defined(SunOS) && SunOS < 40))
            if (hp->h_addr_list) {
#endif /* ULTRIX022 || SunOS */
                if (hp->h_addr)
                    free(hp->h_addr);
#if !(defined(ULTRIX022) || (defined(SunOS) && SunOS < 40))
                free((char *)hp->h_addr_list);
            }
#endif /* ULTRIX022 || SunOS */
        free((char *)hostlist);
    }
    return(retval);
}

/*
 * try to send out and receive message.
 * return 1 on success, 0 on failure
 */

static int
send_recv(pkt,rpkt,f,_to,addrs)
    KTEXT pkt;
    KTEXT rpkt;
    SOCKET f;
    struct sockaddr_in *_to;
    struct hostent *addrs;
{
    fd_set readfds;
    register struct hostent *hp;
    struct sockaddr_in from;
    int sin_size;
    int numsent;
    int selresult;
    int recvresult;
    struct timeval timeout;

#ifdef DEBUG
    if (krb_debug) {
        if (_to->sin_family == AF_INET) {
            printf("Sending message to ");
	    far_fputs (inet_ntoa(_to->sin_addr), stdout);
	    printf("...");
        } else
            printf("Sending message...");
        (void) fflush(stdout);
    }
#endif
    if ((numsent = sendto(f,(char *)(pkt->dat), pkt->length, 0, 
			  (struct sockaddr *)_to,
                          S_AD_SZ)) != pkt->length) {
        DEB (("sent only %d/%d\n",numsent, pkt->length));
        return 0;
    }
#ifdef DEBUG
    if (krb_debug) {
        printf("Sent\nWaiting for reply...");
        (void) fflush(stdout);
    }
#endif
    FD_ZERO(&readfds);
    FD_SET(f, &readfds);
    SOCKET_SET_ERRNO (0);

    /* select - either recv is ready, or timeout */
    /* see if timeout or error or wrong descriptor */
    /* Need to fill in the timeout structure each time, because on some
       systems -- e.g., Linux -- the timeout will be modified in place
       by the select syscall.  */
    timeout.tv_sec = CLIENT_KRB_TIMEOUT;
    timeout.tv_usec = 0;
    selresult = select(SOCKET_NFDS(f), &readfds, (fd_set *)0, (fd_set *)0,
		       &timeout);
    if (selresult != 1 || !FD_ISSET(f, &readfds)) {
#ifdef DEBUG
        if (krb_debug) {
            fprintf(stderr, "select failed: selresult=%d, readfds=%x, errno=%d",
                    selresult, readfds, SOCKET_ERRNO);
            perror("");
        }
#endif
        return 0;
    }

    sin_size = sizeof(from);
    recvresult = recvfrom(f, (char *)(rpkt->dat), sizeof(rpkt->dat), 0,
			  (struct sockaddr *)&from, &sin_size);
    if (recvresult < 0) {
	DEB (("Recvfrom error %d\n", SOCKET_ERRNO));
        return 0;
    }
#ifdef DEBUG
    if (krb_debug) {
        printf("received packet from ");
        far_fputs (inet_ntoa(from.sin_addr), stdout);
        printf("\n");
        fflush(stdout);
    }
#endif
    for (hp = addrs; hp->h_name != (char *)NULL; hp++) {
        if (!memcmp(hp->h_addr, (char *)&from.sin_addr.s_addr,
                  hp->h_length)) {
            DEB (("Received it\n"));
            return 1;
        }
        DEB (("packet not from %x\n", hp->h_addr));
    }
    DEB (("%s: received packet from wrong host! (%x)\n",
	    "send_to_kdc(send_rcv)", from.sin_addr.s_addr));
    return 0;
}
