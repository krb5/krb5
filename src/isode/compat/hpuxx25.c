/* hpuxx25.c - X.25 abstractions for HPUX X25/9000 */

#ifndef lint
static char *rcsid = "$Header$";
#endif

/*
 * $Header$
 *
 * Contributed by John Pavel, Department of Trade and Industry/National
 * Physical Laboratory in the UK
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:27:18  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:15:46  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:33:48  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:17:54  isode
 * Release 7.0
 * 
 * 
 */

/*
 *                                NOTICE
 *
 *    Acquisition, use, and distribution of this module and related
 *    materials are subject to the restrictions of a license agreement.
 *    Consult the Preface in the User's Manual for the full terms of
 *    this agreement.
 *
 */


/* LINTLIBRARY */

#include <stdio.h>
#include <signal.h>
#include "general.h"
#include "manifest.h"
#include "tailor.h"

/*    HP UNIX: X25/9000 */

#ifdef  X25

#include "x25.h"
#include "isoaddrs.h"

#ifdef  HPUX_X25

#define	CALLING	0
#define	CALLED	1
#define	PROBE	(-1)

struct  fdl_st {
	   int	fd; 
	   struct fdl_st *next;
	};
static struct fdl_st *fdl = NULL;
static void setup_sigurg ();
static void clear_sigurg ();

/*  */

#ifdef  DEBUG
void    print_x25_facilities ();
#endif

/*  */

/* ARGSUSED */

int     start_x25_client (local, priv)
struct  NSAPaddr *local;
int     priv;
{
    int     sd, pgrp;

    if ((sd = socket (AF_CCITT, SOCK_STREAM, 0)) == NOTOK) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed", ("socket"));
	return NOTOK;
    }

    pgrp = -getpid();
    if (ioctl(sd, SIOCSPGRP, &pgrp)) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed", ("SIOCSPGRP"));
	return NOTOK; /* Error can be found in errno */
    }

    return sd;
}

/*  */

int     start_x25_server (local, backlog, opt1, opt2)
struct  NSAPaddr *local;
int     backlog,
	opt1,
	opt2;
{
    CONN_DB	sbuf;
    CONN_DB	*sock;
    int		sd, onoff, pgrp;
    char	cudfbuf [NPSIZE + CUDFSIZE];

    bzero(&sbuf, sizeof(CONN_DB));
    sbuf.addr.x25_family = AF_CCITT;
    if ((sd = socket (AF_CCITT, SOCK_STREAM, 0)) == NOTOK) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed", ("socket"));
	return NOTOK;
    }

    pgrp = getpid();
    if (ioctl(sd, SIOCSPGRP, &pgrp)) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed", ("SIOCSPGRP"));
	return NOTOK; /* Error can be found in errno */
    }

    /* if neither dte or pid are given use dte from interface */
    if (!(local->na_dtelen || local->na_pidlen)) {
	strcpy (sbuf.addr.x25ifname, "x25_0");
	if (ioctl (sd, X25_RD_HOSTADR, (char *) &sbuf.addr) == NOTOK) {
	    SLOG (x25_log, LLOG_EXCEPTIONS, "failed", ("X25_RD_HOSTADR"));
	    (void) close_x25_socket (sd);
	    return NOTOK;
	}
	sbuf.addr.x25ifname [0] = '\0';
	sbuf.addr.x25hostlen = strlen(sbuf.addr.x25_host);
	if (x25_dnic_prefix && *x25_dnic_prefix)
	    strcpy (local->na_dte, x25_dnic_prefix);
	strcat (local->na_dte, sbuf.addr.x25_host);
	local->na_dtelen = strlen (local->na_dte);
    }
    /* Avoid a null local dte address, set it to '0',       */
    /* gen2if will set it back to zero in interface address */
    if (!local->na_dtelen) {
	local->na_dtelen = 1;
	local->na_dte [0] = '0';
    }
    sock = gen2if(local, &sbuf, ADDR_LISTEN);

    if (sock->cudf.x25_cud_len)
	if (ioctl (sd, X25_WR_USER_DATA, &sock->cudf) == -1) {
	    SLOG (x25_log, LLOG_EXCEPTIONS, "failed", ("X25_WR_USER_DATA"));
	    (void) close_x25_socket (sd);
	    return NOTOK;
	}
    if (bind (sd, (X25_ADDR *) &sock->addr, sizeof(X25_ADDR)) == NOTOK) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed", ("bind"));
	(void) close_x25_socket (sd);
	return NOTOK;
    }

#ifndef	BSD43
    if (opt1)
	(void) setsockopt (sd, SOL_SOCKET, opt1, NULLCP, 0);
    if (opt2)
	(void) setsockopt (sd, SOL_SOCKET, opt2, NULLCP, 0);
#else
    onoff = 1;
    if (opt1)
	(void) setsockopt (sd, SOL_SOCKET, opt1, (char *)&onoff, sizeof onoff);
    if (opt2)
	(void) setsockopt (sd, SOL_SOCKET, opt2, (char *)&onoff, sizeof onoff);
#endif

    if (set_x25_facilities(sd, CALLED, "Acceptable") == NOTOK) {
	(void) close_x25_socket (sd);
	return NOTOK;
    }

    (void) listen (sd, backlog);

    onoff = 0;
    if (ioctl (sd, X25_CALL_ACPT_APPROVAL, (char *) &onoff) == NOTOK) {
	SLOG (x25_log, LLOG_EXCEPTIONS, "failed",
	      ("X25_CALL_ACPT_APPROVAL"));
	(void) close_x25_socket (sd);
	return NOTOK;
    }

    return sd;
}

/*  */

int     join_x25_server (fd, remote)
register int fd;
register struct NSAPaddr *remote;
{
    CONN_DB sbuf;
    CONN_DB *sock = &sbuf;
    register int nfd;

    bzero(&sbuf, sizeof(CONN_DB));
    sbuf.addr.x25_family = AF_CCITT;
    sock = gen2if (remote, sock, ADDR_REMOTE);

    if (set_x25_facilities(fd, CALLING, "Proposed") == NOTOK)
	return NOTOK;

    if (sock->cudf.x25_cud_len)
	if (ioctl (fd, X25_WR_USER_DATA, &sock->cudf) == -1) {
	    SLOG (x25_log, LLOG_EXCEPTIONS, "failed", ("X25_WR_USER_DATA"));
	    return NOTOK;
	}
    setup_sigurg (fd);
    if ((nfd = connect (fd, (X25_ADDR *) &sock->addr, sizeof (X25_ADDR)))
	    == NOTOK) {
	return nfd;
    }
#ifdef  DEBUG
    else
	if (x25_log -> ll_events & LLOG_DEBUG)
	    (void) log_x25_facilities(fd, CALLING, "Effective Calling");
#endif

    remote = if2gen (remote, sock, ADDR_REMOTE);

    return nfd;
}

/*  */

int     join_x25_client (fd, remote)
int     fd;
struct  NSAPaddr *remote;
{
    CONN_DB     sbuf;
    CONN_DB     *sock = &sbuf;
    int     len = sizeof *sock;
    int     nfd;

    bzero(&sbuf, sizeof(CONN_DB));
    sbuf.addr.x25_family = AF_CCITT;
    if ((nfd = accept (fd, (X25_ADDR *) &sock->addr, &len)) == NOTOK) {
	return nfd;
    }

    setup_sigurg (nfd);
    if (ioctl(nfd,X25_SEND_CALL_ACEPT, NULLCP) < 0)
	SLOG (x25_log, LLOG_EXCEPTIONS, "failed", ("X25_SEND_CALL_ACEPT"));

#ifdef  DEBUG
     if (x25_log -> ll_events & LLOG_DEBUG)
	 (void) log_x25_facilities(fd, CALLED, "Effective Called");
#endif
    remote = if2gen (remote, sock, ADDR_REMOTE);

    return nfd;
}

/*  */

int fac_ccitt2hp (ccitt, hp)
CCITT_FACILITY_DB	*ccitt;
FACILITY_DB		*hp;
{
    register int	i, j;
    int			returncode = OK;

    memset (hp, 0, sizeof (FACILITY_DB));
    for (i = 0; i < ccitt->x25_fac_len; i++)
    switch (ccitt->x25_fac [i]) {
    	case 0x01:
	    hp->t_01 = ccitt->x25_fac [++i];
	    break;
	case 0x02:
	    hp->t_02 = ccitt->x25_fac [++i];
	    break;
	case 0x03:
	    hp->t_03_sel = 1;
	    hp->t_03 = ccitt->x25_fac [++i];
	    break;
	case 0x07:
	    hp->t_07 = ccitt->x25_fac [++i];
	    break;
	case 0x41:
	    hp->t_41_sel = 1;
	    hp->t_41 = ccitt->x25_fac [++i] << 8;
	    hp->t_41 += ccitt->x25_fac [++i];
	    break;
	case 0x42:
	    hp->t_42 [0] = ccitt->x25_fac [++i];
	    hp->t_42 [1] = ccitt->x25_fac [++i];
	    break;
	case 0x43:
	    hp->t_43 [0] = ccitt->x25_fac [++i];
	    hp->t_43 [1] = ccitt->x25_fac [++i];
	    break;
	case 0x44:
	    hp->t_44_sel = 1;
	    hp->t_44 = ccitt->x25_fac [++i] << 8;
	    hp->t_44 += ccitt->x25_fac [++i];
	    break;
	default:
	    /* ignore parameter */
	    returncode = NOTOK;
	    switch (ccitt->x25_fac [i] & 0xc0) {
		case 0x00:
		    i += 1; break;
		case 0x40:
		    i += 2; break;
		case 0x80:
		    i += 3; break;
		case 0xc0:
		    i += ccitt->x25_fac [++i]; break;
	    }
    }
    return (returncode);
}


void fac_hp2ccitt (hp, ccitt)
FACILITY_DB		*hp;
CCITT_FACILITY_DB	*ccitt;
{
    register int	i;

    memset (ccitt, 0, sizeof (CCITT_FACILITY_DB));
    i = 0;
    if (hp->t_01) {
	ccitt->x25_fac_len += 2;
	ccitt->x25_fac [i++] = 0x01;
	ccitt->x25_fac [i++] = hp->t_01;
    }
    if (hp->t_02) {
	ccitt->x25_fac_len += 2;
	ccitt->x25_fac [i++] = 0x02;
	ccitt->x25_fac [i++] = hp->t_02;
    }
    if (hp->t_03_sel) {
	ccitt->x25_fac_len += 2;
	ccitt->x25_fac [i++] = 0x03;
	ccitt->x25_fac [i++] = hp->t_03;
    }
    if (hp->t_07) {
	ccitt->x25_fac_len += 2;
	ccitt->x25_fac [i++] = 0x07;
	ccitt->x25_fac [i++] = hp->t_07;
    }
    if (hp->t_41_sel) {
	ccitt->x25_fac_len += 3;
	ccitt->x25_fac [i++] = 0x41;
	ccitt->x25_fac [i++] = hp->t_41 >> 8;
	ccitt->x25_fac [i++] = hp->t_41 && 0xff;
    }
    if (hp->t_42 [0] || hp->t_42 [1]) {
	ccitt->x25_fac_len += 3;
	ccitt->x25_fac [i++] = 0x42;
	ccitt->x25_fac [i++] = hp->t_42 [0];
	ccitt->x25_fac [i++] = hp->t_42 [1];
    }
    if (hp->t_43 [0] || hp->t_43 [1]) {
	ccitt->x25_fac_len += 3;
	ccitt->x25_fac [i++] = 0x43;
	ccitt->x25_fac [i++] = hp->t_43 [0];
	ccitt->x25_fac [i++] = hp->t_43 [1];
    }
    if (hp->t_44_sel) {
	ccitt->x25_fac_len += 3;
	ccitt->x25_fac [i++] = 0x44;
	ccitt->x25_fac [i++] = hp->t_44 >> 8;
	ccitt->x25_fac [i++] = hp->t_44 && 0xff;
    }
}


int     set_x25_facilities(sd, coc, caption)
int     sd, coc;
char *caption;
{
    FACILITY_DB		facilities;
    CCITT_FACILITY_DB	ccitt_facilities;

    bzero ((char *) &facilities, sizeof (FACILITY_DB));
    bzero ((char *) &ccitt_facilities, sizeof (CCITT_FACILITY_DB));

    if (ioctl (sd, X25_RD_FACILITIES, (char *) &ccitt_facilities) == NOTOK) {
	SLOG (x25_log, LLOG_EXCEPTIONS, "failed", ("X25_RD_FACILITIES"));
	return NOTOK;
    }
    if (fac_ccitt2hp (&ccitt_facilities, &facilities) == NOTOK)
	SLOG (x25_log, LLOG_EXCEPTIONS, "unkonwn parameter(s)", ("fac_ccitt2hp"));

    if (coc == PROBE
	    || !(coc == CALLED
		    || reverse_charge   || recvpktsize || sendpktsize
		    || recvwndsize      || sendwndsize || recvthruput
		    || sendthruput      || cug_req  /* || cug_index */
		    || fast_select_type || rpoa_req /* || rpoa */)) {
	if (facilities.t_42 [0])
	    recvpktsize = 1 << facilities.t_42 [0];
	if (facilities.t_42 [1])
	    sendpktsize = 1 << facilities.t_42 [1];
	return OK;
    }

    if (reverse_charge)
	facilities.t_01 |= 0x01;
    else
	facilities.t_01 &= ~0x01;
    
    switch (recvpktsize) {
	case 16:
	    facilities.t_42 [0] = 4;
	    break;
	case 32:
	    facilities.t_42 [0] = 5;
	    break;
	case 64:
	    facilities.t_42 [0] = 6;
	    break;
	case 128:
	    facilities.t_42 [0] = 7;
	    break;
	case 256:
	    facilities.t_42 [0] = 8;
	    break;
	case 512:
	    facilities.t_42 [0] = 9;
	    break;
	case 1024:
	    facilities.t_42 [0] = 10;
    }
    switch (sendpktsize) {
	case 16:
	    facilities.t_42 [1] = 4;
	    break;
	case 32:
	    facilities.t_42 [1] = 5;
	    break;
	case 64:
	    facilities.t_42 [1] = 6;
	    break;
	case 128:
	    facilities.t_42 [1] = 7;
	    break;
	case 256:
	    facilities.t_42 [1] = 8;
	    break;
	case 512:
	    facilities.t_42 [1] = 9;
	    break;
	case 1024:
	    facilities.t_42 [1] = 10;
    }

    if (recvwndsize)
	facilities.t_43 [0] = recvwndsize;
    if (sendwndsize)
	facilities.t_43 [1] = sendwndsize;

    if (sendthruput)
	facilities.t_02 = (facilities.t_02 & 0xf0) | (sendthruput & 0x0f);
    if (recvthruput)
	facilities.t_02 = (facilities.t_02 & 0x0f) | (recvthruput << 4);

    if (cug_req) {
	facilities.t_03_sel = 1;
	facilities.t_03 = cug_index;
    }

    switch (fast_select_type) {
	case 0:
	    facilities.t_01 &= ~CCITT_FAST_SELECT;
	    if (coc == CALLED)
		facilities.t_01 |= CCITT_FAST_ACPT_CLR;
	    break;
	case 1:
	    facilities.t_01 &= ~CCITT_FAST_SELECT;
	    facilities.t_01 |= CCITT_FAST_CLR_ONLY;
	    break;
	case 2:
	    facilities.t_01 &= ~CCITT_FAST_SELECT;
	    facilities.t_01 |= CCITT_FAST_ACPT_CLR;
	    break;
	default:
	    SLOG (x25_log, LLOG_EXCEPTIONS, "illegal value",
		("fast_select_type"));
    }

    /* rpoa not supported - is this parameter t_41 in ccitt-description ??? */

    fac_hp2ccitt (&facilities, &ccitt_facilities);
    if (ioctl (sd, X25_WR_FACILITIES, (char *) &ccitt_facilities) == NOTOK) {
	SLOG (x25_log, LLOG_EXCEPTIONS, "failed", ("X25_WR_FACILITIES"));
	return NOTOK;
    }

#ifdef  DEBUG
    if (x25_log -> ll_events & LLOG_DEBUG)
	print_x25_facilities (facilities, coc, caption);
#endif

    if (facilities.t_42 [0])
	recvpktsize = 1 << facilities.t_42 [0];
    if (facilities.t_42 [1])
	sendpktsize = 1 << facilities.t_42 [1];

    return OK;
}

/*  */

int     log_cause_and_diag(fd)
int fd;
{
    char buf [MAX_EVENT_SIZE];
    int	buflen;
    char flags = 0;

    for (;;) {
	if ((buflen = recv (fd, buf, MAX_EVENT_SIZE, MSG_OOB)) == NOTOK) {
	    if (x25_log -> ll_events & LLOG_NOTICE)
		SLOG (x25_log, LLOG_NOTICE,
		    "failed", ("recv %d (MSG_OOB)", fd));
	    clear_sigurg (fd);
	    return OK;
	}
	else if (!buflen)
	    return OK;
	switch (buf [1]) {
	    case OOB_INTERRUPT:
		SLOG (x25_log, LLOG_NOTICE, NULLCP, ("OOB_INTERRUPT"));
		break;
	    case OOB_VC_RESET:
		SLOG (x25_log, LLOG_EXCEPTIONS, NULLCP, ("OOB_VC_RESET"));
		flags = (1 << RECV_DIAG);
		close_x25_socket (fd);
		break;
	    case OOB_VC_CLEAR:
		SLOG (x25_log, LLOG_EXCEPTIONS, NULLCP, ("OOB_VC_CLEAR"));
		flags = (1 << RECV_DIAG) | (1 << DIAG_TYPE);
		close_x25_socket (fd);
		break;
	    case OOB_VC_RESET_CONF:
		SLOG (x25_log, LLOG_NOTICE, NULLCP, ("OOB_VC_RESET_CONF"));
		break;
	    case OOB_VC_INTERRUPT_CONF:
		SLOG (x25_log, LLOG_NOTICE, NULLCP, ("OOB_VC_INTERRUPT_CONF"));
		break;
	    case OOB_VC_DBIT_CONF:
		SLOG (x25_log, LLOG_NOTICE, NULLCP, ("OOB_VC_DBIT_CONF"));
		break;
	    case OOB_VC_MSG_TOO_BIG:
		SLOG (x25_log, LLOG_EXCEPTIONS, NULLCP, ("OOB_VC_MSG_TOO_BIG"));
		close_x25_socket (fd);
		break;
	    case OOB_VC_L2DOWN:
		SLOG (x25_log, LLOG_EXCEPTIONS, NULLCP, ("OOB_VC_L2DOWN"));
		close_x25_socket (fd);
		break;
	}
	(void) elucidate_x25_err (flags, &buf [2]);
    }
}


void sigurg (sig, code, scp)
int  sig, code;
struct sigcontext *scp;
{
    struct fdl_st *fdlp = fdl, *nfdlp;

    (void) signal (SIGURG, sigurg);
    while (fdlp != NULL) {
	log_cause_and_diag (fdlp->fd);
	fdlp = fdlp->next;
    }
    if (scp == NULL) {
	SLOG (x25_log, LLOG_NOTICE, NULLCP, ("No signal context"));
	return;
    };
    if (scp->sc_syscall != SYS_NOTSYSCALL)
	scp->sc_syscall_action = SIG_RESTART;
}

void setup_sigurg (fd)
int fd;
{
    struct fdl_st *fdlp = fdl;

    (void) signal (SIGURG, sigurg);
    while (fdlp != NULL)
	if (fdlp->fd == fd)
	    return;
	else
	    fdlp = fdlp->next;
    if ((fdlp = malloc (sizeof (struct fdl_st))) == NULL) {
	SLOG (x25_log, LLOG_EXCEPTIONS, "failed", ("malloc (sigurg-struct)"));
	return;
    }
    fdlp->fd = fd;
    fdlp->next = fdl;
    fdl = fdlp;
}

void clear_sigurg (fd)
int fd;
{
    struct fdl_st *fdlp = fdl, *nfdlp;

    if ((fdl != NULL) && (fdl->fd == fd)) {
	fdl = fdl->next;
	if (free (fdlp) == NOTOK)
	    SLOG (x25_log, LLOG_EXCEPTIONS, "failed",
		("free (sigurg-struct)"));
	return;
    }
    else while (fdlp != NULL)
	if ((fdlp->next != NULL) && (fdlp->next->fd == fd)) {
	    nfdlp = fdlp->next;
	    fdlp->next = fdlp->next->next;
	    if (free (nfdlp) == NOTOK)
		SLOG (x25_log, LLOG_EXCEPTIONS, "failed",
		    ("free (sigurg-struct)"));
	}
	else
	    fdlp = fdlp->next;
}

int close_x25_socket (fd)
int fd;
{
    clear_sigurg (fd);
    return (close (fd));
};


/*  */

#ifdef  DEBUG

static int  log_x25_facilities (fd, coc, caption)
int     fd;
int     coc;
char   *caption;
{
    FACILITY_DB        hp;
    CCITT_FACILITY_DB  ccitt;

    if (ioctl (fd, X25_RD_FACILITIES, (char *) &ccitt) == NOTOK) {
	SLOG (x25_log, LLOG_EXCEPTIONS, "failed", ("X25_RD_FACILITIES"));
	return NOTOK;
    }

    fac_ccitt2hp (&ccitt, &hp);
    print_x25_facilities (&hp, coc, caption);

    return OK;
}

/*  */

static void  print_x25_facilities (hp, coc, caption)
FACILITY_DB *hp;
int     coc;
char   *caption;
{
    int     i, baud;

    DLOG (x25_log, LLOG_DEBUG, ("%s X.25 Facilities:", caption));

    /* reverse charge */
    switch (hp->t_01 & REVCHARGE) {
	case 0:
	    DLOG (x25_log, LLOG_DEBUG, ((coc == CALLED)
		      ? "reverse charging not allowed"
		      : "reverse charging not requested"));
	    break;

	case 1:
	    DLOG (x25_log, LLOG_DEBUG, ((coc == CALLING)
		      ? "reverse charging requested"
		      : "reverse charging allowed"));
	    break;
    }

    /* ACK expected */
    if (hp->t_07 & ACK_EXPECTED)
	DLOG (x25_log, LLOG_DEBUG, ("ACK-packets expected"));
    else
	DLOG (x25_log, LLOG_DEBUG, ("no ACK-packets expected"));

    /* NACK expected */
    if (hp->t_07 & NACK_EXPECTED)
	DLOG (x25_log, LLOG_DEBUG, ("NACK-packets expected"));
    else
	DLOG (x25_log, LLOG_DEBUG, ("no NACK-packets expected"));

    /* recvpktsize */
    switch (i = hp->t_42 [0] ? (1 << hp->t_42 [0]) : 0) {
	case 0:
	    DLOG (x25_log, LLOG_DEBUG, ("default recv packet size"));
	    break;

	case 16:
	case 32:
	case 64:
	case 128:
	case 256:
	case 512:
	case 1024:
	    DLOG (x25_log, LLOG_DEBUG, ("recv packet size %d", i));
	    break;

	default:
	    DLOG (x25_log, LLOG_DEBUG, ("invalid recv packet size %d", i));
	    break;
    }

    /* sendpktsize */
    switch (i = hp->t_42 [1] ? (1 << hp->t_42 [1]) : 0) {
	case 0:
	    DLOG (x25_log, LLOG_DEBUG, ("default send packet size"));
	    break;

	case 16:
	case 32:
	case 64:
	case 128:
	case 256:
	case 512:
	case 1024:
	    DLOG (x25_log, LLOG_DEBUG, ("send packet size %d", i));
	    break;

	default:
	    DLOG (x25_log, LLOG_DEBUG, ("invalid send packet size %d", i));
	    break;
    }

    DLOG (x25_log, LLOG_DEBUG,
	  (hp->t_43 [0] == 0 ? "default recv window size"
		  : 1 <= hp->t_43 [0] && hp->t_43 [0] <= 127
		      ? "recv window size %d"
		      : "invalid recv window size %d",
	      hp->t_43 [0]));

    DLOG (x25_log, LLOG_DEBUG,
	  (hp->t_43 [1] == 0 ? "default send window size"
		  : 1 <= hp->t_43 [1] && hp->t_43 [1] <= 127
		      ? "send window size %d"
		      : "invalid send window size %d",
	      hp->t_43 [1]));

    /* recvthruput */
    switch (hp->t_02 >> 4) {
	case 0:
	    DLOG (x25_log, LLOG_DEBUG, ("default recv throughput"));
	    break;

	case 3:
	    baud = 75;
print_recv: ;
	    DLOG (x25_log, LLOG_DEBUG, ("recv throughput %dbps", baud));
	    break;

	case 4:
	    baud = 150;
	    goto print_recv;

	case 5:
	    baud = 300;
	    goto print_recv;

	case 6:
	    baud = 600;
	    goto print_recv;

	case 7:
	    baud = 1200;
	    goto print_recv;

	case 8:
	    baud = 2400;
	    goto print_recv;

	case 9:
	    baud = 4800;
	    goto print_recv;

	case 10:
	    baud = 9600;
	    goto print_recv;

	case 11:
	    baud = 19200;
	    goto print_recv;

	case 12:
	    baud = 48000;
	    goto print_recv;

	default:
	    DLOG (x25_log, LLOG_DEBUG, ("invalid recv throughput %d",
		      hp->t_02 >> 4));
	    break;
    }

    /* sendthruput */
    switch (hp->t_02 & 0x0f) {
	case 0:
	    DLOG (x25_log, LLOG_DEBUG, ("default send throughput"));
	    break;

	case 3:
	    baud = 75;
print_send: ;
	    DLOG (x25_log, LLOG_DEBUG, ("send throughput %dbps", baud));
	    break;

	case 4:
	    baud = 150;
	    goto print_send;

	case 5:
	    baud = 300;
	    goto print_send;

	case 6:
	    baud = 600;
	    goto print_send;

	case 7:
	    baud = 1200;
	    goto print_send;

	case 8:
	    baud = 2400;
	    goto print_send;

	case 9:
	    baud = 4800;
	    goto print_send;

	case 10:
	    baud = 9600;
	    goto print_send;

	case 11:
	    baud = 19200;
	    goto print_send;

	case 12:
	    baud = 48000;
	    goto print_send;

	default:
	    DLOG (x25_log, LLOG_DEBUG, ("invalid send throughput %d",
		      hp->t_02 & 0x0f));
	    break;
    }

    if (hp->t_03_sel)
	DLOG (x25_log, LLOG_DEBUG, ("closed user group 0x%x (BCD)",
		hp->t_03));
    else
	DLOG (x25_log, LLOG_DEBUG, ("no closed user group"));

    if (hp->t_41_sel)
	DLOG (x25_log, LLOG_DEBUG, ("bilateral closed user group 0x%x (BCD)",
		hp->t_41 [0] << 8 + hp->t_41 [1]));
    else
	DLOG (x25_log, LLOG_DEBUG, ("no bilateral closed user group"));

    switch (hp->t_01 & CCITT_FAST_SELECT) {
	case CCITT_FAST_OFF:
	    DLOG (x25_log, LLOG_DEBUG, ("don't use fast select"));
	    break;

	case CCITT_FAST_CLR_ONLY:
	    DLOG (x25_log, LLOG_DEBUG, ("clear is fast select response"));
	    break;

	case CCITT_FAST_ACPT_CLR:
	    DLOG (x25_log, LLOG_DEBUG,
		  ("clear or call accepted is fast select response"));
	    break;

	default:
	    DLOG (x25_log, LLOG_DEBUG, ("invalid fast select type %d",
	 	hp->t_01 & CCITT_FAST_SELECT));
	    break;
    }

/*
 * Don't know the meaning of this parameter (is t_44 ?)
 *
    switch (f.rpoa_req) {
	case 0:
	    DLOG (x25_log, LLOG_DEBUG, ("no RPOA transit request"));
	    break;

	case 1:
	    DLOG (x25_log, LLOG_DEBUG, ("RPOA transit request 0x%x",
		      f.rpoa_req));
	    break;

	default:
	    DLOG (x25_log, LLOG_DEBUG, ("invalid RPOA transit request %d",
		      f.rpoa_req));
    }
 *
 *
 */
}
#endif
#else
int _hpuxx25_stub2 (){;}
#endif
#else
int _hpuxx25_stub (){;}
#endif
