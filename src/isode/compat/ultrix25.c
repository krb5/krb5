/* ultrix25.c - X.25 abstractions for Ultrix X25 */

/*
 *				  NOTICE
 *
 *    Acquisition, use, and distribution of this module and related
 *    materials are subject to the restrictions of a license agreement.
 *    Consult the Preface in the User's Manual for the full terms of
 *    this agreement.
 *
 */



/* 
 * isode/compat/ultrix25.c
 * Contributed by George Michaelson, University of Queensland in Australia
 *
 *  -based on the ubcx25.c and sunlink.c modules 
 *   by Julian Onions and John Pavel respectively,
 *
 *   Using the example code for the Ultrix X.25 interface 
 *   written by DEC NAC here in Australia
 */

/* LINTLIBRARY */

#include <errno.h>
#include <stdio.h>
#include "general.h"
#include "manifest.h"
#include "tailor.h"
#include "tpkt.h"

/*    Ultrix: X25 */

#ifdef  X25
#ifdef  ULTRIX_X25

#include "x25.h"

/* are these needed george? */
#define         X25_MBIT        0x40
#define         X25_QBIT        0x80

/*
 * from examples/socket_incoming.c et al
 */

/*
 * these routines in the Ultrix X.25 library do encoding and decoding
 * of call params. They'll probably be unused, but if I get clever 
 * enough It'd be nice to use them to build up non-standard facilities
 * and other X.25 call stuff.
 *
 * I think they're varargs. should this be ansi-ized at some point???
 */

extern int X25Decode();
extern int X25Encode();

/*
 * Definitions for Call
 */

#define CALLING	0
#define CALLED	1

#define BACKLOG        2
#define MAXMESSAGESIZE   4096

/*
 * global structs used during decoding and encoding of call params.
 * -these are probably way oversize.
 */

static     char	enc_buf[1024];
static     int	enc_buf_len;

/*  */

int     start_x25_client (local)
struct NSAPaddr *local;
{
    int     sd, pgrp;

    if (local != NULLNA)
	local -> na_stack = NA_X25, local -> na_community = ts_comm_x25_default;
    if ((sd = socket (AF_X25, SOCK_SEQPACKET, X25_ACCESS)) == NOTOK) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed", ("x25 socket()"));
	return NOTOK; /* Error can be found in errno */
    }

    /*
     * somebody tell me sometime why setting the process group on
     * the socket is such a big deal. This is getting like alchemy
     * with myself doing this 'cos its in the other fellers code...
     * 
     * camtec & ubc does it, sunlink doesn't.
    pgrp = getpid();
    if (ioctl(sd, SIOCSPGRP, &pgrp)) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed", ("x25 ioctl(SIOCSPGRP)"));
	return NOTOK; 
    }
     */

    return sd;
}

/*  */

int     start_x25_server (local, backlog, opt1, opt2)
struct NSAPaddr *local;
int     backlog,
	/*
 	 * in Ultrix  X.25 socket functions like turn off/on packet
	 * assembly and call acceptance are done with setsockopt.
	 * it looks like other X.25 socket interfaces are using
	 * "traditional" features like SO_KEEPALIVE, and this
	 * is being passed down in the call from tsap/tsaplisten.c
	 * but I really don't think it applies here.
	 *
	 * thus, the following two arguments are ignored in this
	 * module.
	 */
	opt1,
	opt2;
{
    int     sd, pgrp;
    CONN_DB     zsck;
    CONN_DB     *sck = &zsck;
    sockaddr_x25	addr;

    if ((sd = socket (AF_X25, SOCK_SEQPACKET, X25_ACCESS)) == NOTOK) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed", ("x25 socket()"));
	return NOTOK; /* Can't get an X.25 socket */
    }

    /*
     * somebody tell me sometime why setting the process group on
     * the socket is such a big deal. This is getting like alchemy
     * with myself doing this 'cos its in the other fellers code...
     * 
     * camtec & ubc does it, sunlink doesn't.
    pgrp = getpid();
    if (ioctl(sd, SIOCSPGRP, &pgrp)) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed", ("x25 ioctl(SIOCSPGRP)"));
	return NOTOK; 
    }
     */

    if (local != NULLNA) {
	local -> na_stack = NA_X25, local -> na_community = ts_comm_x25_default;
	if (local -> na_dtelen == 0) {
	    (void) strcpy (local -> na_dte, x25_local_dte);
	    local -> na_dtelen = strlen(x25_local_dte);
	    if (local -> na_pidlen == 0 && *x25_local_pid)
		local -> na_pidlen =
		    str2sel (x25_local_pid, -1, local -> na_pid, NPSIZE);
	}
    }

    (void) gen2if (local, sck, ADDR_LISTEN);
    /*
     * now munge this into DEC format.
     */
    addr.sx25_family = AF_X25;
    addr.sx25_flags  = 0;
    addr.sx25_namelen = strlen(x25_default_filter);
    strcpy(addr.sx25_name, x25_default_filter);

    if (bind (sd, &addr, sizeof(addr)) == NOTOK) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed", ("x25 bind()"));
	(void) close_x25_socket (sd);
	return NOTOK;
    }
    if (listen (sd, backlog) < 0) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed", ("x25 listen()"));
	(void) close_x25_socket (sd);
	return NOTOK;
    }
    return sd;
}

/*  */

int     join_x25_client (fd, remote)
int     fd;
struct NSAPaddr *remote;
{
    CONN_DB		zsck;
    CONN_DB		*sck = &zsck;
    sockaddr_x25	filter;
    int			len = sizeof filter;
    int			stat;
    int         	nfd;

    if((nfd = accept (fd, &filter, &len)) == NOTOK) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed", ("x25 accept()"));
        if (compat_log -> ll_events & LLOG_EXCEPTIONS)
            (void) log_call_status(fd);      /* decode useful information */
	return NOTOK;
    }
    /*
     * as well as doing a socket level accept, have to accept responsibilty
     * for the X.25 incoming request as well...
     */
    enc_buf_len = sizeof(enc_buf);
    if ((stat = getsockopt(nfd,X25_ACCESS,XSO_TAKECALL,enc_buf,&enc_buf_len) < 0 ) ) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed",
              ("Taking inbound X.25 Call"));
        if (compat_log -> ll_events & LLOG_EXCEPTIONS)
            (void) log_call_status(fd);      /* decode useful information */
        return NOTOK;
    }
#ifdef  DEBUG
    if (compat_log -> ll_events & LLOG_DEBUG)
        (void) print_x25_facilities(fd, CALLED, "Effective Called");
#endif
    /*
     * snarf the incoming call details. could permit some local 
     * sanityclaus checks on the X.25 guff but what the hell...
     */

    sck->na_dtelen = sizeof(sck->na_dte);
    if ((stat = X25Decode(enc_buf, enc_buf_len, X25I_CALLINGDTE, sck->na_dte, &(sck->na_dtelen) ) ) <0 ) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed",
              ("Getting remote DTE"));
        if (compat_log -> ll_events & LLOG_EXCEPTIONS)
            (void) log_call_status(fd);      /* decode useful information */
        return NOTOK;
    }

    sck->na_cudflen = sizeof(sck->na_cudf);
    if ((stat = X25Decode(enc_buf, enc_buf_len, X25I_USERDATA, sck->na_cudf, &(sck->na_cudflen) ) ) <0 ) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed",
              ("Getting remote CUDF"));
        if (compat_log -> ll_events & LLOG_EXCEPTIONS)
            (void) log_call_status(fd);      /* decode useful information */
        return NOTOK;
    }

    (void) if2gen (remote, sck, ADDR_REMOTE);

    /*
     * now send the poor bozo the X.25 acceptance (at last!)
     */
    if (setsockopt(nfd,X25_ACCESS,XSO_ACCEPTCALL,(caddr_t)0, 0) <0 ) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed",
              ("Sending Ultrix X.25 Connect Accept"));
        if (compat_log -> ll_events & LLOG_EXCEPTIONS)
            (void) log_call_status(fd);      /* decode useful information */
        return NOTOK;
    }
    return nfd;
}

int     join_x25_server (fd, remote)
int     fd;
struct NSAPaddr *remote;
{
    CONN_DB zsck;
    CONN_DB *sck = &zsck;
    sockaddr_x25 template;

    register int nfd;

    if (remote == NULLNA || remote -> na_stack != NA_X25)
    {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed",
	      ("Invalid type na%d", remote->na_stack));
	return NOTOK;
    }
    (void) gen2if (remote, sck, ADDR_REMOTE);
    /*
     * now we have to re-map the generic forms of the DTE/CUDF/facil 
     * into DECspeak using the X25Encode() call.
     */
    if ((enc_buf_len = X25Encode (enc_buf, 1024, X25I_NULL)) <0) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed",
              ("Initializing Ultrix X.25 Call Template"));
        return NOTOK;
    }
    if ((enc_buf_len = X25Encode (enc_buf, 1024,
              X25I_DTECLASS,
              strlen(x25_default_class), x25_default_class,
	      X25I_CALLEDDTE,
              sck->na_dtelen, sck->na_dte,
              X25I_USERDATA,
              sck->na_cudflen, sck->na_cudf, 
              X25I_NULL)) < 0) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed",
              ("Encoding Ultrix X.25 Call Template"));
        return NOTOK;
    }
    if (setsockopt(fd,X25_ACCESS,XSO_SETCONN,enc_buf,enc_buf_len) <0) { 
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed",
              ("Overriding Ultrix X.25 Template Values"));
        return NOTOK;
    }
    template.sx25_family = AF_X25;
    template.sx25_flags  = 0;
    template.sx25_namelen = strlen(x25_default_template);
    strcpy(template.sx25_name, x25_default_template);

    /*
     * poached from sunlink.c
     */
    if ((nfd = connect (fd, &template, sizeof (template))) == NOTOK) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed", ("x25 connect()"));
        if (compat_log -> ll_events & LLOG_EXCEPTIONS)
            (void) log_call_status(fd);      /* decode useful information */
	return NOTOK;
   }
#ifdef  DEBUG
    else
        if (compat_log -> ll_events & LLOG_DEBUG)
               (void) log_x25_facilities(fd, CALLING, "Effective Calling");
#endif
    remote = if2gen (remote, sck, ADDR_REMOTE);
    return nfd;
}

close_x25_socket(fd)
int	fd;
{
    struct	X25ClearData	cbuf;
    struct	X25ClearData	*cdata = &cbuf;
    int 			cbl	= sizeof(cbuf);
    int 			stat;

    cdata->clearCause = 0;		/* DTE originated */
    cdata->clearDiagnostic = 0;		/* no additional information */
    cdata->clearDetailsLength = 0;	/* no Clear Details information */

    if ((stat = setsockopt(fd, X25_ACCESS, XSO_CLEARCALL, cdata, cbl)) < 0) {
	if (errno != EACCES)
	    SLOG (compat_log, LLOG_EXCEPTIONS, "failed", 
		("x25 setsockopt(XSO_CLEARCALL)"));
    }

    log_call_status(fd);
    close(fd);
}

log_call_status(fd)
int	fd;
{
	struct	X25PortStatus	sbuf;
	struct	X25PortStatus	*stats = &sbuf;
	int 			sbl	= sizeof(sbuf);
	int			stat;

	/*
	 * get X25PortStatus information
	 */
	if ((stat = getsockopt(fd,X25_ACCESS,XSO_SHOWSTATUS,stats,&sbl) < 0)) {
		SLOG (compat_log, LLOG_EXCEPTIONS, "failed", 
			("x25 getsockopt(XSO_SHOWSTATUS)"));
		return; 
	}
	switch (stats->portState) {
	case	X25S_OPEN:
		SLOG (compat_log, LLOG_DEBUG, NULLCP, 
			("X25S_OPEN: No connection is in Progress."));
		log_call_clear(fd, 0);
		break;

	case	X25S_CLEARED:
		SLOG (compat_log, LLOG_DEBUG, NULLCP, 
			("X25S_CLEARED: The connection has been cleared."));
		log_call_clear(fd, 0);
		break;

	case	X25S_RUNNING:
#ifdef	DEBUG
		SLOG (compat_log, LLOG_DEBUG, NULLCP, 
			("X25S_RUNNING: The connection is still open."));
		log_call_clear(fd, 0);
#endif	DEBUG
		break;

	case X25S_CALLING:         /* Connection in progress       */
		SLOG (compat_log, LLOG_DEBUG, NULLCP, 
			("X25S_CALLING: Connection in progress."));
		log_call_clear(fd, 0);
		break;

	case X25S_CALLED:          /* Call received and taken      */
		SLOG (compat_log, LLOG_DEBUG, NULLCP, 
			("X25S_CALLED: Call received and taken."));
		log_call_clear(fd, 0);
		break;

	case X25S_SYNC:            /* Unconfirmed user reset       */
		SLOG (compat_log, LLOG_DEBUG, NULLCP, 
			("X25S_SYNC: Unconfirmed user reset."));
		log_call_clear(fd, 0);
		break;

	case X25S_UNSYNC:          /* Unconfirmed reset indic      */
		SLOG (compat_log, LLOG_DEBUG, NULLCP, 
			("X25S_UNSYNC: Unconfirmed reset indication."));
		log_call_clear(fd, 0);
		break;

	case X25S_CLEARING:        /* User requested clearing      */
		SLOG (compat_log, LLOG_DEBUG, NULLCP, 
			("X25S_CLEARING: User requested clearing."));
		log_call_clear(fd, 0);
		break;

	case X25S_NOCOMM:          /* No communication with net    */
		SLOG (compat_log, LLOG_DEBUG, NULLCP, 
			("X25S_NOCOMM: No communication with net."));
		log_call_clear(fd, 0);
		break;

	case X25S_CLEARBYDIR:     /* Cleared by directive         */
		SLOG (compat_log, LLOG_DEBUG, NULLCP, 
			("X25S_CLEARBYDIR: Cleared by directive."));
		log_call_clear(fd, 0);
		break;

	case X25S_INCALL:          /* Untaken incoming call        */
		SLOG (compat_log, LLOG_DEBUG, NULLCP, 
			("X25S_INCALL: Untaken incoming call."));
		log_call_clear(fd, 0);
		break;

	default:
		SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP, 
			("unknown return from getsockopt(XSO_SHOWSTATUS)= %d [see /usr/include/netx25/x25.h]", stats->portState));
		SLOG (compat_log, LLOG_DEBUG, NULLCP, 
			("restricted = %d", stats->restrictedInterface));
		SLOG (compat_log, LLOG_DEBUG, NULLCP, 
			("Int Msg Size = %d", stats->interruptMessageSize));
		SLOG (compat_log, LLOG_DEBUG, NULLCP, 
			("Data Msg Size in = %d", stats->dataMessageSizeIn));
		SLOG (compat_log, LLOG_DEBUG, NULLCP, 
			("Data Msg Size out = %d", stats->dataMessageSizeOut));
		SLOG (compat_log, LLOG_DEBUG, NULLCP, 
			("Error BitMap = %2x", stats->errorBitMap));
	}
	return;
}

log_call_clear(fd, type)
int	fd;
int	type;
{
	struct	X25ClearData	cbuf;
	struct	X25ClearData	*cdata = &cbuf;
	int 			cbl	= sizeof(cbuf);
	int			stat;
	int			flags;
	unsigned char		buf[2];
	extern	void		elucidate_x25_err();
	char			dbuf[128];
	int			dlen = sizeof(dbuf);

	/*
	 * get X25ClearData information
	 */
	if ((stat = getsockopt(fd,X25_ACCESS,XSO_CLEARDATA,cdata,&cbl) < 0) &&
	     errno != ENOMSG) {
		SLOG (compat_log, LLOG_EXCEPTIONS, "failed", 
			("x25 getsockopt(XSO_CLEARDATA)"));
		return; 
	}
	if (errno == ENOMSG)
		return;
	/*
	 * set up argbuf to call elucidate_x25_err()
	 */
	flags = 0;
	flags = 1 << RECV_DIAG;		/* we have diagnostics */
	if (type == 0)			/*  diag type (clear/reset) */
	    flags |= 1 << DIAG_TYPE;	/* we have call clear diagnostics */
	buf[0] = cdata->clearCause;
	buf[1] = cdata->clearDiagnostic;
	elucidate_x25_err(flags, buf);

	SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP, 
		("[Clear origin was %s]", 
			cdata->clearOrigin == X25R_ORIGINREMOTE ? "remote" :
			 cdata->clearOrigin == X25R_ORIGINLOCAL ? "local" :
			  "unknown" ));
	SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP, 
		("and %d bytes of info", cdata->clearDetailsLength));

	dlen = sizeof(dbuf);
	if ((stat = X25Decode(cdata->clearDetails, 
			      cdata->clearDetailsLength, 
			      X25I_CHARGEMON, 
			      dbuf, &dlen) ) <0 ) {
	    SLOG (compat_log, LLOG_EXCEPTIONS, "failed",
       		  ("X25Decode(X25I_CHARGEMON)"));
	    return;
    	}
	if (stat > 0) 
	    SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP, 
		("%*s Money Units", stat, dlen, dlen, dbuf));
	dlen = sizeof(dbuf);
	if ((stat = X25Decode(cdata->clearDetails, 
			      cdata->clearDetailsLength, 
			      X25I_CHARGESEG, 
			      dbuf, &dlen) ) <0 ) {
	    SLOG (compat_log, LLOG_EXCEPTIONS, "failed",
       		  ("X25Decode(X25I_CHARGESEG)"));
	    return;
    	}
	if (stat > 0) 
	    SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP, 
		("%*s Segments", dlen, dbuf));
	dlen = sizeof(dbuf);
	if ((stat = X25Decode(cdata->clearDetails, 
			      cdata->clearDetailsLength, 
			      X25I_CHARGETIME, 
			      dbuf, &dlen) ) <0 ) {
	    SLOG (compat_log, LLOG_EXCEPTIONS, "failed",
       		  ("X25Decode(X25I_CHARGETIME)"));
	    return;
    	}
	if (stat > 0) 
	    SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP, 
		("%*s Time Units", dlen, dbuf));
	dlen = sizeof(dbuf);
	if ((stat = X25Decode(cdata->clearDetails, 
			      cdata->clearDetailsLength, 
			      X25I_USERDATA, 
			      dbuf, &dlen) ) <0 ) {
	    SLOG (compat_log, LLOG_EXCEPTIONS, "failed",
       		  ("X25Decode(X25I_USERDATA)"));
	    return;
    	}
	if (stat > 0) 
	    SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP, 
		("%d Bytes User Data", dlen));
	return;
}


#ifdef  DEBUG

static int  log_x25_facilities (fd, coc, caption)
int     fd;
int     coc;
char   *caption;
{
    int	stat;

    enc_buf_len = sizeof(enc_buf);
    if (coc == CALLING) {
        if ((stat = getsockopt(fd,
			       X25_ACCESS,
			       XSO_ACCEPTDETAILS,
			       enc_buf,&enc_buf_len) < 0 ) ) {
	    SLOG (compat_log, LLOG_EXCEPTIONS, "failed", 
			("getsockopt(XSO_ACCEPTDETAILS)"));
    	    return NOTOK;
        }
    }

    print_x25_facilities (fd, coc, caption);

    return OK;
}

/*  */

void	*
epl_prtstr (fmt, val, vallen)
char	*fmt;
char	*val;
int	vallen;
{
	static char	abuf[128];
	static char	tbuf[128];
	char	*c, *d;

	abuf[0] = 0;
	if (vallen > 0) {
	    for (c = val, d = abuf; vallen; c++, vallen--) {
		if (!isprint(*c)) {
		    sprintf(d, " 0x%02x ", *c & 0xff);
		    d += 6;
		} else {
		    sprintf(d, "%c", *c);
		    d++;
		}
	    }
	    *d = 0;
	}
	sprintf(tbuf, fmt, abuf);
	return tbuf;
}

void	*
epl_prtbool (fmt, val, vallen)
char	*fmt;
short	*val;
int	vallen;
{
	static char	*true = "true";
	static char	*false = "false";

	if (*val == 0)
		return (true);
	else
		return (false);
}

void	*
epl_prtint (fmt, val, vallen)
char	*fmt;
short	*val;
int	vallen;
{
	static char	tbuf[128];

	sprintf(tbuf, fmt, *val);
	return tbuf;
}

void	*
epl_prtlst (fmt, val, vallen)
char	*fmt;
short	*val;
int	vallen;
{
	static char	*list = "[LIST]";

	return list;
}

static struct {
	short	code;
	char	type;
#define	EPL_STR		0
#define	EPL_BOOL	1
#define	EPL_INT		2
#define	EPL_LIST	3
	char	*fmt;
} epl_tab[] = {
    X25I_CALLEDEXTISO,	     EPL_STR,	"Address ext for dest (ISO): %s",
    X25I_CALLEDEXTNONISO,    EPL_STR,	"Non-ISO format: %s",
    X25I_CALLINGEXTISO,	     EPL_STR,	"Address ext for target (ISO): %s",
    X25I_CALLINGEXTNONISO,   EPL_STR,	"Non-ISO format: %s",
    X25I_CHARGEMON,	     EPL_STR,	"Call charge in monetary units: %s",
    X25I_CHARGESEG,	     EPL_STR,	"Call charge in segment counts: %s",
    X25I_CHARGETIME,	     EPL_STR,	"Call charge in elapsed time: %s",
    X25I_CHARGEINFO,	     EPL_BOOL,	"Charging information request: %s",
    X25I_CUG,	 	     EPL_STR,	"Closed User Group: %s",
    X25I_ETETRANSITDELAY,    EPL_LIST,	"End-to-end transit delay request: %s",
    X25I_EXPEDITE,	     EPL_BOOL,	"Interrupts allowed: %s",
    X25I_NOEXPEDITE,	     EPL_BOOL,	"Interrupts not allowed: %s",
    X25I_FASTSELECT,	     EPL_BOOL,	"Fast select facility: %s",
    X25I_FASTSELECTRESTR,    EPL_BOOL,	"Fast select restricted response : %s",
    X25I_NONX25FACILITIES,   EPL_STR,	"Non-X.25 facilities: %s",
    X25I_CALLINGSUBADDR,     EPL_STR,	"Calling DTE subaddress: %s",
    X25I_MINTHRUCLSIN,	     EPL_INT,	"Minimum throughput class incoming: %d",
    X25I_MINTHRUCLSOUT,	     EPL_INT,	"Minimum throughput class outgoing: %d",
    X25I_NETUSERID,	     EPL_STR,	"Network-specific user ID: %s",
    X25I_NSAPMAP,	     EPL_BOOL,	"NSAP mapping to DTE: %s",
    X25I_PKTSIZEIN,	     EPL_INT,	"Requested incoming packet size: %d",
    X25I_PKTSIZEOUT,	     EPL_INT,	"Requested outgoing packet size: %d",
    X25I_PRIORITY,	     EPL_STR,	"Connection priority: %s",
    X25I_PROTECTION,	     EPL_STR,	"Protection: %s",
    X25I_CALLINGDTE,	     EPL_STR,	"Calling DTE address: %s",
    X25I_RPOA,	 	     EPL_LIST,	"Specify how call is to be routed: %s",
    X25I_THRUCLSIN,	     EPL_INT,	"Maximum incoming data rate for VC: %d",
    X25I_THRUCLSOUT,	     EPL_INT,	"Maximum outgoing data rate for VC: %d",
    X25I_TRANSITDELAY,	     EPL_INT,	"Actual transit delay for our call: %d",
    X25I_USERDATA,	     EPL_STR,	"User data: %s",
    X25I_WINSIZEIN,	     EPL_INT,	"Window size for incoming call: %d",
    X25I_WINSIZEOUT,	     EPL_INT,	"Window size for outgoing call: %d",
    X25I_DTECLASS,	     EPL_STR,	"DTE class name: %s",
    X25I_TEMPLATE,	     EPL_STR,	"Template for XSO_ACCEPTCALL: %s",
    X25I_BUFFPREALLOC,	     EPL_BOOL,	"Buffer pre-allocation by gateway: %s",
    X25I_CALLEDDTE,	     EPL_STR, 	"Requested DTE address: %s",
    X25I_LOCALDTE,	     EPL_STR,	"DTE receiving incoming call: %s",
    X25I_REDIRECTREASON,     EPL_INT,	"Reason for call redirection: %d",
    0,	 0, 0,
};

print_x25_facilities (fd, coc, caption)
int	fd;
int     coc;
char   *caption;
{
    int		numitems,stat,baud,i,j;
    char	cbuf[128];
    int		cbl = sizeof(cbuf);
    char	*cptr = cbuf;
    short	lbuf[128];
    int		lbl;

    DLOG (compat_log, LLOG_DEBUG, ("%s X.25 Facilities:", caption));

    lbl = sizeof(lbuf);
    if ((numitems = X25GetItemList(enc_buf, enc_buf_len, lbuf, &lbl)) < 0) {
	SLOG (compat_log, LLOG_EXCEPTIONS, "failed",
              ("Getting Returned Facilities List"));
    }
    for (i=0;i < numitems; i++) {
        cbl = sizeof(cbuf);
        if ((stat = X25Decode(enc_buf, enc_buf_len, 
			  lbuf[i], cbuf, &cbl)) < 0) {
	    SLOG (compat_log, LLOG_EXCEPTIONS, "failed",
              ("Getting Facility [%d] = X25I_%d", i, lbuf[i]));
        }
	if (stat > 0)  {
	char	*tptr;
	    for(j=0; epl_tab[j].code != 0 && epl_tab[j].code != lbuf[i]; j++);
	    if (epl_tab[j].code == 0)
                DLOG (compat_log, LLOG_DEBUG, ("unknown facility %d", lbuf[i]));
	    else {
	        switch (epl_tab[j].type) {
	    	case EPL_STR:
		    tptr = epl_prtstr((epl_tab[j].fmt), cptr, cbl);
		    DLOG (compat_log, LLOG_DEBUG, ("%s", tptr));
		    break;
		case EPL_BOOL:
		    tptr = epl_prtbool((epl_tab[j].fmt), (short *)cptr, cbl);
		    DLOG (compat_log, LLOG_DEBUG, ("%s", tptr));
		    break;
		case EPL_INT:
		    tptr = epl_prtint((epl_tab[j].fmt), (short *)cptr, cbl);
		    DLOG (compat_log, LLOG_DEBUG, ("%s", tptr));
		    break;
		case EPL_LIST:
		    tptr = epl_prtlst((epl_tab[j].fmt), (short *)cptr, cbl);
		    DLOG (compat_log, LLOG_DEBUG, ("%s", tptr));
		    break;
		default:
                    DLOG (compat_log, LLOG_DEBUG, 
			  ("unknown type of EPL %d", epl_tab[j].code));
		    break;
	        }
	    }
        }
    }
    return OK;
}
#endif
#else   /* ULTRIX_X25 */
int     _ultrix25_stub2 () {;}
#endif  /* ULTRIX_X25 */
#else	/* X25 */
int	_ultrix25_stub () {;}
#endif  /* X25 */
