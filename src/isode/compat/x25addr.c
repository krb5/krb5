/* x25addr.c - X.25 level generic <-> interface address munging */

#ifndef lint
static char *rcsid = "$Header$";
#endif

/*
 * $Header$
 *
 * Contributed by George Michaelson, Julian Onions, and John Pavel
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

/*
 * for *really* generic address translation
 */

#include <errno.h>
#include <stdio.h>
#include "general.h"
#include "manifest.h"

#ifdef X25
#include "tailor.h"
#include "tpkt.h"
#include "sys.file.h"
#include "x25.h"

#ifndef	DEBUG
#define	DEBUG
#endif

/*  */

static int  char2bcd ();
static int  bcd2char ();

/*
 * convert from the generic X25 structure to interface specific
 */
/* ARGSUSED */
CONN_DB *gen2if (generic, specific, context)
struct NSAPaddr *generic;
CONN_DB         *specific;
int             context;
{
    int     dtelen;
    char    dte[NSAP_DTELEN + 1];
#ifdef CAMTEC_CCL
    struct iovec *iov;
#endif

    if (generic == NULLNA
	    || specific == (CONN_DB *) 0)
	return (CONN_DB *)0;
    if (generic -> na_stack != NA_X25) {
#ifdef SUN_X25			/* really NSAP specific */
#ifdef AEF_NSAP
	/* for suns, with sunnet 7.0 or >,
	 * if this a real NSAP, we have a NULL X121
	 * and let the routing tables do the business
	 */

	if (generic -> na_stack == NA_NSAP) {
	    memset ((char *)specific, 0, sizeof *specific);
	    return specific;
	}
#endif
#endif
	return (CONN_DB *)0;
    }

    if (x25_dnic_prefix && *x25_dnic_prefix) {
		/* need DNIC on local calls? */
	register int    i;

	if ( strncmp(generic -> na_dte, x25_dnic_prefix,
	    i = strlen(x25_dnic_prefix)) == 0 )
	    {
	    if (x25_strip_dnic) memcpy(dte, generic -> na_dte + i,
				       dtelen = generic -> na_dtelen - i);
	    else memcpy(dte, generic -> na_dte, dtelen = generic -> na_dtelen);
	    }
	else
	    if (x25_intl_zero)
		{
		memcpy(dte + 1, generic -> na_dte, dtelen = generic-> na_dtelen);
		*dte = '0', dtelen++;
		}
	    else memcpy(dte, generic -> na_dte, dtelen = generic -> na_dtelen);

    }
    else memcpy (dte, generic -> na_dte, dtelen = generic -> na_dtelen);
    dte[dtelen] = NULL;

#ifdef	SUN_X25_HACK
	/*	
	 * If your X.25 provider expects to receive the subaddress alone
	 * on listen requests, and you are using SunLink X.25, you may need
	 * to enable SUN_X25_HACK in your config file. This will allow you
	 * to use x25_local_dte in isotailor to specify a dte mask to be
	 * stripped when listening, and thus use full DTE strings in
	 * isoentities and QUIPU EDB files. You will also have to use the 
	 * tsapd -a <dte> option to specify the listen address in
	 * /etc/rc.local and other tsapd startups since by default this equals
	 * x25_local_dte and thus will be masked to <null> unless overridden
	 * with full DTE + subaddress. 
	 */

	/* 
	 * in ADDR_LISTEN context, it may be neccessary to only listen
	 * on the sub-address, because certain PTT-provided networks
	 * remove the local DTE from incoming CR packets. 
	 *
	 * SunLink X.25 listen asserts whatever DTE it is given as a simple
	 * string-compare, and will never receive inbound calls that bear
	 * only the sub-address if you assert the full DTE.
	 *
	 * this behaviour is orthogonal to any requirements to remove DNIC
	 * or add a leading 0 on outbound calls, and so needs a separate
	 * test. It uses tailor variable x25_local_dte to assert the local 
	 * DTE *without* subaddress which should be tested for and stripped 
	 * when detected. 
	 */

    if ((context == ADDR_LISTEN) && x25_local_dte && *x25_local_dte) 
	{
	register int    i;

	if ( strncmp(generic -> na_dte, x25_local_dte,
	    i = strlen(x25_local_dte)) == 0 ) 
	    {
	    memcpy(dte, generic -> na_dte + i, dtelen =
		   generic -> na_dtelen - i);
    	    dte[dtelen] = NULL;
	    }
	}
#endif

    DLOG (x25_log, LLOG_DEBUG,
	   ("gen2if %s -> %s, %d octets; PID %s",
	    generic -> na_dte, dte, dtelen,
	    sel2str (generic -> na_pid, (int) generic -> na_pidlen,1)));


#if !defined(CAMTEC_CCL) && !defined(HPUX_X25)
    memset ((char *)specific, 0, sizeof *specific);
#endif

#ifdef UBC_X25
    if ((specific -> xaddr_len = dtelen) != 0)  {
	memcpy (specific -> xaddr_addr, dte,
		dtelen);
	specific -> xaddr_len = dtelen;
	specific -> xaddr_facilities = 0;
	memcpy (specific -> xaddr_proto, generic -> na_pid,
		generic -> na_pidlen);
	memcpy (specific -> xaddr_userdata, generic -> na_cudf,
		generic -> na_cudflen);
    }
#endif

#ifdef HPUX_X25
    if ((dtelen != 1) || (dte [0] != '0'))
	memcpy (specific -> addr.x25_host, dte,
		specific -> addr.x25hostlen = dtelen);

    /* Zero PID */
    if (generic -> na_pidlen) { /* non-null PID */
	if (generic -> na_pidlen > NPSIZE) {
	    SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP,
		  ("PID too long (%d > %d)", generic -> na_pidlen, NPSIZE));
	    return (CONN_DB *)0;
	} else {
	    memset((char *)specific -> addr.x25pid, 0, NPSIZE);
	    memcpy ((char *)specific -> addr.x25pid, generic -> na_pid,
		    specific -> addr.x25pidlen = generic -> na_pidlen);
	    memcpy ((char *)specific -> cudf.x25_cu_data, generic -> na_pid,
		    specific -> cudf.x25_cud_len = generic -> na_pidlen);
	}
	/* copy in CUDF */
	if (generic -> na_cudflen) {
	    if (generic -> na_cudflen + specific -> cudf.x25_cud_len > X25_MAX_C
		U_LEN) {
		SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP,
		      ("CALL-USERDATA too long (%d > %d)",
		       generic -> na_cudflen + specific -> cudf.x25_cud_len,
		       X25_MAX_CU_LEN));
		return (CONN_DB *)0;
	    } else {
		memcpy (&specific -> cudf.x25_cu_data [specific -> cudf.x25_cud_len],
			generic -> na_cudf,
			generic -> na_cudflen);
		specific -> cudf.x25_cud_len += generic -> na_cudflen;
	    }
	}
    } else {
	/* PID ws empty, use first four Byte of cudf */
	/* CUDF has PID - I hope so */
	memcpy (specific -> addr.x25pid, generic -> na_cudf,
		specific -> addr.x25pidlen =
		(generic -> na_cudflen <= NPSIZE) ?
		generic -> na_cudflen : NPSIZE);
	if (generic -> na_cudflen > X25_MAX_CU_LEN) {
	    SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP,
		  ("CALL-USERDATA too long (%d > %d)",
		   generic -> na_cudflen - NPSIZE, X25_MAX_CU_LEN));
	    return (CONN_DB *)0;
	} else
	    memcpy (specific -> cudf.x25_cu_data, generic -> na_cudf,
		    specific -> cudf.x25_cud_len = generic -> na_cudflen);
    }

#endif

#ifdef SUN_X25
    specific -> hostlen = char2bcd (dte, dtelen, specific -> host);

    /* Zero PID */
    if (generic -> na_pidlen) { /* non-null PID */
	if (generic -> na_pidlen > NPSIZE) {
	    SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP,
		  ("PID too long (%d > %d)", generic -> na_pidlen, NPSIZE));
	    return (CONN_DB *)0;
	} else {
	    memset((char *)specific -> data, 0, NPSIZE);
	    memcpy ((char *)specific -> data, generic -> na_pid,
		    generic -> na_pidlen);
	    memcpy ((char *) specific -> data + NPSIZE, generic -> na_cudf,
		    generic -> na_cudflen);
	    specific -> datalen = generic -> na_pidlen + generic -> na_cudflen;
	}
    } else { /* Null PID (just copy in CUDF, the first four octets of which
		will be the PID in any case) */
	 memcpy ((char *)specific -> data, generic -> na_cudf,
		 generic -> na_cudflen);
	 specific -> datalen = generic -> na_cudflen;
    }
#endif

#ifdef CAMTEC_CCL
    switch (context) {
	case ADDR_REMOTE:
	    iov = &(specific -> ccl_iovec[0]);
	    if (x25_outgoing_port == '#') {
		char *a, *b;
		int i;

		iov -> iov_len = dtelen + 4;
		memset(iov -> iov_base, 0, iov -> iov_len + 1);
		a = iov -> iov_base;
		b = dte;
		*a++ = '#';
		*a++ = '[';
		for (i = 0; i < dtelen; i++) {
			if (i == 2) *a++ = ':';
			else if (i == 14) *a++ = ']';
			*a++ = *b++;
		}
	    }
	    else {
		iov -> iov_len = dtelen+1;
		memcpy((iov -> iov_base)+1, dte, dtelen);
		*(iov -> iov_base) = x25_outgoing_port;
	    }
	    break;

	case ADDR_LOCAL:
	    iov = &(specific -> ccl_iovec[0]);
	    strncpy(iov -> iov_base, generic -> na_dte, generic -> na_dtelen);
	    iov -> iov_base[generic -> na_dtelen] = '\0';
	    return (specific);

	case ADDR_LISTEN:
	    iov = &(specific -> ccl_iovec[0]);
	    if (generic -> na_pidlen)
		{                       /* listen on a PID */
		register int i;
		iov -> iov_base[0] = 'C';
		memcpy(iov -> iov_base + 1, generic -> na_pid,
		       i = generic -> na_pidlen);
		iov -> iov_len = i + 1;
		}
	    else
	    if (generic -> na_dtelen < 6)
		{           /* listen on a subaddress */
		register int i;
		iov -> iov_base[0] = 'S';
		memcpy(iov -> iov_base + 1, generic -> na_dte,
		       i = generic -> na_dtelen);
		iov -> iov_len = i + 1;
		}
	    else    /* full DTE */
		memcpy(iov -> iov_base, dte,
		       iov -> iov_len = dtelen);
	    return (specific);
    }
    /*
     * CUDF & PID must be merged. malloc initailly PIDsize space
     * and zero it. this may be UK net specific action which
     * ensures we do NOT fall foul of listeners which use pid
     * to match as well as "true" cudf & DTE.
     */

    (iov = &(specific -> ccl_iovec[2])) -> iov_len = 0;
    if (generic -> na_faclen != 0)
	memcpy ( iov -> iov_base, generic -> na_fac,
		iov -> iov_len = min( generic -> na_faclen, FACSIZE) );
    iov++;
    if ( (iov -> iov_len = generic -> na_pidlen) != 0)
	memcpy ( iov -> iov_base, generic -> na_pid, generic -> na_pidlen);

    /*
     * if there is any other user data add that in now...
     * actually cudf is a variable length field so this is
     * all very suspect.
     */

    if (generic -> na_cudflen != 0)
	memcpy(iov -> iov_base + iov -> iov_len, generic -> na_cudf,
	       generic -> na_cudflen), iov -> iov_len += generic -> na_cudflen;
#endif

#ifdef	ULTRIX_X25
    if (generic -> na_dtelen  != 0) {
        specific -> na_dtelen = specific -> na_pidlen 
		= specific -> na_cudflen = 0;
	memcpy (specific -> na_dte,
		generic -> na_dte, 
		specific -> na_dtelen = generic -> na_dtelen);
        /*
         * concatenate PID and CUDF into CUDF buffer.
         */
        if (generic -> na_pidlen > 0) {
	    memcpy (specific -> na_cudf,
		    generic -> na_pid, 
		    specific -> na_cudflen = generic -> na_pidlen);
        }
        if (generic -> na_cudflen > 0) {
	    memcpy (specific -> na_cudf + specific -> na_pidlen,
		    generic -> na_cudf, 
		    generic -> na_cudflen);
	    specific -> na_cudflen += generic -> na_cudflen;
        }
    }
#endif	/* ULTRIX_X25 */
    return(specific);
}

/*  */

/*
 * convert from interface specific format to generic X.25 structure
 */
/* ARGSUSED */
struct NSAPaddr *if2gen (generic, specific, context)
struct NSAPaddr *generic;
CONN_DB         *specific;
int             context;
{
    int     dtelen;
    char    dte[NSAP_DTELEN + 1];
#ifdef CAMTEC_CCL
    struct iovec *iov;
#endif

    if (generic == NULLNA || specific == (CONN_DB *) 0)
	return NULLNA;
    memset ((char *)generic, 0, sizeof *generic);
    memset (dte, 0, sizeof dte);
    dtelen = 0;

    generic -> na_stack = NA_X25;
    generic -> na_community = ts_comm_x25_default;

#ifdef UBC_X25
    if (specific -> xaddr_len  != 0) {
	memcpy (dte, specific -> xaddr_addr, specific -> xaddr_len);
	dtelen = specific -> xaddr_len;
	memcpy (generic -> na_pid, specific -> xaddr_proto,
		sizeof(specific -> xaddr_proto));
	generic -> na_pidlen = sizeof specific -> xaddr_proto;
	memcpy (generic -> na_cudf, specific -> xaddr_userdata,
		sizeof(specific -> xaddr_userdata));
	generic -> na_cudflen = sizeof specific -> xaddr_userdata;
    }
#endif

#ifdef SUN_X25
    dtelen = bcd2char (specific -> host, dte, (int) specific -> hostlen);

    if (specific -> datalen > NPSIZE) { /* have some real user data after the PID */
	memcpy(generic -> na_pid, (char *)specific -> data,
	       generic -> na_pidlen = NPSIZE);
	memcpy(generic -> na_cudf, 
	       (char *) specific -> data + generic -> na_pidlen,
	       generic -> na_cudflen = specific -> datalen - generic -> na_pidlen);
    }
    else { /* PID only */
	memcpy(generic -> na_pid, (char *)specific -> data,
	       generic -> na_pidlen = specific -> datalen);
	generic -> na_cudflen = 0;
    }

#endif

#ifdef HPUX_X25
    if (specific -> addr.x25hostlen)
	memcpy (dte, specific -> addr.x25_host,
		dtelen = specific -> addr.x25hostlen);
    else {
	dte [0] = '0';
	dte [1] = NULL;
	dtelen = 1;
    }

    if (specific -> addr.x25pidlen > NPSIZE) {
	SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP,
	      ("PID too long (%d > %d)", specific -> addr.x25pidlen, NPSIZE));
	specific -> addr.x25pidlen = NPSIZE;
    }
    memcpy(generic -> na_pid, (char *)specific -> addr.x25pid,
	   generic -> na_pidlen = specific -> addr.x25pidlen);

    if (specific -> cudf.x25_cud_len) {
	memcpy (generic -> na_cudf, specific -> cudf.x25_cu_data,
		generic -> na_cudflen = specific -> cudf.x25_cud_len);
    }
#endif


#ifdef CAMTEC_CCL
    switch (context) {
    case ADDR_REMOTE:

	iov = &(specific -> ccl_iovec[1]);
	if (iov -> iov_len) {
		if (*(iov->iov_base) == '#') {
			char *a;

			a = iov -> iov_base;
			while (*a && iov -> iov_len) {
				if (*a == ']') {
					iov -> iov_len--;
					a++;
					break;
				}
				iov -> iov_len--;
				a++;
			}
			if (*a == 0 || iov -> iov_len == 0)
				dtelen = 0;
			else {
				dtelen = iov -> iov_len;
				memcpy (dte, a, dtelen);
			}
		}
		else {
			dtelen = iov -> iov_len - 1;
			memcpy (dte, (iov -> iov_base)+1,
				dtelen);
		}
	}
	else dtelen = 0;
	break;

    case ADDR_LOCAL:
	iov = &(specific -> ccl_iovec[0]);
	if (iov -> iov_len) {
		dtelen = iov -> iov_len -1;
		memcpy (dte, (iov -> iov_base)+1,
			dtelen);
	}
	else dtelen = 0;
	break;

    case ADDR_LISTEN:
	return NULLNA;
    }

    if ( (iov = &(specific -> ccl_iovec[2])) -> iov_len )
	memcpy(generic -> na_fac,  iov -> iov_base,
	       generic -> na_faclen = min( iov -> iov_len, FACSIZE));

    if ( ++iov -> iov_len)
	{
	memcpy(generic -> na_pid,  iov -> iov_base,
	       generic -> na_pidlen = min( iov -> iov_len, NPSIZE));
	if ( iov -> iov_len > NPSIZE)
	    memcpy(generic -> na_cudf,  iov -> iov_base + NPSIZE,
		   generic -> na_cudflen = min(iov -> iov_len - NPSIZE, CUDFSIZE));
	}
#endif

#ifdef	ULTRIX_X25
    if (specific -> na_dtelen  > 0) {
	memcpy (dte, specific -> na_dte, specific -> na_dtelen);
	dtelen = specific -> na_dtelen;

	/*
	 * if CUDF non-zero, copy up to first NPSIZE (or cufdlen if less) 
	 * bytes into pid field and shift remainder down.
	 */
	if (specific -> na_cudflen > 0) {
	    memcpy(generic -> na_pid,
		   specific -> na_cudf, 
		   generic -> na_pidlen = (specific -> na_cudflen <= NPSIZE ? 
					   specific -> na_cudflen : NPSIZE));
	    if (specific -> na_cudflen > NPSIZE) {
	        memcpy(generic -> na_cudf,
		       specific -> na_cudf + NPSIZE, 
		       generic -> na_cudflen = specific -> na_cudflen - NPSIZE);
	    }
	} else {
	    generic -> na_pidlen = 0;
	    generic -> na_pid[0] = 0;
	    generic -> na_cudflen = 0;
	    generic -> na_cudf[0] = 0;
	}
    }
#endif	/* ULTRIX_X25 */

    if (x25_dnic_prefix && *x25_dnic_prefix) {
	register int    i;

	i = 0;
	if (x25_intl_zero && dte[0] == '0' && dte[1] != '0')
	    i = 1;
	else
	    if (x25_dnic_prefix
		    && *x25_dnic_prefix
		    && x25_strip_dnic
		    && dtelen < 12)   /* local call... */
		memcpy (generic -> na_dte, x25_dnic_prefix,
			generic -> na_dtelen = strlen (x25_dnic_prefix));

	memcpy (generic -> na_dte + generic -> na_dtelen, dte + i, dtelen - i);
	generic -> na_dtelen += dtelen - i;
    }
    else
	memcpy (generic -> na_dte, dte, generic -> na_dtelen = dtelen);

    DLOG (x25_log, LLOG_DEBUG,
	   ("if2gen %s -> %s, %d octets; PID %s",
	    dte, generic -> na_dte, generic -> na_dtelen,
	    sel2str (generic -> na_pid, (int) generic -> na_pidlen,1)));

    return(generic);
}

/*  */

elucidate_x25_err (flags, pkt)
int flags;
unsigned char * pkt;
{
    char * cp;

    if (flags & (1 << RECV_DIAG)) {
#ifdef HPUX_X25
	if (flags & (1 << DIAG_TYPE)) /* cleared */
	    SLOG (x25_log, LLOG_EXCEPTIONS, NULLCP,
		  ("cleared 0x%02x", pkt[0] ));
	else if (flags & (1 << REST_TYPE))
	    SLOG (x25_log, LLOG_EXCEPTIONS, NULLCP,
		  ("restart 0x%02x", pkt[0] ));
	else
	    SLOG (x25_log, LLOG_EXCEPTIONS, NULLCP,
		  ("reset 0x%02x", pkt[0] ));

#else
	SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP,
	      (( flags & (1 << DIAG_TYPE) ) ?
	       "cleared 0x%02x" : "reset 0x%02x",
	       pkt[0] ));
#endif

	if ((flags) & (1 << DIAG_TYPE)) /* cleared */
	    switch(pkt[0]) {
		case 0x00:
		    cp = "DTE Clearing";
		    break;

		case 0x01:
		    cp = "Number Busy";
		    break;

		case 0x09:
		    cp = "Out of Order";
		    break;

		case 0x11:
		    cp = "Remote Procedure Error";
		    break;

		case 0x19:
		    cp = "Reverse Charging not subscribed";
		    break;

		case 0x03:
		    cp = "Invalid Facility Request";
		    break;

		case 0x0B:
		    cp = "Access Barred";
		    break;

		case 0x13:
		    cp = "Local Procedure Error";
		    break;

		case 0x05:
		    cp = "Network Congestion";
		    break;

		case 0x0D:
		    cp = "Not Obtainable";
		    break;

		case 0x21:
		    cp = "DTE Incompatible Call";
		    break;

		case 0x29:
		    cp = "Fast Select Acceptance not Subscribed";
		    break;

		default:
		    SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP,
			  ("clearing cause 0x2%x", pkt[0]));
		    goto next;
	    }
#ifdef HPUX_X25
      else if ((flags) & (1 << REST_TYPE))
          switch((unsigned char)(pkt[0] & 0x7f)) {
	  case 0x01:
	      cp = "Local Procedure Error";
	      break;

	  case 0x03:
	      cp = "Network Congestion";
	      break;

	  case 0x07:
	      cp = "Network Operational";
	      break;

	  case 0x7f:
	      cp = "Registration/Cancellation Confirmed";
	      break;

	  default:
	      SLOG (x25_log, LLOG_EXCEPTIONS, NULLCP,
		    ("restarting cause 0x2%x", pkt[0]));
	      goto next;
          }
#endif
	else /* reset */
	    switch(pkt[0]) {
		case 0x00:
		    cp = "DTE Reset";
		    break;

		case 0x01:
		    cp = "Out of Order (PVC Only)";
		    break;

		case 0x03:
		    cp = "Remote Procedure Error";
		    break;

		case 0x05:
		    cp = "Local Procedure Error";
		    break;

		case 0x07:
		    cp = "Network Congestion";
		    break;

		case 0x09:
		    cp = "Remote DTE Operational (PVC Only)";
		    break;

		case 0x0F:
		    cp = "Network Operational (PVC Only";
		    break;

		default:
		    SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP,
			  ("resetting cause 0x%2x", pkt[0]));
		    goto next;

	    }
#ifdef HPUX_X25
	if (flags & (1 << DIAG_TYPE)) /* cleared */
	    SLOG (x25_log, LLOG_EXCEPTIONS, NULLCP,
		  ("%sclearing cause: %s (%d)",
		   (pkt[0] & 0x80) ? "Remote DTE " : "", cp, pkt [0]));
	else if (flags & (1 << REST_TYPE))
	    SLOG (x25_log, LLOG_EXCEPTIONS, NULLCP,
		  ("%srestarting cause: %s (%d)",
		   (pkt[0] & 0x80) ? "Remote DTE " : "", cp, pkt [0]));
	else
	    SLOG (x25_log, LLOG_EXCEPTIONS, NULLCP,
		  ("%sresetting cause: %s (%d)",
		   (pkt[0] & 0x80) ? "Remote DTE " : "", cp, pkt [0]));
#else
	SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP, ("%s%s",
	    ( flags & (1 << DIAG_TYPE) ) ? "clearing cause " :
	    "resetting cause ", cp));

#endif

next: ;
	/* The following may only be applicable to PSS in the UK */
	/* In any case, if someone is keen, they can stuff it all
	   into a text file and read it out */

	switch (pkt[1]) {
	    case 0x00:
		cp = "NO ADDITIONAL INFORMATION";
		break;

	    case 0x01:
		cp = "INVALID P(S)\tRESET";
		break;

	    case 0x02:
		cp = "INVALID P(R)\tRESET";
		break;

	    case 0x11:
		cp = "PACKET TYPE INVALID FOR STATE r1\tRESTART";
		break;

	    case 0x12:
		cp = "PACKET TYPE INVALID FOR STATE r2\tRESTART";
		break;

	    case 0x13:
		cp = "PACKET TYPE INVALID FOR STATE r3\tRESTART";
		break;

	    case 0x14:
		cp = "PACKET TYPE INVALID FOR STATE p1\tCLEAR";
		break;

	    case 0x15:
		cp = "PACKET TYPE INVALID FOR STATE p2\tCLEAR";
		break;

	    case 0x16:
		cp = "PACKET TYPE INVALID FOR STATE p3\tCLEAR";
		break;

	    case 0x17:
		cp = "PACKET TYPE INVALID FOR STATE p4\tCLEAR";
		break;

	    case 0x18:
		cp = "PACKET TYPE INVALID FOR STATE p5\tRESET";
		break;

	    case 0x19:
		cp = "PACKET TYPE INVALID FOR STATE p6\tCLEAR";
		break;

	    case 0x1A:
		cp = "PACKET TYPE INVALID FOR STATE p7\tCLEAR";
		break;

	    case 0x1B:
		cp = "PACKET TYPE INVALID FOR STATE d1\tRESET";
		break;

	    case 0x1C:
		cp = "PACKET TYPE INVALID FOR STATE d2\tRESET";
		break;

	    case 0x1D:
		cp = "PACKET TYPE INVALID FOR STATE d3\tRESET";
		break;

	    case 0x20:
		cp = "PACKET NOT ALLOWED";
		break;

	    case 0x21:
		cp = "UNIDENTIFIABLE PACKET";
		break;

	    case 0x22:
		cp = "CALL ON ONE-WAY LOGICAL CHANNEL\tCLEAR";
		break;

	    case 0x23:
		cp = "INVALID PACKET TYPE ON PVC\tRESET";
		break;

	    case 0x24:
		cp = "PACKET ON UNASSIGNED LCN\tCLEAR";
		break;

	    case 0x25:
		cp = "REJECT NOT SUBSCRIBED TO\tRESET";
		break;

	    case 0x26:
		cp = "PACKET TOO SHORT\tRESET";
		break;

	    case 0x27:
		cp = "PACKET TOO LONG\tRESET";
		break;

	    case 0x28:
		cp = "INVALID GFI\tCLEAR";
		break;

	    case 0x29:
		cp = "RESTART WITH NON-ZERO BITS 5-16";
		break;

	    case 0x2A:
		cp = "PACKET TYPE NOT COMPATIBLE WITH FACILITY\tCLEAR";
		break;

	    case 0x2B:
		cp = "UNAUTHORISED INTERRUPT CONF\tRESET";
		break;

	    case 0x2C:
		cp = "UNAUTHORISED INTERRUPT\tRESET";
		break;

	    case 0x31:
		cp = "TIMER EXPIRED;  INCOMING CALL";
		break;

	    case 0x32:
		cp = "TIMER EXPIRED;\tCLEAR INDICATION";
		break;

	    case 0x33:
		cp = "TIMER EXPIRED;\tRESET INDICATION";
		break;

	    case 0x34:
		cp = "TIMER EXPIRED;\tRESTART IND";
		break;

	    case 0x40:
		cp = "UNSPECIFIED CALL SET-UP PROBLEM CLEAR";
		break;

	    case 0x41:
		cp = "FACILITY CODE NOT ALLOWED\tCLEAR";
		break;

	    case 0x42:
		cp = "FACILITY PARAMETER NOT ALLOWED\tCLEAR";
		break;

	    case 0x43:
		cp = "INVALID CALLED ADDRESS\tCLEAR";
		break;

	    case 0x44:
		cp = "INVALID CALLING ADDRESS\tCLEAR";
		break;

	    case 0x90:
		cp = "DTE/DCE CONGESTION\tRESET";
		break;

	    case 0x91:
		cp = "RECEIVED FAST SELECT CLEAR REQUEST";
		break;

	    case 0x92:
		cp = "LINE RESTARTING BY INMC COMMAND\tRESTART";
		break;

	    case 0xA0:
#ifdef HPUX_X25
		cp = "REVERSE CHARGE REQUESTED WHEN NOT ALLOWED - RESET";
 #else
		cp = "NON-ZERO RESET CAUSE FROM DTE\tRESET";
#endif
		break;

	    case 0xA1:
#ifdef HPUX_X25
		cp = "LEVEL 2 IS COMING UP - RESET";
#else
		cp = "DATA PACKET TOO LONG\tRESET";
#endif
		break;

	    case 0xA2:
#ifdef HPUX_X25
		cp = "LEVEL 2 OR 3 IS DOWN - RESET";
#else
		cp = "INTERRUPT PACKET TOO LONG\tRESET";
#endif
		break;

	    case 0xA3:
#ifdef HPUX_X25
		cp = "LACK OF MEMORY - RESET";
#else
		cp = "INT PACKET TOO SHORT; NO USER DATA\tRESET";
#endif
		break;

	    case 0xA4:
#ifdef HPUX_X25
		cp = "FAST SELECT NOT SUBSCRIBED - CLEAR";
#else
		cp = "INT CONFIRMATION PACKET TOO LONG\tRESET";
#endif
		break;

	    case 0xA5:
		cp = "RR PACKET TOO LONG\tRESET";
		break;

	    case 0xA6:
		cp = "RNR PACKET TOO LONG\tRESET";
		break;

	    case 0xA7:
		cp = "RESET PACKET TOO LONG\tRESET";
		break;

	    case 0xA8:
		cp = "RESET CONF PACKET TOO LONG\tRESET";
		break;

	    case 0xA9:
		cp = "INVALID `Q' BIT IN DATA PACKET\tRESET";
		break;

	    case 0xAA:
		cp = "PACKET WINDOW RANGE EXCEEDED\tRESET";
		break;

	    case 0xAB:
		cp = "UNABLE TO TRANSMIT PACKET\tRESET";
		break;

	    case 0xAC:
		cp = "diagnostic `Q' BIT SET IN NON-DATA PACKET\tRESET";
		break;

	    case 0xAD:
		cp = "OUTSTANDING PACKET COUNT LESS THAN ZERO\tRESET";
		break;

	    case 0xAE:
		cp = "RETRANSMISSION ERROR\tRESET";
		break;

	    case 0xAF:
		cp = "RESET PACKET TOO SHORT (NO CAUSE)\tRESET";
		break;

	    case 0xB0:
		cp = "REJECT PACKET TOO LONG\tRESET";
		break;

	    case 0xB1:
		cp = "INVALID 1D PACKET\tRESET";
		break;

	    case 0xB2:
		cp = "UNSUCCESSFUL RECONNECTION RESNC\tCLEAR";
		break;

	    case 0xB3:
		cp = "NON-RECONNECT CALL IN STATE C1\tCLEAR";
		break;

	    case 0xB4:
		cp = "SECOND 1D PACKET FROM DTE\tCLEAR";
		break;

	    case 0xB5:
		cp = "BAD DATA TRANSFER STATE IN RECONNECT\tCLEAR";
		break;

	    case 0xB6:
		cp = "PACKET FORMAT INVALID\tCLEAR";
		break;

	    case 0xB7:
		cp = "FACILITY BYTE COUNT TOO LARGE\tCLEAR";
		break;

	    case 0xB8:
		cp = "INVALID PACKET DETECTED\tCLEAR";
		break;

	    case 0xB9:
		cp = "FACILITY/UTILITY FIELD BYTE COUNT > 63\tCLEAR";
		break;

	    case 0xBA:
		cp = "OUTGOING CALLS BARRED\tCLEAR";
		break;

	    case 0xBB:
		cp = "INCOMING CALLS BARRED\tCLEAR";
		break;

	    case 0xBC:
		cp = "CLEARING OF PVC\tCLEAR";
		break;

	    case 0xBD:
		cp = "CALLED ADDRESS TOO LONG\tCLEAR";
		break;

	    case 0xBE:
		cp = "CALLED ADDRESS TOO SHORT\tCLEAR";
		break;

	    case 0xBF:
		cp = "CALLING ADDRESS TOO LONG\tCLEAR";
		break;

	    case 0xC0:
		cp = "CALLING ADDRESS TOO SHORT\tCLEAR";
		break;

	    case 0xC1:
		cp = "BCD ERROR IN CALL ADDRESS\tCLEAR";
		break;

	    case 0xC2:
		cp = "BCD ERROR IN CALLING ADDRESS\tCLEAR";
		break;

	    case 0xC3:
		cp = "USER DATA FIELD TOO LONG\tCLEAR";
		break;

	    case 0xC4:
		cp = "NO BUFFER AVAILABLE\tCLEAR";
		break;

	    case 0xC5:
		cp = "LOCAL DTE IS NOT ENHANCED\tCLEAR";
		break;

	    case 0xC6:
		cp = "FACILITY NEGOTIATION INVALID\tCLEAR";
		break;

	    case 0xC7:
		cp = "MANDATORY UTILITY NOT INPUT\tCLEAR";
		break;

	    case 0xC8:
		cp = "BUFFER NO AVAILABLE FOR TNIC\tCLEAR";
		break;

	    case 0xC9:
		cp = "OVERFLOW OF TNIC IN BUFFER\tCLEAR";
		break;

	    case 0xCA:
		cp = "DTE LINE CONGESTED\tCLEAR";
		break;

	    case 0xCB:
		cp = "TABLE ERROR IN PACKET PROCEDURES";
		break;

	    case 0xCC:
		cp = "INSERT TABLE OVERFLOW";
		break;

	    case 0xCD:
		cp = "DELETE TABLE OVERFLOW";
		break;

	    case 0xD0:
		cp = "TRUNK LINE RESTART\tRESTART";
		break;

	    case 0xD1:
		cp = "INVALID EVENT IN STATE p2";
		break;

	    case 0xD2:
		cp = "INVALID EVENT IN STATE p3";
		break;

	    case 0xD3:
		cp = "INVALID 1D EVENT IN STATE d1";
		break;

	    case 0xD4:
		cp = "CALL COLLISION ON TRUNK LINE";
		break;

	    case 0xD5:
		cp = "NO BUFFER AVAILABLE";
		break;

	    case 0xD6:

		cp = "CALL COLLISION ON DTE LINE";
		break;

	    case 0xD7:
		cp = "DTE RESTART";
		break;

	    case 0xD8:
		cp = "CALL REQUEST TO TRUNK LINE TIMEOUT";
		break;

	    case 0xD9:
		cp = "RECONNECT SET-UP TIMED OUT";
		break;

	    case 0xDA:
		cp = "INVALID OUTPUT SIDE STATE";
		break;

	    case 0xDB:
		cp = "ERROR DETECTED IN BLINK PACKET QUEUE PROCEDURE";
		break;

	    case 0xDC:
		cp = "RESET INDICATION RETRANSMISSION COUNT EXPIRED";
		break;

	    case 0xDD:
		cp = "INVALID OUTPUT SIDE STATE";
		break;

	    case 0xDE:
		cp = "BLIND BUFFER QUEUE OVERFLOW IN STATE d4";
		break;

	    case 0xDF:
		cp = "BLIND BUFFER QUEUE OVERFLOW IN STATE c1";
		break;

	    case 0xE0:
		cp = "BLIND BUFFER QUEUE OVERFLOW IN STATE c2";
		break;

	    case 0xE1:
#ifdef HPUX_X25
		cp = "DISCONNECTION (TRANSIENT CONDITION) - CLEAR";
#else
		cp = "CLEAR PACKET BYTE COUNT TOO LARGE OR TOO SMALL";
#endif
		break;

	    case 0xE2:
#ifdef HPUX_X25
		cp = "CONNECTION REJECTION (TRANSIENT CONDITION) - CLEAR";
#else
		cp = "NON-ZERO\tCLEAR CAUSE";
#endif
		break;

	    case 0xE3:
		cp = "CLEAR CONF PACKET BYTE COUNT TOO SMALL OR TOO LARGE";
		break;

	    case 0xE4:
#ifdef HPUX_X25
		cp = "CONNECTION REJECTION (REASON UNSPECIFIED) - CLEAR";
#else
		cp = "CALL COLLISION";
#endif
		break;

	    case 0xE5:
		cp = "INVALID TP LOAD REQUEST CALL PKT";
		break;

	    case 0xE6:
		cp = "MAXIMUM HOPCOUNT EXCEEDED";
		break;

	    case 0xE7:
#ifdef HPUX_X25
		cp = "NSAP UNREACHABLE (TRANSIENT CONDITION) - CLEAR";
#else
		cp = "ROUTING LOOP DETECTED";
#endif
		break;

	    case 0xE8:
#ifdef HPUX_X25
		cp = "NSAP UNREACHABLE (PERMANENT CONDITION) - CLEAR";
#else
		cp = "PVC CALL REQUEST FAILURE";
#endif
		break;

	    case 0xE9:
#ifdef HPUX_X25
		cp = "RESET CAUSE UNSPECIFIED - RESET";
#else
		cp = "RECONNECT CALL REQUEST FAILED";
#endif
		break;

	    case 0xEA:
		cp = "NO LC AVAILABLE ON OUTPUT SIDE";
		break;

	    case 0xEB:
		cp = "NO BUFFER AVAILABLE";
		break;

	    case 0xEC:
		cp = "CALL REDIRECTION CLEAR";
		break;

	    case 0xED:
		cp = "NO PATH ROUTE CALL";
		break;

	    case 0xEE:
		cp = "CALL ROUTED TO DTE LINE";
		break;

	    case 0xEF:
		cp = "CALL CANNOT BE REROUTED";
		break;

	    case 0xF0:
		cp = "ADDRESS NOT IN ROUTING TABLES";
		break;

	    case 0xF1:
#ifdef HPUX_X25
		cp = "NORMAL DISCONNECTION - CLEAR";
#else
		cp = "ROUTING TABLE CHANGE DURING CALL ROUTING";
#endif
		break;

	    case 0xF2:
#ifdef HPUX_X25
		cp = "ABNORMAL DISCONNECTION - CLEAR";
#else
		cp = "NO LC AVAILABLE ON FAKE TRUNK";
#endif
		break;

	    case 0xF3:
		cp = "REMOTE DTE DOWN ON A PVC";
		break;

	    case 0xF4:
		cp = "INVALID EVENT DETECTED";
		break;

	    case 0xF5:
		cp = "INVALID PACKET RECEIVED; STATE d4";
		break;

	    case 0xF6:
		cp = "INVALID PACKET RECEIVED; STATE d5";
		break;

	    case 0xF7:
		cp = "INVALID PACKET RECEIVED; STATE p8";
		break;

	    case 0xF8:
		cp = "INTERNAL PROCESSING FAILURE";
		break;

	    case 0xF9:
		cp = "INVALID RESTART INDICATION";
		break;

	    case 0xFA:
#ifdef HPUX_X25
		cp = "USER SYNCHRONISATION - RESET";
#else
		cp = "LINE STATUS CHANGE IN STATE r4";
#endif
		break;

	    case 0xFB:
		cp = "INVALID PACKET RECEIVED; STATE r4";
		break;

	    case 0xFC:
		cp = "INVALID PACKET RECEIVED; STATE r3";
		break;

	    case 0xFD:
		cp = "LINE STATUS CHANGE IN STATE r2";
		break;

	    case 0xFE:
		cp = "LINE STATUS CHANGE IN STATE r1";
		break;

	    case 0xFF:
		cp = "LINE STATUS CHANGE IN STATE r0";
		break;

	    default:
		SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP,
		      ("diagnostic: 0x%2x", pkt[1]));
		goto done;
	}
	SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP, ("diagnostic %s", cp));
#ifdef HPUX_X25
	if (flags & (1 << DIAG_TYPE)) /* cleared */
	    SLOG (x25_log, LLOG_EXCEPTIONS, NULLCP,
		  ("clearing source: %s (%d)",
		   pkt [2] ? "X25-Level 2" : "network prov./firmware",
		   pkt [2] ));
	else if (flags & (1 << REST_TYPE))
	    SLOG (x25_log, LLOG_EXCEPTIONS, NULLCP,
		  ("restart source unknown (%d)", pkt [2] ));
	else
	    SLOG (x25_log, LLOG_EXCEPTIONS, NULLCP,
		  ("resetting source: %s (%d)",
		   pkt [2] ? "network provider" : "undefined", pkt [2] ));
#endif
    }
    else        /* Not RECV_DIAG */
#ifdef HPUX_X25
	SLOG (x25_log, LLOG_EXCEPTIONS, NULLCP,
	      ("cause: 0x%02x - diag code: 0x%02x", pkt [0], pkt [1]));
#else
    if (flags)
	SLOG (compat_log, LLOG_EXCEPTIONS, NULLCP,
	      ("diag flags: 0x%02x", flags));
#endif

done: ;
    return OK;
};

/*  */

#ifdef  SUN_X25
#ifdef AEF_NSAP
int nsap2if (nsap, aef)
struct NSAPaddr *nsap;
AEF *aef;
{
    char buf[NASIZE*2+1];
    int len;

    if (nsap -> na_stack != NA_NSAP)
	return NOTOK;
    aef -> aef_type = AEF_NSAP;
    len = explode (buf, (u_char *) nsap -> na_address, nsap -> na_addrlen);
    aef -> aef_len = char2bcd (buf, len, aef -> aef);
    return OK;
}
#endif

static int  char2bcd (s, n, d)
register char   *s;
int n;
register u_char *d;
{
    register int    c,
		    i;

    for (i = 0; *s && n-- > 0; i++) {
	if ((c = *s++) >= 'a' && c <= 'f')
	    c -= 'a' + 0x0a;
	else
	    if (c >= 'A' && c <= 'F')
		c -= 'A' + 0x0a;
	    else
		if (c >= '0' && c <= '9')
		    c -= '0';
		else
		    c = 0;

	if (i & 1)
	    *d++ |= c & 0xf;
	else
	    *d = (c & 0xf) << 4;
    }

    return i;
}

/*  */
#ifdef AEF_NSAP
int if2nsap (aef, nsap)
AEF	*aef;
struct NSAPaddr *nsap;
{
    char buf[NASIZE*2+1];
    int len;

    if (aef -> aef_type != AEF_NSAP)
	return NOTOK;

    nsap -> na_stack = NA_NSAP;
    len = bcd2char (aef -> aef, buf, (int)aef -> aef_len);
    nsap -> na_addrlen = implode ((u_char *) nsap -> na_address, buf, len);
    return OK;
}
#endif

static int     bcd2char (s, d, len)
register    u_char *s;
register char  *d;
int     len;
{
    register int    i,
		    g;

    for (i = 0; i < len; i++) {
	g = s[i >> 1];
	if ((i & 1) == 0)
	    g >>= 4;
	g &= 0xf;

	if (g < 0x0a)
	    *d++ = g + '0';
	else
	    *d++ = g + 'a' - 0x0a;
    }

    *d = NULL;

    return len;
}
#endif
#else
int	_x25addr_stub () {}
#endif
