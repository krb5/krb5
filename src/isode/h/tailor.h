/* tailor.h - ISODE tailoring */

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:30:03  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:18:27  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:38:41  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:33:57  isode
 * Release 7.0
 * 
 * 
 */

/*
 *				  NOTICE
 *
 *    Acquisition, use, and distribution of this module and related
 *    materials are subject to the restrictions of a license agreement.
 *    Consult the Preface in the User's Manual for the full terms of
 *    this agreement.
 *
 */


#ifndef	_TAILOR_
#define	_TAILOR_

#ifndef	_LOGGER_
#include "logger.h"
#endif


/* SYSTEM AREAS */

extern char    *isodename;
extern char    *isodebinpath;
extern char    *isodesbinpath;
extern char    *isodetcpath;
extern char    *isodelogpath;


/* LOGGING */

extern LLog *compat_log, _compat_log;
extern LLog *addr_log, _addr_log;
extern LLog *tsap_log, _tsap_log;
extern LLog *ssap_log, _ssap_log;
extern LLog *psap_log, _psap_log;
extern LLog *psap2_log, _psap2_log;
extern LLog *acsap_log, _acsap_log;
extern LLog *rtsap_log, _rtsap_log;
extern LLog *rosap_log, _rosap_log;


/* TRANSPORT-SWITCH */

extern int	ts_stacks;
#define	TS_NONE	0x00
#define	TS_TCP	0x01
#define	TS_X25	0x02
#define	TS_BRG	0x04
#define	TS_TP4	0x08
#define TS_X2584 0x10
#define	TS_ALL	0xff

struct ts_interim {
    char   *ts_name;		/* community name, also MACRO name */
    char   *ts_value;		/*   .. MACRO value */

    int	    ts_subnet;		/* internal key */
    int	    ts_syntax;		/* same values as na_stack */

    char    ts_prefix[20];	/* NSAP prefix */
    int	    ts_length;		/*   .. and length */
};
extern struct ts_interim ts_interim[];

extern int	ts_communities[];
extern int	ts_comm_nsap_default;
extern int	ts_comm_x25_default;
extern int	ts_comm_tcp_default;

extern char *tsb_addresses[];
extern int tsb_communities[];

extern char *tsb_default_address;



/* X.25 */

#ifdef	X25
extern char    *x25_local_dte;
extern char    *x25_local_pid;

extern char     x25_intl_zero;
extern char     x25_strip_dnic;
extern char    *x25_dnic_prefix;

extern u_char   reverse_charge;
extern u_short  recvpktsize;
extern u_short  sendpktsize;
extern u_char   recvwndsize;
extern u_char   sendwndsize;
extern u_char   recvthruput;
extern u_char   sendthruput;
extern u_char   cug_req;
extern u_char   cug_index;
extern u_char   fast_select_type;
extern u_char   rpoa_req;
extern u_short  rpoa;

extern LLog *x25_log, _x25_log;

#ifdef	CAMTEC_CCL
extern char     x25_outgoing_port;
#endif

#ifdef ULTRIX_X25
extern char     *x25_default_template;
extern char     *x25_default_filter;
extern char     *x25_default_class;
#endif
#endif


/* BRIDGE X.25 */

#ifdef	BRIDGE_X25
extern char    *x25_bridge_host;
extern char    *x25_bridge_addr;
extern char    *x25_bridge_listen;
extern char    *x25_bridge_pid;
extern char    *x25_bridge_discrim;
#endif

#if	defined (BRIDGE_X25) || defined (X25)
extern u_short  x25_bridge_port;
#endif


/* SESSION */

extern int	ses_ab_timer;
extern int	ses_dn_timer;
extern int	ses_rf_timer;


/* USER-FRIENDLY NAMESERVICE */

extern char	ns_enabled;
extern char    *ns_address;


/* ROUTINES */

void	isodetailor ();
int	isodesetvar ();
void	isodexport ();

#define	isodefile(file,ispgm) \
	_isodefile ((ispgm) ? isodesbinpath : isodetcpath, (file))

char   *_isodefile ();

char   *getlocalhost ();

#endif
