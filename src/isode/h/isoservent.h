/* isoservent.h - ISODE services database access routines */

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:29:23  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:17:47  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:38:00  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:33:46  isode
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


#ifndef	_ISOSERVENT_
#define	_ISOSERVENT_


struct isoservent {
    char         *is_entity;	/* name of entity */
    char         *is_provider;	/* name of service provider */

#define	ISSIZE	64		/* xSAP selector/ID */
    int		  is_selectlen;
    union {
	char		is_un_selector[ISSIZE];
	unsigned short  is_un_port;
    }		un_is;
#define	is_selector	un_is.is_un_selector
#define	is_port		un_is.is_un_port

    char        **is_vec;	/* exec vector */
    char        **is_tail;	/* next free slot in vector */
};


int	setisoservent (), endisoservent ();

struct isoservent *getisoservent ();

struct isoservent *getisoserventbyname ();
struct isoservent *getisoserventbyselector ();
struct isoservent *getisoserventbyport ();

#endif
