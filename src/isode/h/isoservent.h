/* isoservent.h - ISODE services database access routines */

/* 
 * isode/h/isoservent.h
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
