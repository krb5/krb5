/* mpkt.h - defines the report format for management */

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:29:28  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:17:53  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:38:08  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:33:49  isode
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

#include "isoaddrs.h"


struct MReport {
    u_short type;
#define OPREQIN         1
#define OPREQOUT        2
#define USERDT          3
#define USERDR          4
#define DISCREQ         5
#define PROTERR         6
#define CONGEST         7
#define CONFIGBAD       8
#define OPREQINBAD      9
#define OPREQOUTBAD     10
#define SOURCEADDR      11
#define	STARTLISTEN	12
#define	ENDLISTEN	13

    long    id;		/* process id */
    u_short cid;        /* connection fd */

    union {
	struct {
	    int a, b, c, d, e, f;
	} gp;

	struct {
	    int	    tsel_len;
	    char    tsel[TSSIZE];
	    struct NSAPaddr nsap;
	} taddr;
    } u;
};

int	TManGen ();
