/* pepdefs.h */

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:29:30  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:17:55  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:38:10  eichin
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


#ifndef PEPDEF_DEFINITIONS
#define PEPDEF_DEFINITIONS
/*
 * Globally known pep definitions
 */

typedef	struct	{
	char	*md_name;	/* Name of this module */
	int	md_nentries;	/* Number of entries */
	tpe	**md_etab;	/* Pointer to encoding tables */
	tpe	**md_dtab;	/* Pointer to decoding tables */
	ptpe **md_ptab;	/* Pointer to Printing tables */
	PE	(*md_eucode)();	/* User code for encoding */
	PE	(*md_ducode)();	/* User code for decoding */
	PE	(*md_pucode)();	/* User code for printing */

	}	modtyp;

#ifndef NULL
#define NULL	(char *)0
#endif

#endif
