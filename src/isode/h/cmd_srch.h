/* cmd_srch.h - command search structure */

/*
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:29:04  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:17:27  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:37:46  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:33:42  isode
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


#ifndef _CMD_SRCH_
#define _CMD_SRCH_

typedef struct  cmd_table {
	char    *cmd_key;
	int     cmd_value;
} CMD_TABLE;


struct  cm_args {
	char    *cm_key;
	char    *cm_value;
};

int     cmd_srch ();
char   *rcmd_srch ();

#endif
