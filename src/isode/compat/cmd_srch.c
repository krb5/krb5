/* cmd_srch.c - search a lookup table: return numeric value */

#ifndef lint
static char *rcsid = "$Header$";
#endif

/*
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:27:07  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:15:34  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:33:38  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:17:51  isode
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

#include "manifest.h"
#include "cmd_srch.h"

/*  */

/* map a string onto a value */

cmd_srch(str, cmd)
register char   *str;
register CMD_TABLE *cmd;
{
	extern char chrcnv[];

	for(;cmd->cmd_key != NULLCP; cmd++)
		if(chrcnv[*str] == chrcnv[*cmd->cmd_key] &&
		   lexequ(str, cmd->cmd_key) == 0)
			return(cmd->cmd_value);
	return(cmd->cmd_value);
}
