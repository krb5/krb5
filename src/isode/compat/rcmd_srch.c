/* rcmd_srch.c: search a lookup table: return string value */

#ifndef lint
static char *rcsid = "$Header$";
#endif

/*
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:27:57  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:16:27  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:34:28  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:18:08  isode
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

char   *rcmd_srch(val, cmd)
register int   val;
register CMD_TABLE *cmd;
{
	for(;cmd->cmd_key != NULLCP; cmd++)
		if(val == cmd->cmd_value)
			return(cmd->cmd_key);
	return(NULLCP);
}
