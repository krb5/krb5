/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 * 
 * $Log$
 * Revision 1.3  1996/07/22 20:26:27  marc
 * this commit includes all the changes on the OV_9510_INTEGRATION and
 * OV_MERGE branches.  This includes, but is not limited to, the new openvision
 * admin system, and major changes to gssapi to add functionality, and bring
 * the implementation in line with rfc1964.  before committing, the
 * code was built and tested for netbsd and solaris.
 *
 * Revision 1.2.4.1  1996/07/18 03:02:23  marc
 * merged in changes from OV_9510_BP to OV_9510_FINAL1
 *
 * Revision 1.2.2.1  1996/06/20  21:48:24  marc
 * File added to the repository on a branch
 *
 * Revision 1.2  1996/06/05  20:52:28  bjaspan
 * initial hack at porting to mit kerberos
 *
 * Revision 1.1  1993/11/17 06:13:23  shanzer
 * Initial revision
 *
 */

#include    <stdio.h>

/*
 * XXX These should be defined somewhere so import and export get the
 * same value.
 */
#define	VERSION_OVSEC_10	"OpenV*Secure V1.0"
#define VERSION_KADM5_20	"Kerberos KADM5 database V2.0"

int	import_file(krb5_context context, FILE *fp, int merge_princs,
		    osa_adb_policy_t pol_db);
int	confirm(void);
char	*nstrtok(char *str, char *delim);
