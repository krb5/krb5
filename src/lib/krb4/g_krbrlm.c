/*
 * g_krbrlm.c
 *
 * Copyright 1985, 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"
#include <stdio.h>
#include "krb.h"
#include <string.h>

/*
 * krb_get_lrealm takes a pointer to a string, and a number, n.  It fills
 * in the string, r, with the name of the nth realm specified on the
 * first line of the kerberos config file (KRB_CONF, defined in "krb.h").
 * It returns 0 (KSUCCESS) on success, and KFAILURE on failure.  If the
 * config file does not exist, and if n=1, a successful return will occur
 * with r = KRB_REALM (also defined in "krb.h").
 *
 * NOTE: for archaic & compatibility reasons, this routine will only return
 * valid results when n = 1.
 *
 * For the format of the KRB_CONF file, see comments describing the routine
 * krb_get_krbhst().  This will also look in KRB_FB_CONF is
 * ATHENA_CONF_FALLBACK is defined.
 */
static char *krb_conf = KRB_CONF;


KRB5_DLLIMP int KRB5_CALLCONV
krb_get_lrealm(r,n)
    char *r;
    int n;
{
    FILE *cnffile, *krb__get_cnffile();

    if (n > 1)
	return(KFAILURE);  /* Temporary restriction */

    cnffile = krb__get_cnffile();
    if (!cnffile) {
	if (n == 1) {
	    (void) strcpy(r, KRB_REALM);
	    return(KSUCCESS);
	}
	else
	    return(KFAILURE);
    }

    /*
     * XXX This assumes REALM_SZ == 40,
     * and that r is 40 characters long.
     */
    if (fscanf(cnffile,"%39s",r) != 1) {
        (void) fclose(cnffile);
        return(KFAILURE);
    }
    (void) fclose(cnffile);
    return(KSUCCESS);
}
