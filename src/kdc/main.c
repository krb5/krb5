/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Main procedure body for the KDC server process.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_main_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

/*
 outline:

 initialize database access (fetch master key, open DB)

 initialize network

 loop:
 	listen for packet

	determine packet type, dispatch to handling routine
		(AS or TGS (or V4?))

	reflect response

	exit on signal

 clean up secrets

 shut down network

 exit
 */

krb5_error_code
init_db(dbname, masterkeyname, masterkeyblock)
char *dbname;
krb5_principal masterkeyname;
krb5_keyblock *masterkeyblock;
{
    krb5_error_code retval;
    krb5_db_entry master_entry;

    /* set db name if appropriate */
    if (dbname && (retval = krb5_db_set_name(dbname)))
	return(retval);

    /* initialize database */
    if (retval = krb5_db_init())
	return(retval);

    master_encblock.crypto_entry = &krb5_des_cs_entry;

    if (retval = krb5_db_verify_master_key(masterkeyname, masterkeyblock)) {
	master_encblock.crypto_entry = 0;
	return(retval);
    }

    /* do any necessary key pre-processing */
    if (retval = (*master_encblock.crypto_entry->
		  process_key)(&eblock, masterkeyblock)) {
	master_encblock.crypto_entry = 0;
	return(retval);
    }

    return 0;
}
